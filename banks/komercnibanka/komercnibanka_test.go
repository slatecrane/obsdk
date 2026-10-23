package komercnibanka

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/flowstate"
	"github.com/slatecrane/obsdk/obsdktest"
)

func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

var frozen = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

const (
	testIBAN  = "CZ8501000900930427310227"
	payeeIBAN = "CZ6508000000192000145399"
)

func newTestClient(t *testing.T, srv *httptest.Server) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "obsdk", RedirectURL: "https://www.example.com/cb"},
		HTTPClient:  http.DefaultClient,
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{paramTPPName: "obsdk"},
	}
	if srv != nil {
		cfg.HTTPClient = srv.Client()
		cfg.Extra[paramBaseURL] = srv.URL
	}
	c, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "CZ"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func aisSession() *obsdk.Session {
	exp := frozen.Add(time.Hour)
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "CZ", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "at", RefreshToken: "rt", AccessExpiresAt: &exp, Scope: scopeAIS,
		Consents: map[string]obsdk.Consent{consentKind: {Kind: consentKind}}, Meta: map[string]string{metaRedirectURL: "https://www.example.com/cb"}}
}

// fake records the requests it gets and answers from a handler.
type fake struct {
	reqs   []*http.Request
	bodies []string
	h      func(w http.ResponseWriter, r *http.Request)
}

func (f *fake) server(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.reqs = append(f.reqs, r)
		f.bodies = append(f.bodies, string(b))
		f.h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConfig(t *testing.T) {
	_, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "CZ"}, obsdk.Config{Env: obsdk.Sandbox, HTTPClient: http.DefaultClient,
		Credentials: obsdk.Credentials{ClientID: "x"}})
	if !errors.Is(err, obsdk.ErrInvalidConfig) || !strings.Contains(err.Error(), "tpp_name") {
		t.Fatalf("missing tpp_name: got %v", err)
	}
	_, err = obsdk.New(obsdk.Target{Bank: bankKey, Country: "CZ"}, obsdk.Config{Env: obsdk.Production, HTTPClient: http.DefaultClient,
		Credentials: obsdk.Credentials{ClientID: "x", RedirectURL: "https://tpp.example/cb"}, Extra: map[string]string{paramTPPName: "T"}})
	if !errors.Is(err, obsdk.ErrInvalidConfig) || !strings.Contains(err.Error(), "client_secret") {
		t.Fatalf("production without secret: got %v", err)
	}
}

func TestAuthorizeURL(t *testing.T) {
	c := newTestClient(t, nil)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.Redirect.URL)
	q := u.Query()
	if u.Host != "api-gateway.kb.cz" || q.Get("scope") != "aisp" || q.Get("response_type") != "code" ||
		q.Get("client_id") != "obsdk" || q.Get("redirect_uri") != "https://www.example.com/cb" || q.Get("state") != "state-1" {
		t.Fatalf("unexpected URL %s", st.Redirect.URL)
	}
}

func TestConnectCallbackErrors(t *testing.T) {
	c := newTestClient(t, nil)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://www.example.com/cb?error=access_denied&state=state-1"})
	if !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("denied: got %v", err)
	}
	_, err = c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://www.example.com/cb?code=c&state=other"})
	if !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: got %v", err)
	}
}

func TestAmount(t *testing.T) {
	for _, tc := range []struct {
		n, ind, want string
		dir          obsdk.Direction
	}{
		{"443.95", "CRDT", "443.95", obsdk.Credit},
		{"0.59", "DBIT", "-0.59", obsdk.Debit},
		{"250", "DBIT", "-250", obsdk.Debit},
		{"-2.5", "", "-2.5", obsdk.Debit},
		{"1E+2", "CRDT", "100.00", obsdk.Credit},
	} {
		got, dir := amount(json.Number(tc.n), tc.ind)
		if string(got) != tc.want || dir != tc.dir {
			t.Errorf("amount(%s, %s) = %s %s, want %s %s", tc.n, tc.ind, got, dir, tc.want, tc.dir)
		}
	}
}

func TestPageNext(t *testing.T) {
	n := func(i int) *int { return &i }
	for _, tc := range []struct {
		p    page
		want int
		ok   bool
	}{
		{page{PageNumber: 0, PageCount: 1, NextPage: n(0)}, 0, false}, // KB's last page of the account list
		{page{PageNumber: 0, PageCount: 0}, 0, false},
		{page{PageNumber: 5, PageCount: 7, NextPage: n(6)}, 6, true},
	} {
		got, ok := tc.p.next()
		if got != tc.want || ok != tc.ok {
			t.Errorf("%+v: got %d %t", tc.p, got, ok)
		}
	}
}

func TestErrorMapping(t *testing.T) {
	c := newTestClient(t, nil)
	r := func(status int, body string) *resp {
		return &resp{status: status, header: http.Header{}, body: []byte(body)}
	}
	if err := c.apiErr(opAccounts, r(401, `{"errors":[{"error":"ERR_CODE_401","message":"UNAUTHORISED"}]}`)); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("401: got %v", err)
	}
	if err := c.apiErr(opBalances, r(400, `{"errors":[{"error":"NARR","message":"[AccessDenied - Unauthorized access to account]"}]}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("NARR: got %v", err)
	}
	if err := c.apiErr(opRefresh, r(400, `{"errors":[{"code":"invalid_grant","message":"x"}]}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("refresh invalid_grant: got %v", err)
	}
	if err := c.apiErr(opToken, r(400, `{"errors":[{"code":"invalid_grant","message":"x"}]}`)); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Errorf("token invalid_grant: got %v", err)
	}
	if err := c.apiErr(opPayment, &resp{status: 429, header: http.Header{"Retry-After": {"7"}}, body: []byte("{}")}); !errors.Is(err, obsdk.ErrRateLimited) {
		t.Errorf("429: got %v", err)
	}
	ae := c.apiErr(opPayment, &resp{status: 400, header: http.Header{"Gwcorrelationid": {"g1"}},
		body: []byte(`{"errors":[{"code":"RR10","scope":"paymentIdentification.instructionIdentification","message":"Invalid charset"}]}`)}).(*obsdk.APIError)
	if ae.Code != "RR10" || ae.RequestID != "g1" || !strings.Contains(ae.Text, "instructionIdentification") {
		t.Errorf("got %+v", ae)
	}
}

// From KB's AIS manual (domestic payment, debit), with a variable symbol added.
const domesticTx = `{"entryReference":"357-12032019 1602 602033 935171","amount":{"value":1.23,"currency":"CZK"},
"creditDebitIndicator":"DBIT","status":"BOOK","bookingDate":{"date":"2019-03-12"},"valueDate":{"date":"2019-03-12"},
"bankTransactionCode":{"proprietary":{"code":10000101008,"issuer":"CBA"}},
"entryDetails":{"transactionDetails":{"references":{"accountServicerReference":"ZU000005UO8"},
"relatedParties":{"creditorAccount":{"identification":{"iban":"CZ3203000000000001111132"}}},
"relatedAgents":{"creditorAgent":{"financialInstitutionIdentification":{"bic":"CEKOCZPPXXX"}}},
"remittanceInformation":{"unstructured":"Poznámka pro příjemce","structured":{"creditorReferenceInformation":{"reference":["VS:3451859072","KS:0","SS:0"]}}},
"additionalTransactionInformation":"Platba na vrub vašeho účtu"}}}`

func TestToTransaction(t *testing.T) {
	tx, err := toTransaction(json.RawMessage(domesticTx))
	if err != nil {
		t.Fatal(err)
	}
	if tx.Amount.Amount != "-1.23" || tx.Direction != obsdk.Debit || tx.Status != obsdk.TxBooked || tx.BookingDate != "2019-03-12" ||
		tx.BankCode != "10000101008" || tx.BankCodeText != "Platba na vrub vašeho účtu" || tx.ReferenceNumber != "3451859072" ||
		tx.ID != "357-12032019 1602 602033 935171" || len(tx.Remittance) != 1 ||
		len(tx.Counterparty.Identifiers) != 1 || tx.Counterparty.Identifiers[0].Value != "CZ3203000000000001111132" {
		t.Fatalf("got %+v", tx)
	}
	if variableSymbol([]string{"VS:0", "KS:0"}) != "" {
		t.Fatal("a zero VS is no VS")
	}
}

func TestTransactionsFilterAndCursor(t *testing.T) {
	pending := strings.Replace(domesticTx, `"BOOK"`, `"PDNG"`, 1)
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"pageNumber":0,"pageCount":2,"pageSize":2,"nextPage":1,"transactions":[`+domesticTx+`,`+pending+`]}`)
	}}
	c := newTestClient(t, f.server(t))
	res, err := c.Transactions(context.Background(), aisSession(), obsdk.TxQuery{AccountID: "a/b+c=", From: frozen.AddDate(0, -1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transactions) != 1 || res.Transactions[0].Status != obsdk.TxBooked {
		t.Fatalf("booked only: got %+v", res.Transactions)
	}
	if got := f.reqs[0].URL.EscapedPath(); got != "/aisp/v2/my/accounts/a%2Fb+c=/transactions" {
		t.Fatalf("path %s", got)
	}
	q, _ := url.ParseQuery(res.NextCursor)
	if q.Get("page") != "1" || q.Get("fromDate") != "2026-09-23" {
		t.Fatalf("cursor %q", res.NextCursor)
	}
	res, err = c.Transactions(context.Background(), aisSession(), obsdk.TxQuery{AccountID: "a", Cursor: res.NextCursor,
		Status: []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transactions) != 2 || f.reqs[1].URL.Query().Get("page") != "1" || f.reqs[1].URL.Query().Get("fromDate") != "2026-09-23" {
		t.Fatalf("second page: %d items, query %s", len(res.Transactions), f.reqs[1].URL.RawQuery)
	}
}

func payRequest() obsdk.PaymentRequest {
	return obsdk.PaymentRequest{
		Type:   obsdk.PaymentDomestic,
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: testIBAN}},
		Transfers: []obsdk.Transfer{{
			Amount:     obsdk.Money{Amount: "12.50", Currency: "CZK"},
			Creditor:   obsdk.Creditor{Name: "Test Payee", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: payeeIBAN}},
			Remittance: []string{"obsdk test"},
			Reference:  &obsdk.Reference{Scheme: obsdk.ReferenceCZ, Value: "1234567890"},
		}},
		IdempotencyKey: "3987b4fa-a057-44d8",
	}
}

func TestBuildBody(t *testing.T) {
	c := newTestClient(t, nil)
	b, err := c.buildBody(payRequest())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"paymentIdentification":{"instructionIdentification":"3987B4FAA05744D8"},"amount":{"instructedAmount":{"value":12.50,"currency":"CZK"}},` +
		`"debtorAccount":{"identification":{"iban":"` + testIBAN + `"},"currency":"CZK"},"creditor":{"name":"Test Payee"},` +
		`"creditorAccount":{"identification":{"iban":"` + payeeIBAN + `"}},` +
		`"remittanceInformation":{"unstructured":"obsdk test","structured":{"creditorReferenceInformation":{"reference":["VS:1234567890"]}}}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	r := payRequest()
	r.Transfers[0].InstructionID = "bad-id"
	if _, err := c.buildBody(r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("instruction id: got %v", err)
	}
}

func TestPaymentSpecs(t *testing.T) {
	c := newTestClient(t, nil)
	r := payRequest()
	r.Transfers[0].Reference.Value = "12345678901"
	if err := c.Info().Payments[0].Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("11-digit VS: got %v", err)
	}
	r = payRequest()
	r.Type = obsdk.PaymentSEPA
	r.Transfers[0].Amount.Currency = "EUR"
	r.Transfers[0].Creditor.Account.Value = "DE89370400440532013000"
	spec, _ := c.Info().PaymentSpec("CZ", "", obsdk.PaymentSEPA)
	if err := spec.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("SEPA with a VS: got %v", err)
	}
	r.Transfers[0].Reference = nil
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatalf("SEPA: got %v", err)
	}
}

// TestPaymentFlow drives login, creation, signature and status against a
// fake KB.
func TestPaymentFlow(t *testing.T) {
	status := "ACSP"
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/v1/token":
			_, _ = io.WriteString(w, `{"access_token":"pt","refresh_token":"prt","token_type":"Bearer","expires_in":3600}`)
		case r.Method == http.MethodPost && r.URL.Path == "/pisp/v2/my/payments":
			_, _ = io.WriteString(w, `{"paymentRequest":{"paymentIdentification":{"transactionIdentification":"P1"},"debtorAccount":{"identification":{"iban":"`+testIBAN+`"}}},"signInfo":{"state":"OPEN","signId":"S1"},"instructionStatus":"ACTC"}`)
		case r.URL.Path == "/pisp/v2/my/payments/P1/sign/S1":
			_, _ = io.WriteString(w, `{"authorizationType":"USERAGENT_REDIRECT","href":{"url":"https://sign.example/ssologin?SAMLRequest=x"},"method":"GET","signInfo":{"state":"OPEN","signId":"S1"}}`)
		case r.URL.Path == "/pisp/v2/my/payments/P1/status":
			_, _ = io.WriteString(w, `{"instructionStatus":"`+status+`"}`)
		default:
			w.WriteHeader(404)
		}
	}}
	c := newTestClient(t, f.server(t))
	ctx := context.Background()
	st, err := c.InitiatePayment(ctx, payRequest())
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(st.Redirect.URL); u.Query().Get("scope") != "pisp" {
		t.Fatalf("login URL %s", st.Redirect.URL)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://www.example.com/cb?code=c&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect.URL != "https://sign.example/ssologin?SAMLRequest=x" ||
		st.Session == nil || !hasScope(st.Session, scopePIS) || st.Payment == nil || st.Payment.ID != "P1" || st.Payment.Status != obsdk.PaymentReceived {
		t.Fatalf("sign step: %+v", st)
	}
	for _, r := range f.reqs[1:3] {
		if r.Header.Get("Authorization") != "Bearer pt" || r.Header.Get("User-Involved") != "true" || r.Header.Get("Date") == "" || r.Header.Get("TPP-Name") != "obsdk" {
			t.Fatalf("headers of %s: %v", r.URL.Path, r.Header)
		}
	}
	if !strings.Contains(f.bodies[2], `"authorizationType":"USERAGENT_REDIRECT"`) || !strings.Contains(f.bodies[2], `"redirectUrl":"https://www.example.com/cb"`) {
		t.Fatalf("sign body %s", f.bodies[2])
	}
	signState := st.State
	done, err := c.Resume(ctx, signState, obsdk.StepInput{Callback: "https://www.example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Payment.Status != obsdk.PaymentInProgress || done.Payment.BankStatus != "ACSP" {
		t.Fatalf("done: %+v", done.Payment)
	}
	if f.reqs[len(f.reqs)-1].Header.Get("Authorization") != "" {
		t.Fatal("status is read with the certificate only")
	}

	// The user left the signing page: the payment still waits for the signature.
	status = "ACTC"
	_, err = c.Resume(ctx, signState, obsdk.StepInput{Callback: "https://www.example.com/cb"})
	var fe *obsdk.FlowError
	if !errors.As(err, &fe) || fe.Payment == nil || fe.Payment.ID != "P1" || !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("unsigned: got %v", err)
	}

	if done.Session == nil || done.Session.AccessToken != "pt" {
		t.Fatalf("done must hand back the payment login: %+v", done.Session)
	}
}

func TestPaymentReusesLogin(t *testing.T) {
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pisp/v2/my/payments":
			_, _ = io.WriteString(w, `{"paymentRequest":{"paymentIdentification":{"transactionIdentification":"P2"}},"signInfo":{"state":"OPEN","signId":"S2"},"instructionStatus":"ACTC"}`)
		case "/pisp/v2/my/payments/P2/sign/S2":
			_, _ = io.WriteString(w, `{"authorizationType":"USERAGENT_REDIRECT","href":{"url":"https://sign.example/2"},"method":"GET"}`)
		default:
			w.WriteHeader(404)
		}
	}}
	c := newTestClient(t, f.server(t))
	s := aisSession()
	s.Scope = scopePIS
	r := payRequest()
	r.Session = s
	st, err := c.InitiatePayment(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if st.Redirect.URL != "https://sign.example/2" || len(f.reqs) != 2 {
		t.Fatalf("expected straight to signing: %+v (%d requests)", st, len(f.reqs))
	}
}

func TestCancelUnsupported(t *testing.T) {
	c := newTestClient(t, nil)
	ref, _ := flowstate.Encode(paymentRef{Integration: integrationID, ID: "P1", Type: obsdk.PaymentDomestic})
	if _, err := c.CancelPayment(context.Background(), ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}
