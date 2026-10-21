package abnamro

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

var frozen = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

const testIBAN = "NL12ABNA9999876523"

func newTestClient(t *testing.T, srv *httptest.Server) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "TPP_test", RedirectURL: "https://localhost/auth"},
		HTTPClient:  http.DefaultClient,
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{paramAPIKey: "key"},
	}
	if srv != nil {
		cfg.HTTPClient = srv.Client()
		cfg.Extra[paramBaseURL] = srv.URL
		cfg.Extra[paramTokenURL] = srv.URL + "/as/token.oauth2"
		cfg.Extra[paramRevokeURL] = srv.URL + "/as/revoke_token.oauth2"
	}
	c, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "NL"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func aisSession() *obsdk.Session {
	exp := frozen.Add(time.Hour)
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "NL", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "at", RefreshToken: "rt", AccessExpiresAt: &exp,
		Consents: map[string]obsdk.Consent{consentKind: {Kind: consentKind, Accounts: []string{testIBAN}}}, Meta: map[string]string{}}
}

func TestConfigRequiresAPIKeyAndClient(t *testing.T) {
	_, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "NL"}, obsdk.Config{Env: obsdk.Sandbox})
	if !errors.Is(err, obsdk.ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestAmount(t *testing.T) {
	for _, tc := range []struct {
		n, ind, want string
		dir          obsdk.Direction
	}{
		{"40.0", "CRDT", "40.0", obsdk.Credit},
		{"4638.06", "DBIT", "-4638.06", obsdk.Debit},
		{"-4.99", "DBIT", "-4.99", obsdk.Debit}, // balances arrive signed as well
		{"-2.5", "", "-2.5", obsdk.Debit},
		{"1E+2", "CRDT", "100.00", obsdk.Credit},
	} {
		got, dir := amount(json.Number(tc.n), tc.ind)
		if string(got) != tc.want || dir != tc.dir {
			t.Errorf("amount(%s, %s) = %s %s, want %s %s", tc.n, tc.ind, got, dir, tc.want, tc.dir)
		}
	}
}

func TestParseExpiresIn(t *testing.T) {
	got := parseExpiresIn("26 days, 23 hours, 57 minutes, and 5 seconds")
	want := 26*24*time.Hour + 23*time.Hour + 57*time.Minute + 5*time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if parseExpiresIn("") != 0 {
		t.Fatal("empty text must give 0")
	}
}

func TestRemittanceDropsPadding(t *testing.T) {
	got := remittance([]string{"SEPA Overboeking", " Naam:  X ", "Kenmerk: 1,,", ",,", ""})
	want := []string{"SEPA Overboeking", "Naam:  X", "Kenmerk: 1"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}

func TestAuthorizeURLStaysShort(t *testing.T) {
	c := newTestClient(t, nil)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	u := st.Redirect.URL
	if !strings.Contains(u, "scope=psd2:account:details:read+psd2:account:balance:read+psd2:account:transaction:read&") ||
		!strings.Contains(u, "redirect_uri=https://localhost/auth&") {
		t.Fatalf("unexpected URL %s", u)
	}
	// ABN AMRO's limit is 256 characters. The sandbox does not enforce it
	// (it took 271), so check the production page, with the longest
	// (cross-border payment) scopes and a full-length id behind the state.
	c.auth = productionAuth
	c.cfg.NewID = func(string) string { return "3987b4fa-a057-44d8-8c48-2130749def38" }
	u = c.authorizeURL([]string{"psd2:payment:xborder:write", "psd2:payment:xborder:read"}, "https://localhost/auth", c.newState(), "OC2JUZGVSK1792523586909")
	if len(u) > 256 {
		t.Fatalf("authorize URL has %d characters: %s", len(u), u)
	}
}

func TestConnectCallbackErrors(t *testing.T) {
	c := newTestClient(t, nil)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://localhost/auth?error=access_denied&error_description=x&state=state-1"})
	if !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("denied consent: got %v", err)
	}
	_, err = c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://localhost/auth?code=c&state=other"})
	if !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: got %v", err)
	}
}

func TestPaymentDeniedKeepsPayment(t *testing.T) {
	c := newTestClient(t, nil)
	pf := &payFlow{Phase: phPayRedirect, Type: obsdk.PaymentSEPA, Product: productSEPA, ID: "P1", OAuthState: "s", RedirectURL: "https://localhost/auth"}
	state, _ := flowstate.Encode(pf)
	_, err := c.Resume(context.Background(), state, obsdk.StepInput{Callback: "https://localhost/auth?error=access_denied&state=s"})
	var fe *obsdk.FlowError
	if !errors.As(err, &fe) || fe.Payment == nil || fe.Payment.ID != "P1" || !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("got %v", err)
	}
}

func apiError(status int, code string) string {
	return `{"errors":[{"code":"` + code + `","message":"m","traceId":"t","status":` + strconv.Itoa(status) + `}]}`
}

func TestErrorMapping(t *testing.T) {
	c := newTestClient(t, nil)
	if err := c.apiErr(opBalances, &resp{status: 401, body: []byte(apiError(401, "ERR_2002_001"))}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("401: got %v", err)
	}
	if err := c.apiErr(opTransactions, &resp{status: 403, body: []byte(apiError(403, codeNoAccess))}); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("no access: got %v", err)
	}
	if err := c.apiErr(opRefresh, &resp{status: 400, body: []byte(`{"error":"invalid_grant","error_description":"x"}`)}); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("invalid_grant: got %v", err)
	}
	if err := c.apiErr(opPayment, &resp{status: 429, header: http.Header{"Retry-After": {"7"}}, body: []byte("{}")}); !errors.Is(err, obsdk.ErrRateLimited) {
		t.Errorf("429: got %v", err)
	}
	ae := c.apiErr(opPayExecute, &resp{status: 400, body: []byte(apiError(400, "PAYMENT_ALREADY_EXECUTED"))}).(*obsdk.APIError)
	if ae.Code != "PAYMENT_ALREADY_EXECUTED" || ae.RequestID != "t" {
		t.Errorf("got %+v", ae)
	}
}

func TestAccountOutsideConsentIsRefused(t *testing.T) {
	c := newTestClient(t, nil)
	_, err := c.Balances(context.Background(), aisSession(), "NL58ABNA9999142181", obsdk.CallOptions{})
	if !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("got %v", err)
	}
}

// fake records the requests it gets and answers from a handler.
type fake struct {
	reqs []*http.Request
	h    func(w http.ResponseWriter, r *http.Request)
}

func (f *fake) server(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.reqs = append(f.reqs, r)
		f.h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBalancesSkipTypesForeignAccountsLack(t *testing.T) {
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("balanceType") != "BOOKBALANCE" {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, apiError(400, "MESSAGE_BAI560_0085"))
			return
		}
		_, _ = io.WriteString(w, `{"accountNumber":"`+testIBAN+`","currency":"EUR","balanceType":"BOOKBALANCE","amount":-4.99,"creditDebitIndicator":"DBIT"}`)
	}}
	c := newTestClient(t, f.server(t))
	res, err := c.Balances(context.Background(), aisSession(), testIBAN, obsdk.CallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Data) != 1 || res.Data[0].Amount.Amount != "-4.99" || res.Data[0].Kind != obsdk.BalanceInterimBooked {
		t.Fatalf("got %+v", res.Data)
	}
	if got := f.reqs[0].Header.Get("API-Key"); got != "key" {
		t.Fatalf("API-Key %q", got)
	}
}

func TestTransactionsPendingAndCursor(t *testing.T) {
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("activityType") == "RESERVATION":
			_, _ = io.WriteString(w, `{"activities":{"reservations":[{"id":"r1","amount":12.5,"creditDebitIndicator":"DBIT","currency":"EUR","status":"ACTIVE"}]}}`)
		case q.Get("nextPageKey") == "":
			_, _ = io.WriteString(w, `{"nextPageKey":"k1","activities":{"booked":[{"id":"b1","bookDate":"2026-10-01","amount":1,"creditDebitIndicator":"CRDT","currency":"EUR","counterPartyAccountNumber":"13141513158835300"}]}}`)
		default:
			_, _ = io.WriteString(w, `{"activities":{"booked":[]}}`)
		}
	}}
	c := newTestClient(t, f.server(t))
	ctx := context.Background()
	q := obsdk.TxQuery{AccountID: testIBAN, From: frozen.AddDate(0, 0, -30), To: frozen, Status: []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}}

	p1, err := c.Transactions(ctx, aisSession(), q)
	if err != nil {
		t.Fatal(err)
	}
	if tx := p1.Transactions[0]; tx.Counterparty.Identifiers[0].Scheme != obsdk.SchemeBBAN || tx.Status != obsdk.TxBooked {
		t.Fatalf("page 1: %+v", tx)
	}
	q.Cursor = p1.NextCursor
	p2, err := c.Transactions(ctx, aisSession(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Transactions) != 0 || !strings.Contains(p2.NextCursor, "activityType=RESERVATION") {
		t.Fatalf("page 2: %+v cursor %q", p2.Transactions, p2.NextCursor)
	}
	q.Cursor = p2.NextCursor
	p3, err := c.Transactions(ctx, aisSession(), q)
	if err != nil {
		t.Fatal(err)
	}
	if tx := p3.Transactions[0]; tx.Status != obsdk.TxPending || tx.Amount.Amount != "-12.5" || p3.NextCursor != "" {
		t.Fatalf("page 3: %+v cursor %q", tx, p3.NextCursor)
	}

	// The filters travel with every page, and reservations are asked for active only.
	if q := f.reqs[1].URL.Query(); q.Get("nextPageKey") != "k1" || q.Get("dateFrom") != "2026-09-20" || q.Get("then") != "" {
		t.Errorf("page 2 query %v", q)
	}
	if q := f.reqs[2].URL.Query(); q.Get("status") != "ACTIVE" || q.Get("dateTo") != "2026-10-20" {
		t.Errorf("page 3 query %v", q)
	}

	if _, err := c.Transactions(ctx, aisSession(), obsdk.TxQuery{AccountID: testIBAN, Cursor: "%zz"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("bad cursor: got %v", err)
	}
}

func paymentSession(id string, expired bool) *obsdk.Session {
	exp := frozen.Add(time.Hour)
	if expired {
		exp = frozen.Add(-time.Minute)
	}
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "NL", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "pt", RefreshToken: "prt", AccessExpiresAt: &exp,
		Consents: map[string]obsdk.Consent{paymentKind: {ID: id, Kind: paymentKind}}, Meta: map[string]string{}}
}

func TestPaymentStatusNeedsItsSessionAndRefreshes(t *testing.T) {
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "prt" {
				t.Errorf("token form %v", r.Form)
			}
			_, _ = io.WriteString(w, `{"access_token":"pt2","refresh_token":"prt2","token_type":"Bearer","expires_in":7199}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pt2" {
			t.Errorf("Authorization %q", got)
		}
		_, _ = io.WriteString(w, `{"paymentId":"P1","paymentStatus":"RJCT","statusDetails":{"statusISORsn":"AM03"},"debtorAccount":{"iban":"`+testIBAN+`"}}`)
	}}
	c := newTestClient(t, f.server(t))
	ref, _ := flowstate.Encode(paymentRef{Integration: integrationID, Product: productSEPA, ID: "P1", Type: obsdk.PaymentSEPA})
	ctx := context.Background()

	if _, err := c.PaymentStatus(ctx, ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("no session: got %v", err)
	}
	if _, err := c.PaymentStatus(ctx, ref, obsdk.PaymentCallOptions{Session: paymentSession("P2", false)}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("other payment's session: got %v", err)
	}
	res, err := c.PaymentStatus(ctx, ref, obsdk.PaymentCallOptions{Session: paymentSession("P1", true)})
	if err != nil {
		t.Fatal(err)
	}
	if p := res.Data; p.Status != obsdk.PaymentRejected || !p.Final || p.Reason != "AM03" || p.Debtor.Value != testIBAN {
		t.Fatalf("payment %+v", p)
	}
	if res.Session == nil || res.Session.RefreshToken != "prt2" {
		t.Fatalf("refreshed session not returned: %+v", res.Session)
	}
}

func TestBuildBody(t *testing.T) {
	r := obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, Transfers: []obsdk.Transfer{{
		Amount:    obsdk.Money{Amount: "1.50", Currency: "EUR"},
		Creditor:  obsdk.Creditor{Name: "John Doe", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: testIBAN}},
		Reference: &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"},
	}}}
	b, err := buildBody(r)
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(b)
	if !strings.Contains(string(js), `"amount":1.50`) || !strings.Contains(string(js), `{"issuer":"ISO","reference":"RF18539007547034"}`) {
		t.Fatalf("body %s", js)
	}
	r.Transfers[0].Remittance = []string{"text"}
	if _, err := buildBody(r); err == nil {
		t.Fatal("description and reference together must be refused")
	}
	r.Transfers[0].Remittance, r.Transfers[0].Reference = nil, nil
	r.Transfers[0].Creditor.Address = &obsdk.PostalAddress{Lines: []string{"Main Street 1"}}
	if _, err := buildBody(r); err == nil {
		t.Fatal("free address lines must be refused")
	}
}

func TestDisconnectRevokesRefreshToken(t *testing.T) {
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/as/revoke_token.oauth2" || r.Form.Get("token") != "rt" || r.Form.Get("token_type_hint") != "refresh_token" {
			t.Errorf("revoke %s %v", r.URL.Path, r.Form)
		}
	}}
	c := newTestClient(t, f.server(t))
	res, err := c.Disconnect(context.Background(), aisSession())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Closed) != 1 || res.Session.AccessToken != "" || len(res.Session.Consents) != 0 {
		t.Fatalf("got %+v", res)
	}
}
