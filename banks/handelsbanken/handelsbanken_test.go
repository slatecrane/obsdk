package handelsbanken

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
)

var frozen = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func newTestClient(t *testing.T, srv *httptest.Server, env obsdk.Env, country obsdk.Country, seg obsdk.Segment) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         env,
		Credentials: obsdk.Credentials{ClientID: "cid", RedirectURL: "https://example.com/cb"},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{},
	}
	if srv != nil {
		cfg.HTTPClient, cfg.Extra[paramBaseURL] = srv.Client(), srv.URL+"/openbanking"
	}
	if env == obsdk.Production {
		cfg.HTTPClient = srv.Client() // stands in for the mTLS client
	}
	c, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: country, Segment: seg}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func session(country obsdk.Country, seg obsdk.Segment) *obsdk.Session {
	exp := frozen.Add(time.Hour)
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: country, Segment: seg, Env: obsdk.Production,
		Integration: integrationID, AccessToken: "at", RefreshToken: "rt", AccessExpiresAt: &exp}
}

func scaJSON(srv string) string {
	return `[{"scaMethodType":"REDIRECT","_links":{"authorization":[{"href":"` + srv + `/login/authorize/1.0"}]}},
	         {"scaMethodType":"DECOUPLED","_links":{"authorization":[{"href":"` + srv + `/mbid/init"}]}}]`
}

// TestConnectProduction: in production the user goes to the authorisation
// link from the consent; the business consent carries the company id.
func TestConnectProduction(t *testing.T) {
	var srv *httptest.Server
	var consentHdr http.Header
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/openbanking/oauth2/token/1.0":
			f, _ := url.ParseQuery(string(body))
			if f.Get("client_id") != "cid" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if f.Get("grant_type") == "authorization_code" && (f.Get("code") != "the-code" || f.Get("scope") != "AIS:c-1") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at","expires_in":86400,"token_type":"Bearer","refresh_token":"rt"}`))
		case "/openbanking/psd2/v1/consents":
			consentHdr = r.Header.Clone()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"consentId":"c-1","consentStatus":"RECEIVED","scaMethods":` + scaJSON(srv.URL) + `}`))
		case "/openbanking/psd2/v2/accounts":
			_, _ = w.Write([]byte(`{"accounts":[{"accountId":"a1","iban":"SE1160000000000923451110","bban":"923451110","clearingNumber":"6112",
				"currency":"SEK","accountType":"Checkkonto","bic":"HANDSESS","ownerName":"Toren AB",
				"balances":[{"amount":{"content":1000.50,"currency":"SEK"},"balanceType":"AVAILABLE_AMOUNT"},{"amount":{"content":900,"currency":"SEK"},"balanceType":"VALUE_DATE"}]}]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, obsdk.Production, "SE", obsdk.Business)
	c.tokenURL = srv.URL + "/openbanking/oauth2/token/1.0"

	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepInputRequired || st.Fields[0].Key != keyCorporateID {
		t.Fatalf("want the company id first: %+v", st)
	}
	st, err = c.Resume(context.Background(), st.State, obsdk.StepInput{Values: map[string]string{keyCorporateID: "556677-8899"}})
	if err != nil {
		t.Fatal(err)
	}
	if consentHdr.Get("PSU-Corporate-ID") != "5566778899" || consentHdr.Get("PSU-Corporate-ID-Type") != "BANK" ||
		consentHdr.Get("Country") != "SE" || consentHdr.Get("X-IBM-Client-Id") != "cid" || consentHdr.Get("TPP-Request-ID") == "" {
		t.Fatalf("consent headers: %v", consentHdr)
	}
	u, _ := url.Parse(st.Redirect.URL)
	q := u.Query()
	if u.Path != "/login/authorize/1.0" || q.Get("scope") != "AIS:c-1" || q.Get("state") != "state-1" || q.Get("client_id") != "cid" ||
		q.Get("redirect_uri") != "https://example.com/cb" || q.Get("response_type") != "code" {
		t.Fatalf("redirect: %s", st.Redirect.URL)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb?code=x&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: %v", err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb?code=the-code&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	a := done.Accounts[0]
	if a.Identifiers[1].Value != "6112923451110" || a.Usage != "ORGA" || a.Product != "Checkkonto" || len(a.Balances) != 2 ||
		a.Balances[0].Amount.Amount != "1000.50" || a.Balances[1].Kind != obsdk.BalanceOther {
		t.Fatalf("account: %+v", a)
	}
	s := done.Session
	if s.Consents[consentKind].ID != "c-1" || s.RefreshToken != "rt" || !s.AccessExpiresAt.Equal(frozen.Add(24*time.Hour)) {
		t.Fatalf("session: %+v", s)
	}
}

// TestDecoupledPolling: Mobile BankID keeps the flow waiting until the token
// link answers COMPLETE; a BankID error fails the flow.
func TestDecoupledPolling(t *testing.T) {
	var srv *httptest.Server
	polls := 0
	var init map[string]any
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/openbanking/oauth2/token/1.0":
			_, _ = w.Write([]byte(`{"access_token":"cct","expires_in":86400,"token_type":"Bearer"}`))
		case "/openbanking/psd2/v1/consents":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"consentId":"c-2","scaMethods":` + scaJSON(srv.URL) + `}`))
		case "/mbid/init":
			_ = json.Unmarshal(body, &init)
			_, _ = w.Write([]byte(`{"auto_start_token":"ast","sleep_time":1500,"_links":{"token":{"href":"` + srv.URL + `/mbid/token?sessionId=s1"},"cancel":{"href":"` + srv.URL + `/mbid/cancel"}}}`))
		case "/mbid/token":
			polls++
			if polls == 1 {
				_, _ = w.Write([]byte(`{"result":"userSign"}`))
				return
			}
			_, _ = w.Write([]byte(`{"result":"COMPLETE","access_token":"at","expires_in":86400,"refresh_token":"rt"}`))
		case "/openbanking/psd2/v2/accounts":
			_, _ = w.Write([]byte(`{"accounts":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, obsdk.Sandbox, "SE", obsdk.Personal)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{Method: "decoupled", PSU: obsdk.PSUContext{IP: "10.0.0.1", ID: "199001011234"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepWait || st.WaitFor != 1500*time.Millisecond || st.Challenge.AutoStartToken != "ast" {
		t.Fatalf("wait step: %+v", st)
	}
	if init["scope"] != "AIS:c-2" || init["psu_id"] != "199001011234" || init["psu_client_ip"] != "10.0.0.1" || init["client_id"] != "cid" {
		t.Fatalf("init body: %v", init)
	}
	st, err = c.Resume(context.Background(), st.State, obsdk.StepInput{})
	if err != nil || st.Kind != obsdk.StepWait {
		t.Fatalf("still waiting: %+v %v", st, err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{})
	if err != nil || done.Kind != obsdk.StepDone || done.Session.AccessToken != "at" || done.Session.Meta["method"] != "decoupled" {
		t.Fatalf("done: %+v %v", done, err)
	}
	if _, err := newTestClient(t, srv, obsdk.Sandbox, "GB", obsdk.Personal).Connect(context.Background(), obsdk.ConnectRequest{Method: "decoupled"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("decoupled outside Sweden: %v", err)
	}
}

// TestBasketPayment: several Swedish transfers go into one signing basket
// with one approval; the status sums up the transfers.
func TestBasketPayment(t *testing.T) {
	var srv *httptest.Server
	var basket struct {
		Transfers []map[string]any `json:"sekCreditTransfers"`
	}
	executed := false
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p := r.URL.Path
		switch {
		case p == "/openbanking/oauth2/token/1.0":
			f, _ := url.ParseQuery(string(body))
			if f.Get("grant_type") == "authorization_code" && f.Get("scope") != "PIS:sb-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":900,"token_type":"Bearer"}`))
		case p == "/openbanking/psd2/se/v2/payments/private/signing-basket" && r.Method == http.MethodPost:
			_ = json.Unmarshal(body, &basket)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"signingBasketId":"sb-1","payments":[{"paymentId":"p-1"},{"paymentId":"p-2"}],"scaMethods":` + scaJSON(srv.URL) + `}`))
		case p == "/login/authorize/1.0":
			q := r.URL.Query()
			http.Redirect(w, r, q.Get("redirect_uri")+"?code=c&state="+q.Get("state"), http.StatusFound)
		case p == "/openbanking/psd2/se/v2/payments/private/signing-basket/sb-1" && r.Method == http.MethodPut:
			executed = r.Header.Get("Authorization") == "Bearer tok"
			_, _ = w.Write([]byte(`{"signingBasketId":"sb-1","transactionStatus":"PARTIAL_FAILURE"}`))
		case p == "/openbanking/psd2/se/v2/payments/private/sek-credit-transfer/p-1/status":
			_, _ = w.Write([]byte(`{"paymentId":"p-1","transactionStatus":"ACCP"}`))
		case p == "/openbanking/psd2/se/v2/payments/private/sek-credit-transfer/p-2/status":
			_, _ = w.Write([]byte(`{"paymentId":"p-2","transactionStatus":"RJCT"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, p)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, obsdk.Sandbox, "SE", obsdk.Personal)
	debtor := obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "6154923450017"}
	req := obsdk.PaymentRequest{Type: obsdk.PaymentDomestic, Debtor: &obsdk.PaymentDebtor{Account: &debtor}, Transfers: []obsdk.Transfer{
		{Amount: obsdk.Money{Amount: "100.50", Currency: "SEK"}, Creditor: obsdk.Creditor{Account: obsdk.Identifier{Scheme: obsdk.SchemeBankgiro, Value: "5050-1055"}},
			Reference: &obsdk.Reference{Scheme: obsdk.ReferenceOCR, Value: "1234567897"}},
		{Amount: obsdk.Money{Amount: "20", Currency: "SEK"}, Creditor: obsdk.Creditor{Name: "Anna", Account: obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "8327-9,123456789"}},
			Remittance: []string{"Rent"}},
	}}
	st, err := c.InitiatePayment(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(basket.Transfers) != 2 || st.Payment.ID != "sb-1" || st.Payment.Status != obsdk.PaymentReceived {
		t.Fatalf("basket %v, step %+v", basket, st)
	}
	bg, acct := basket.Transfers[0], basket.Transfers[1]
	if bg["creditorAccount"].(map[string]any)["accountType"] != "BG" || bg["remittanceInformation"].(map[string]any)["text"] != "1234567897" ||
		bg["debtorAccount"].(map[string]any)["value"] != "923450017" {
		t.Fatalf("bankgiro transfer: %v", bg)
	}
	if acct["creditorAccount"].(map[string]any)["value"] != "123456789" ||
		acct["creditorAgent"].(map[string]any)["identification"].(map[string]any)["code"] != "83279" {
		t.Fatalf("account transfer: %v", acct)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: st.Redirect.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !executed || done.Payment.Status != obsdk.PaymentPartiallyAccepted || done.Payment.Final {
		t.Fatalf("executed %v, payment %+v", executed, done.Payment)
	}
	if _, err := c.CancelPayment(context.Background(), done.Payment.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("cancel of a basket with two transfers: %v", err)
	}
}

func TestPaymentValidation(t *testing.T) {
	c := newTestClient(t, nil, obsdk.Sandbox, "SE", obsdk.Personal)
	debtor := obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "6154923450017"}
	base := obsdk.PaymentRequest{Type: obsdk.PaymentDomestic, Debtor: &obsdk.PaymentDebtor{Account: &debtor}}
	cases := map[string]obsdk.Transfer{
		"name for an account payee": {Amount: obsdk.Money{Amount: "1", Currency: "SEK"}, Creditor: obsdk.Creditor{Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "SE4550000000058398257466"}}, Remittance: []string{"x"}},
		"message or reference":      {Amount: obsdk.Money{Amount: "1", Currency: "SEK"}, Creditor: obsdk.Creditor{Account: obsdk.Identifier{Scheme: obsdk.SchemeBankgiro, Value: "5050-1055"}}},
		"Swedish IBAN only":         {Amount: obsdk.Money{Amount: "1", Currency: "SEK"}, Creditor: obsdk.Creditor{Name: "A", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE89370400440532013000"}}, Remittance: []string{"x"}},
	}
	for name, tr := range cases {
		r := base
		r.Transfers = []obsdk.Transfer{tr}
		if _, err := c.InitiatePayment(context.Background(), r); !errors.Is(err, obsdk.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAccountHelpers(t *testing.T) {
	for in, want := range map[string]string{"8327-9,123456789": "83279|123456789", "6154923450017": "6154|923450017", "5000 12345678": "5000|12345678"} {
		cl, acct := splitClearing(in)
		if cl+"|"+acct != want {
			t.Errorf("splitClearing(%q) = %s|%s", in, cl, acct)
		}
	}
	for in, want := range map[obsdk.Identifier]string{
		{Scheme: obsdk.SchemeBBAN, Value: "6154923450017"}:                 "923450017",
		{Scheme: obsdk.SchemeBBAN, Value: "923450017"}:                     "923450017",
		{Scheme: obsdk.SchemeIBAN, Value: "SE34 6000 0000 0009 2345 0017"}: "923450017",
	} {
		if got, err := shbAccount(in); err != nil || got != want {
			t.Errorf("shbAccount(%v) = %q, %v", in, got, err)
		}
	}
	if _, err := shbAccount(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "SE4550000000058398257466"}); err == nil {
		t.Error("an IBAN of another bank is not a Handelsbanken account")
	}
}

// TestTransactionShapes covers the spec's timestamps and counterparties and
// the LU sandbox's renamed amount objects.
func TestTransactionShapes(t *testing.T) {
	c := newTestClient(t, nil, obsdk.Sandbox, "SE", obsdk.Personal)
	page, err := c.parseTransactions([]byte(`{"transactions":[
	  {"status":"BOOKED","amount":{"content":899.99,"currency":"EUR"},"bookingDate":"2017-11-17T00:00:00.000Z","creditDebit":"DEBITED","creditorName":"Kone OY","remittanceInformation":"INVOICE 4512","balance":{"amount":{"content":33633.25,"currency":"EUR"},"balanceType":"CURRENT"}},
	  {"status":"BOOKED","transactionAmount":{"amount":12.5,"currency":"EUR"},"bookingDate":"2026-10-17","creditDebit":"CREDITED","debtorName":"Employer"},
	  {"status":"PENDING","amount":{"content":1,"currency":"EUR"},"creditDebit":"DEBITED"}]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Transactions) != 2 {
		t.Fatalf("booked only: %+v", page.Transactions)
	}
	d, cr := page.Transactions[0], page.Transactions[1]
	if d.Amount.Amount != "-899.99" || d.Direction != obsdk.Debit || d.BookingDate != "2017-11-17" || d.Counterparty.Name != "Kone OY" || d.BalanceAfter.Amount != "33633.25" {
		t.Fatalf("debit: %+v", d)
	}
	if cr.Amount.Amount != "12.5" || cr.Direction != obsdk.Credit || cr.Counterparty.Name != "Employer" {
		t.Fatalf("credit: %+v", cr)
	}
	in := inRange([]obsdk.Transaction{{BookingDate: "2026-09-30"}, {BookingDate: "2026-10-01"}, {ValueDate: "2026-10-17"}, {}},
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC))
	if len(in) != 2 {
		t.Fatalf("inRange: %+v", in)
	}
}

func TestErrorClassification(t *testing.T) {
	c := newTestClient(t, nil, obsdk.Sandbox, "SE", obsdk.Personal)
	mk := func(status int, body string) *resp {
		return &resp{status: status, header: http.Header{}, body: []byte(body)}
	}
	var ae *obsdk.APIError
	if err := c.apiErr(opAccounts, mk(401, `{ "httpCode":"401", "httpMessage":"Unauthorized", "moreInformation":"Bearer error='invalid_token'" }`)); !errors.Is(err, obsdk.ErrAccessExpired) ||
		!errors.As(err, &ae) || ae.Code != "Unauthorized" || !strings.Contains(ae.Text, "invalid_token") {
		t.Fatalf("401: %v", err)
	}
	if err := c.apiErr(opTransactions, mk(403, `{"tppMessages":[{"category":"ERROR","code":"CONSENT_EXPIRED","text":"x"}]}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("403: %v", err)
	}
	if err := c.apiErr(opRefresh, mk(400, `{"error":"invalid_grant"}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("refresh: %v", err)
	}
	if err := c.apiErr(opAccounts, mk(429, `{}`)); !errors.Is(err, obsdk.ErrRateLimited) {
		t.Fatalf("429: %v", err)
	}
}

func TestDisconnectIsLocal(t *testing.T) {
	c := newTestClient(t, nil, obsdk.Sandbox, "SE", obsdk.Personal)
	s := session("SE", obsdk.Personal)
	s.Env = obsdk.Sandbox
	s.Consents = map[string]obsdk.Consent{consentKind: {ID: "c-1", Kind: consentKind}}
	res, err := c.Disconnect(context.Background(), s)
	if err != nil || len(res.Closed) != 0 || res.Failed[consentKind] == "" || res.Session.AccessToken != "" || res.Session.Consents != nil {
		t.Fatalf("disconnect: %+v %v", res, err)
	}
}
