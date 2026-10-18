package crosskey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

// fakeBank is a minimal Crosskey store: token endpoint, AIS and PIS.
type fakeBank struct {
	t        *testing.T
	mu       sync.Mutex
	srv      *httptest.Server
	requests []string
	bodies   map[string][]byte // last body per path
	headers  map[string]http.Header
}

func newFakeBank(t *testing.T) *fakeBank {
	f := &fakeBank{t: t, bodies: map[string][]byte{}, headers: map[string]http.Header{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBank) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.bodies[r.Method+" "+r.URL.Path] = b
	f.headers[r.Method+" "+r.URL.Path] = r.Header.Clone()
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	const ais, pis = "/open-banking/v3.1.6/aisp", "/open-banking/v3.1.7/pisp"
	switch p := r.URL.Path; {
	case p == "/open-banking/v2.0/oidc/token":
		form, _ := url.ParseQuery(string(b))
		switch form.Get("grant_type") {
		case "client_credentials":
			io.WriteString(w, `{"access_token":"cc-token","token_type":"Bearer","expires_in":30}`)
		case "authorization_code":
			if form.Get("code") != "the-code" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			io.WriteString(w, `{"access_token":"user-token","refresh_token":"rt-1","token_type":"Bearer","expires_in":180,"scope":"openid accounts"}`)
		case "refresh_token":
			if form.Get("refresh_token") != "rt-1" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			io.WriteString(w, `{"access_token":"user-token-2","refresh_token":"rt-2","expires_in":"180"}`)
		}
	case p == ais+"/account-access-consents" && r.Method == http.MethodPost:
		w.WriteHeader(201)
		io.WriteString(w, `{"Data":{"ConsentId":"c-1","Status":"AwaitingAuthorisation","Permissions":["ReadAccountsBasic"]},"Risk":{}}`)
	case p == ais+"/account-access-consents/c-1" && r.Method == http.MethodDelete:
		w.WriteHeader(204)
	case p == ais+"/accounts":
		io.WriteString(w, `{"Data":{"Account":[{"AccountId":"a-1","Currency":"EUR","AccountType":"Personal","AccountSubType":"CurrentAccount",
			"Nickname":"Käyttötili","Account":[{"SchemeName":"UK.OBIE.IBAN","Identification":"FI2112345600000785","Name":"Matti Meikäläinen"}]},
			{"AccountId":"a-2","Currency":"EUR","AccountType":"Personal","AccountSubType":"CreditCard",
			"Account":[{"SchemeName":"FI.S-Pankki.CreditCard","Identification":"1234"}]}]}}`)
	case p == ais+"/accounts/a-1/balances":
		io.WriteString(w, `{"Data":{"Balance":[{"AccountId":"a-1","Type":"InterimAvailable","CreditDebitIndicator":"Credit","DateTime":"2026-10-18T10:00:00+03:00","Amount":{"Amount":"1200.50","Currency":"EUR"}}]}}`)
	case p == ais+"/accounts/a-1/transactions":
		if r.URL.Query().Get("paginationKey") == "" {
			io.WriteString(w, `{"Data":{"Transaction":[{"TransactionId":"t-1","Status":"Booked","CreditDebitIndicator":"Debit","BookingDateTime":"2026-10-17T00:00:00+03:00",
				"Amount":{"Amount":"12.30","Currency":"EUR"},"TransactionInformation":"K-Market","CreditorAccount":{"Name":"K-Market"}}]},
				"Links":{"Self":"`+f.srv.URL+r.URL.Path+`","Next":"`+f.srv.URL+r.URL.Path+`?paginationKey=2"}}`)
			return
		}
		io.WriteString(w, `{"Data":{"Transaction":[{"TransactionId":"t-2","Status":"Booked","CreditDebitIndicator":"Credit","BookingDateTime":"2026-10-16T00:00:00+03:00",
			"Amount":{"Amount":"100.00","Currency":"EUR"},"DebtorAccount":{"SchemeName":"UK.OBIE.IBAN","Identification":"FI5542345670000081","Name":"Employer"}}]},"Links":{}}`)
	case p == pis+"/international-scheduled-payment-consents":
		w.WriteHeader(201)
		io.WriteString(w, `{"Data":{"ConsentId":"pc-1","Status":"AwaitingAuthorisation"},"Risk":{}}`)
	case p == pis+"/international-scheduled-payments":
		w.WriteHeader(201)
		io.WriteString(w, `{"Data":{"InternationalScheduledPaymentId":"p-1","ConsentId":"pc-1","Status":"InitiationCompleted",
			"Initiation":{"DebtorAccount":{"SchemeName":"UK.OBIE.IBAN","Identification":"FI2112345600000785"}}}}`)
	case p == pis+"/international-scheduled-payments/p-1" && r.Method == http.MethodDelete:
		w.WriteHeader(204)
	case p == pis+"/international-scheduled-payments/p-1":
		io.WriteString(w, `{"Data":{"InternationalScheduledPaymentId":"p-1","Status":"Cancelled"}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"Code":"404","Message":"not found","Errors":[{"ErrorCode":"UK.OBIE.NotFound","Message":"no such path"}]}`)
	}
}

func testSeal(t *testing.T) *obsdk.Seal {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(123456789), Subject: pkix.Name{CommonName: "obsdk", Country: []string{"FI"}},
		NotBefore: frozen, NotAfter: frozen.AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &obsdk.Seal{Key: key, Certificate: cert}
}

func newTestClient(t *testing.T, f *fakeBank, bank obsdk.Target) obsdk.Client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", RedirectURL: "https://app.example/cb"},
		HTTPClient:  f.srv.Client(),
		Seal:        testSeal(t),
		Extra:       map[string]string{"api_key": "the-api-key", "base_url": f.srv.URL, "auth_url": "https://auth.example/open-banking/v4.0/oidc/auth"},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
	}
	c, err := obsdk.New(bank, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func requestObject(t *testing.T, authURL string) map[string]any {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(u.Query().Get("request"), ".")
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestConnectAndRead(t *testing.T) {
	f := newFakeBank(t)
	c := newTestClient(t, f, obsdk.Target{Bank: "spankki", Country: "FI"})
	ctx := context.Background()

	st, err := c.Connect(ctx, obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || !strings.HasPrefix(st.Redirect.URL, "https://auth.example/open-banking/v4.0/oidc/auth?") {
		t.Fatalf("step = %+v", st)
	}
	ro := requestObject(t, st.Redirect.URL)
	intent := ro["claims"].(map[string]any)["id_token"].(map[string]any)["openbanking_intent_id"].(map[string]any)
	if intent["value"] != "urn:s-pankki:account:c-1" {
		t.Errorf("intent = %v", intent["value"])
	}
	if ro["iss"] != "CN=obsdk,C=FI" {
		t.Errorf("iss = %v", ro["iss"])
	}
	if h := f.headers["POST /open-banking/v3.1.6/aisp/account-access-consents"]; h.Get("x-api-key") != "the-api-key" || h.Get("Authorization") != "Bearer cc-token" {
		t.Errorf("consent headers = %v", h)
	}
	if h := f.headers["POST /open-banking/v2.0/oidc/token"]; h.Get("x-api-key") != "" {
		t.Error("API key sent to the token endpoint")
	}

	if _, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb#code=the-code&state=wrong"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Errorf("wrong state: err = %v", err)
	}
	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb#code=the-code&id_token=x&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	s := done.Session
	if s == nil || s.AccessToken != "user-token" || s.RefreshToken != "rt-1" || s.AccessExpiresAt == nil || !s.AccessExpiresAt.Equal(frozen.Add(3*time.Minute)) {
		t.Fatalf("session = %+v", s)
	}
	if len(done.Accounts) != 2 {
		t.Fatalf("accounts = %+v", done.Accounts)
	}
	a := done.Accounts[0]
	if a.Type != "CACC" || a.Identifiers[0].Scheme != obsdk.SchemeIBAN || a.OwnerName != "Matti Meikäläinen" || a.Usage != "PRIV" {
		t.Errorf("account = %+v", a)
	}
	if card := done.Accounts[1]; card.Type != "CARD" || card.Identifiers[0].Scheme != "FI.S-Pankki.CreditCard" {
		t.Errorf("card = %+v", card)
	}

	bal, err := c.Balances(ctx, s, "a-1", obsdk.CallOptions{})
	if err != nil || len(bal.Data) != 1 || bal.Data[0].Kind != obsdk.BalanceInterimAvailable || bal.Data[0].Amount.Amount != "1200.50" {
		t.Fatalf("balances = %+v, %v", bal, err)
	}

	page, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "a-1", From: frozen.AddDate(0, 0, -30)})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Transactions) != 1 || page.Transactions[0].Amount.Amount != "-12.30" || page.Transactions[0].Direction != obsdk.Debit || page.NextCursor == "" {
		t.Fatalf("page 1 = %+v", page.TxPage)
	}
	page, err = c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "a-1", Cursor: page.NextCursor})
	if err != nil || len(page.Transactions) != 1 || page.NextCursor != "" || page.Transactions[0].Counterparty.Name != "Employer" {
		t.Fatalf("page 2 = %+v, %v", page, err)
	}
	if _, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "a-1", Cursor: "https://evil.example/x"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("foreign cursor: err = %v", err)
	}

	ns, err := c.Refresh(ctx, s)
	if err != nil || ns.AccessToken != "user-token-2" || ns.RefreshToken != "rt-2" {
		t.Fatalf("refresh = %+v, %v", ns, err)
	}
	if _, err := c.Refresh(ctx, ns); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("used refresh token: err = %v", err)
	}

	dr, err := c.Disconnect(ctx, ns)
	if err != nil || len(dr.Closed) != 1 || len(dr.Session.Consents) != 0 {
		t.Fatalf("disconnect = %+v, %v", dr, err)
	}
}

func TestScheduledSEPAPayment(t *testing.T) {
	f := newFakeBank(t)
	c := newTestClient(t, f, obsdk.Target{Bank: "spankki", Country: "FI"})
	ctx := context.Background()
	req := obsdk.PaymentRequest{
		Type: obsdk.PaymentSEPA, ExecutionDate: "2026-10-25",
		Transfers: []obsdk.Transfer{{
			Amount:     obsdk.Money{Amount: "10", Currency: "EUR"},
			Creditor:   obsdk.Creditor{Name: "Maija", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI5542345670000081"}, Address: &obsdk.PostalAddress{Town: "Helsinki", Country: "FI"}},
			Remittance: []string{"Rent"},
		}},
	}
	st, err := c.InitiatePayment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	cons := "POST /open-banking/v3.1.7/pisp/international-scheduled-payment-consents"
	var body struct {
		Data struct {
			Permission string
			Initiation map[string]any
		}
	}
	if err := json.Unmarshal(f.bodies[cons], &body); err != nil {
		t.Fatal(err)
	}
	ini := body.Data.Initiation
	if body.Data.Permission != "Create" || ini["LocalInstrument"] != "UK.OBIE.SEPACreditTransfer" || ini["CurrencyOfTransfer"] != "EUR" ||
		ini["RequestedExecutionDateTime"] != "2026-10-25T12:00:00+00:00" || ini["InstructedAmount"].(map[string]any)["Amount"] != "10.00" {
		t.Errorf("initiation = %v", body.Data)
	}
	if ini["Creditor"].(map[string]any)["PostalAddress"].(map[string]any)["TownName"] != "Helsinki" {
		t.Errorf("creditor = %v", ini["Creditor"])
	}
	if sig := f.headers[cons].Get("x-jws-signature"); !strings.Contains(sig, "..") {
		t.Errorf("x-jws-signature = %q", sig)
	}
	ro := requestObject(t, st.Redirect.URL)
	if ro["scope"] != "openid payments" {
		t.Errorf("scope = %v", ro["scope"])
	}

	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb#code=the-code&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	p := done.Payment
	if p.ID != "p-1" || p.Status != obsdk.PaymentInProgress || !p.Final || p.Debtor == nil || p.Debtor.Value != "FI2112345600000785" {
		t.Errorf("payment = %+v", p)
	}
	if h := f.headers["POST /open-banking/v3.1.7/pisp/international-scheduled-payments"]; h.Get("Authorization") != "Bearer user-token" {
		t.Errorf("submission headers = %v", h)
	}

	cs, err := c.CancelPayment(ctx, p.Ref, obsdk.PaymentCallOptions{})
	if err != nil || cs.Payment.Status != obsdk.PaymentCancelled {
		t.Fatalf("cancel = %+v, %v", cs, err)
	}
}

func TestPaymentRules(t *testing.T) {
	f := newFakeBank(t)
	ctx := context.Background()
	fi := newTestClient(t, f, obsdk.Target{Bank: "spankki", Country: "FI"})
	tr := obsdk.Transfer{Amount: obsdk.Money{Amount: "1", Currency: "EUR"}, Creditor: obsdk.Creditor{Name: "X",
		Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI5542345670000081"}, Address: &obsdk.PostalAddress{Lines: []string{"Somewhere"}}}}
	if _, err := fi.InitiatePayment(ctx, obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, Transfers: []obsdk.Transfer{tr}}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("unstructured address: err = %v", err)
	}
	resurs := newTestClient(t, f, obsdk.Target{Bank: "resursbank", Country: "SE"})
	if _, err := resurs.InitiatePayment(ctx, obsdk.PaymentRequest{Type: obsdk.PaymentDomestic}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Errorf("resurs payment: err = %v", err)
	}
}

func TestBuilders(t *testing.T) {
	newID := func() string { return "id" }
	fam, ini, _, err := buildSwedish(obsdk.PaymentRequest{Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "5", Currency: "SEK"},
		Creditor:  obsdk.Creditor{Name: "Elbolaget", Account: obsdk.Identifier{Scheme: obsdk.SchemeBankgiro, Value: "5050-1055"}},
		Reference: &obsdk.Reference{Scheme: obsdk.ReferenceOCR, Value: "1234567897"}}}}, obsdk.Target{}, newID)
	d := ini.(domInitiation)
	if err != nil || fam != "domestic" || d.LocalInstrument != "SE.Bankgiro" || d.CreditorAccount.SchemeName != "SE.BGNR" || d.RemittanceInformation.Reference != "1234567897" {
		t.Errorf("swedish = %s %+v %v", fam, d, err)
	}
	fam, ini, _, err = buildMorrow(obsdk.PaymentRequest{Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "5", Currency: "NOK"},
		Creditor: obsdk.Creditor{Name: "Ola", Account: obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "12345678903"}}}}}, obsdk.Target{Country: "NO"}, newID)
	d = ini.(domInitiation)
	if err != nil || fam != "domestic" || d.LocalInstrument != "" || d.CreditorAccount.SchemeName != "UK.OBIE.BBAN" {
		t.Errorf("morrow = %s %+v %v", fam, d, err)
	}
}

func TestInfo(t *testing.T) {
	for _, tc := range []struct {
		bank     string
		country  obsdk.Country
		segment  obsdk.Segment
		types    int
		maturity obsdk.Maturity
	}{
		{"spankki", "FI", obsdk.Personal, 2, obsdk.MaturitySandboxVerified},
		{"spankki", "FI", obsdk.Business, 2, obsdk.MaturityExperimental},
		{"aktia", "FI", obsdk.Business, 2, obsdk.MaturitySandboxVerified},
		{"alandsbanken", "FI", obsdk.Personal, 2, obsdk.MaturitySandboxVerified},
		{"alandsbanken", "SE", obsdk.Personal, 1, obsdk.MaturitySandboxVerified},
		{"morrowbank", "NO", obsdk.Personal, 3, obsdk.MaturitySandboxVerified},
		{"resursbank", "DK", obsdk.Personal, 0, obsdk.MaturitySandboxVerified},
	} {
		f := newFakeBank(t)
		c := newTestClient(t, f, obsdk.Target{Bank: tc.bank, Country: tc.country, Segment: tc.segment})
		i := c.Info()
		if len(i.Variants) != 1 || i.Variants[0].Country != tc.country || len(i.Payments) != tc.types || i.Spec != "uk" {
			t.Errorf("%s %s %s: info = %+v", tc.bank, tc.country, tc.segment, i)
			continue
		}
		if v := i.Variants[0]; v.Maturity != tc.maturity || (tc.maturity == obsdk.MaturitySandboxVerified) != (v.VerifiedOn != "") {
			t.Errorf("%s %s %s: maturity %s (%q), want %s", tc.bank, tc.country, tc.segment, v.Maturity, v.VerifiedOn, tc.maturity)
		}
	}
}
