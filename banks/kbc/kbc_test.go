package kbc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type fake struct {
	t    *testing.T
	seen []string
	h    map[string]func(w http.ResponseWriter, r *http.Request, body []byte)
}

func newFake(t *testing.T) (*fake, *httptest.Server) {
	f := &fake{t: t, h: map[string]func(http.ResponseWriter, *http.Request, []byte){}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		k := r.Method + " " + r.URL.Path
		f.seen = append(f.seen, k)
		if !strings.HasPrefix(r.URL.Path, "/ASK/") && r.Header.Get("X-Request-ID") == "" {
			t.Errorf("%s without X-Request-ID", k)
		}
		h, ok := f.h[k]
		if !ok {
			t.Errorf("unexpected request %s", k)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		h(w, r, body)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func reply(status int, body string) func(http.ResponseWriter, *http.Request, []byte) {
	return func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func newTestClient(t *testing.T, bank string, srv *httptest.Server) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "PSDBE-NBB-0123456789", RedirectURL: "https://example.com/cb"},
		HTTPClient:  http.DefaultClient,
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{},
	}
	if srv != nil {
		cfg.HTTPClient = srv.Client()
		cfg.Extra[paramBaseURL] = srv.URL + "/psd2/v2"
		cfg.Extra[paramTokenURL] = srv.URL + "/ASK/oauth/token/1"
		cfg.Extra[paramAuthURL] = srv.URL + "/ASK/oauth/authorize/1"
	}
	c, err := obsdk.New(obsdk.Target{Bank: bank, Country: "BE"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func session(bank string) *obsdk.Session {
	exp := frozen.Add(30 * time.Minute)
	until := frozen.AddDate(0, 0, 90)
	return &obsdk.Session{Version: 1, Bank: bank, Country: "BE", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationPrefix + bank, AccessToken: "at", RefreshToken: "rt", AccessExpiresAt: &exp,
		Consents: map[string]obsdk.Consent{consentKind: {ID: "cons-1", Kind: consentKind, ValidUntil: &until}}, Meta: map[string]string{}}
}

const accountsJSON = `{"accounts":[{"resourceId":"test-account-001","iban":"BE16690375703426","currency":"EUR","name":"KBC-BE-USER-01","product":"","cashAccountType":"CACC","balances":[{"balanceAmount":{"amount":"1000.00","currency":"EUR"},"balanceType":"closingBooked"}]}]}`

func TestRegistrationAndHosts(t *testing.T) {
	for _, tc := range []struct{ bank, api string }{
		{"kbc", "https://psd2.api.kbc.be/psd2/v2"},
		{"cbc", "https://psd2.api.cbc.be/psd2/v2"},
		{"kbcbrussels", "https://psd2.api.kbcbrussels.be/psd2/v2"},
	} {
		c, err := obsdk.New(obsdk.Target{Bank: tc.bank, Country: "BE", Segment: obsdk.Business},
			obsdk.Config{Env: obsdk.Production, Credentials: obsdk.Credentials{ClientID: "x", RedirectURL: "https://example.com/cb"}, HTTPClient: http.DefaultClient})
		if err != nil {
			t.Fatalf("%s: %v", tc.bank, err)
		}
		kc := c.(*client)
		if kc.api != tc.api || kc.tokenURL != productionToken || kc.authorize != productionAuthorize {
			t.Errorf("%s: hosts %s %s %s", tc.bank, kc.api, kc.tokenURL, kc.authorize)
		}
		if len(c.Info().Variants) != 1 || c.Info().Variants[0].Maturity != obsdk.MaturityUnverified {
			t.Errorf("%s: Info should narrow to the unverified production variant, got %+v", tc.bank, c.Info().Variants)
		}
	}
	if _, err := obsdk.New(obsdk.Target{Bank: "kbc", Country: "BE"}, obsdk.Config{Env: obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "x", RedirectURL: "https://example.com/cb"}}); !errors.Is(err, obsdk.ErrInvalidConfig) {
		t.Fatalf("a client without the QWAC should be a config error, got %v", err)
	}
}

func TestClientIDFromCertificate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: frozen, NotAfter: frozen.AddDate(1, 0, 0),
		Subject: pkix.Name{CommonName: "tpp", ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidOrganizationIdentifier, Value: "PSDBE-NBB-0123456789"}}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if id, err := ClientID(cert); err != nil || id != "PSDBE-NBB-0123456789" {
		t.Fatalf("ClientID = %q, %v", id, err)
	}
	cert.Subject.Names = nil
	if _, err := ClientID(cert); err == nil {
		t.Fatal("a certificate without organizationIdentifier should fail")
	}
}

func TestConsentBody(t *testing.T) {
	for _, tc := range []struct {
		caps []obsdk.Capability
		iban string
		want string
	}{
		{nil, "", `{"balances":[],"transactions":[]}`},
		{nil, "BE16690375703426", `{"balances":[{"iban":"BE16690375703426"}],"transactions":[{"iban":"BE16690375703426"}]}`},
		{[]obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances}, "", `{"balances":[]}`},
	} {
		b, _ := json.Marshal(consentBody(tc.caps, tc.iban, "2027-01-15").Access)
		if string(b) != tc.want {
			t.Errorf("access for %v %q = %s, want %s", tc.caps, tc.iban, b, tc.want)
		}
	}
	b, _ := json.Marshal(consentBody(nil, "", "2027-01-15"))
	if !strings.Contains(string(b), `"recurringIndicator":true,"validUntil":"2027-01-15","frequencyPerDay":4,"combinedServiceIndicator":false`) {
		t.Errorf("consent body %s", b)
	}
}

func TestPKCE(t *testing.T) {
	// RFC 7636, appendix B.
	if got := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %s", got)
	}
	c := newTestClient(t, "kbc", nil)
	if v := c.newVerifier(); len(v) < 43 || len(v) > 128 || strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") != "" {
		t.Fatalf("verifier %q: RFC 7636 wants 43 to 128 unreserved characters", v)
	}
}

func TestConnect(t *testing.T) {
	f, srv := newFake(t)
	f.h["POST /psd2/v2/consents"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("TPP-Redirect-URI") != "https://example.com/cb" || r.Header.Get("PSU-IP-Address") != "203.0.113.7" {
			t.Errorf("consent headers %v", r.Header)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("consent creation needs no token")
		}
		var cr consentRequest
		_ = json.Unmarshal(body, &cr)
		if cr.ValidUntil != "2027-01-15" || len(cr.Access["balances"]) != 1 || cr.Access["balances"][0].IBAN != "BE16690375703426" {
			t.Errorf("consent body %s", body)
		}
		reply(201, `{"consentStatus":"received","consentId":"lUGicdMakm","_links":{}}`)(w, r, body)
	}
	var verifier string
	f.h["POST /ASK/oauth/token/1"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "authorization_code" || form.Get("code") != "the-code" || form.Get("client_id") != "PSDBE-NBB-0123456789" ||
			form.Get("redirect_uri") != "https://example.com/cb" || form.Get("client_secret") != "" {
			t.Errorf("token form %v", form)
		}
		verifier = form.Get("code_verifier")
		reply(200, `{"access_token":"AT","expires_in":1800,"token_type":"bearer","refresh_token":"RT","scope":"AIS"}`)(w, r, body)
	}
	f.h["GET /psd2/v2/accounts"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("Authorization") != "Bearer AT" || r.Header.Get("Consent-ID") != "lUGicdMakm" || r.URL.Query().Get("withBalance") != "true" {
			t.Errorf("accounts call %v %v", r.Header, r.URL)
		}
		reply(200, accountsJSON)(w, r, body)
	}
	c := newTestClient(t, "kbcbrussels", srv)

	if _, err := c.Connect(context.Background(), obsdk.ConnectRequest{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("Connect without PSU IP should be refused, got %v", err)
	}
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}, Language: "fr",
		Values: map[string]string{"iban": "BE16 6903 7570 3426"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.Redirect.URL)
	q := u.Query()
	if u.Path != "/ASK/oauth/authorize/1" || q.Get("scope") != "AIS:lUGicdMakm" || q.Get("client_id") != "PSDBE-NBB-0123456789" ||
		q.Get("response_type") != "code" || q.Get("state") != "state-1" || q.Get("code_challenge_method") != "S256" ||
		q.Get("mainCompany") != "0001" || q.Get("company") != "9998" || q.Get("language") != "FR" {
		t.Fatalf("authorize URL %s", st.Redirect.URL)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb?error=access_denied&error_description=user+cancelled&state=state-1"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("a cancelled authorisation should fail auth, got %v", err)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb?code=x&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch should fail auth, got %v", err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb?code=the-code&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	if pkceChallenge(verifier) != q.Get("code_challenge") {
		t.Errorf("code_verifier does not match the challenge")
	}
	s := done.Session
	cons := s.Consents[consentKind]
	if s.Bank != "kbcbrussels" || s.Integration != "kbc-psd2-kbcbrussels" || s.AccessToken != "AT" || s.RefreshToken != "RT" ||
		s.AccessExpiresAt == nil || !s.AccessExpiresAt.Equal(frozen.Add(30*time.Minute)) {
		t.Fatalf("session %+v", s)
	}
	if cons.ID != "lUGicdMakm" || cons.ValidUntil == nil || cons.ValidUntil.Format("2006-01-02") != "2027-01-15" ||
		len(cons.Accounts) != 1 || cons.Accounts[0] != "BE16690375703426" {
		t.Fatalf("consent %+v", cons)
	}
	a := done.Accounts[0]
	if a.ID != "test-account-001" || a.Type != "CACC" || a.BIC != "KREDBEBB" || len(a.Balances) != 1 ||
		a.Balances[0].Kind != obsdk.BalanceClosingBooked || a.Balances[0].Amount.Amount != "1000.00" {
		t.Fatalf("account %+v", a)
	}
}

func TestConnectBankOfferedConsent(t *testing.T) {
	f, srv := newFake(t)
	f.h["POST /psd2/v2/consents"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if !strings.Contains(string(body), `"access":{"balances":[],"transactions":[]}`) {
			t.Errorf("consent body %s", body)
		}
		reply(201, `{"consentStatus":"received","consentId":"c2","_links":{}}`)(w, r, body)
	}
	c := newTestClient(t, "cbc", srv)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}, ConsentValidityDays: 400})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.Redirect.URL)
	if u.Query().Get("mainCompany") != "0002" || u.Query().Has("company") || u.Query().Has("language") {
		t.Fatalf("authorize URL %s", st.Redirect.URL)
	}
	if _, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}, Values: map[string]string{"iban": "BE00"}}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("an invalid IBAN should be refused, got %v", err)
	}
	if validityDays(400) != maxConsentDays || validityDays(0) != defaultConsentDays || validityDays(30) != 30 {
		t.Fatal("consent validity clamping")
	}
}

func TestErrors(t *testing.T) {
	f, srv := newFake(t)
	c := newTestClient(t, "kbc", srv)
	ctx := context.Background()
	for _, tc := range []struct {
		status int
		body   string
		want   error
		reason string
	}{
		{401, `{"tppMessages":[{"category":"ERROR","code":"TOKEN_INVALID","text":"Full authentication is required to access this resource"}]}`, obsdk.ErrAccessExpired, ""},
		{401, `{"status":401,"message":"invalid token"}`, obsdk.ErrAccessExpired, ""},
		{401, `{"tppMessages":[{"category":"ERROR","code":"CONSENT_EXPIRED"}]}`, obsdk.ErrReauthRequired, "consent_expired"},
		{401, `{"tppMessages":[{"category":"ERROR","code":"CONSENT_INVALID"}]}`, obsdk.ErrReauthRequired, "consent_invalid"},
		{429, `{"tppMessages":[{"category":"ERROR","code":"ACCESS_EXCEEDED"}]}`, obsdk.ErrRateLimited, ""},
	} {
		f.h["GET /psd2/v2/accounts/test-account-001/balances"] = reply(tc.status, tc.body)
		_, err := c.Balances(ctx, session("kbc"), "test-account-001", obsdk.CallOptions{})
		if !errors.Is(err, tc.want) {
			t.Errorf("%d %s: got %v, want %v", tc.status, tc.body, err, tc.want)
		}
		var re *obsdk.ReauthError
		if tc.reason != "" && (!errors.As(err, &re) || re.Reason != tc.reason) {
			t.Errorf("%s: reauth reason %v", tc.body, err)
		}
	}
	expired := session("kbc")
	past := frozen.Add(-time.Minute)
	expired.AccessExpiresAt = &past
	if _, err := c.Accounts(ctx, expired, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("an expired token should not be sent, got %v", err)
	}
	if _, err := c.Accounts(ctx, session("cbc"), obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("a CBC session on a KBC client should be refused, got %v", err)
	}
}

func TestBalances(t *testing.T) {
	f, srv := newFake(t)
	f.h["GET /psd2/v2/accounts/test-account-001/balances"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("Consent-ID") != "cons-1" || r.Header.Get("PSU-IP-Address") != "203.0.113.7" {
			t.Errorf("balances headers %v", r.Header)
		}
		reply(200, `{"account":{"iban":"BE16690375703426","currency":"EUR"},"balances":[{"balanceAmount":{"currency":"EUR","amount":"-12.30"},"balanceType":"closingBooked"}]}`)(w, r, body)
	}
	c := newTestClient(t, "kbc", srv)
	res, err := c.Balances(context.Background(), session("kbc"), "test-account-001", obsdk.CallOptions{PSU: &obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Data) != 1 || res.Data[0].Amount.Amount != "-12.30" || res.Data[0].Kind != obsdk.BalanceClosingBooked {
		t.Fatalf("balances %+v", res.Data)
	}
}

func TestTransactionsPaging(t *testing.T) {
	f, srv := newFake(t)
	f.h["GET /psd2/v2/accounts/test-account-001/transactions"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		q := r.URL.Query()
		switch q.Get("page") {
		case "":
			if q.Get("bookingStatus") != "booked" || q.Get("dateFrom") != "2026-07-19" || q.Has("dateTo") {
				t.Errorf("first page query %v", q)
			}
			reply(200, `{"account":{"iban":"BE16690375703426"},"transactions":{"booked":[
				{"transactionId":"t1","bookingDate":"2026-10-01","valueDate":"2026-10-01","transactionAmount":{"currency":"EUR","amount":"-3.14"},
				 "creditorName":"Shop","creditorAccount":{"iban":"BE63380242772874"},"debtorName":"Me","debtorAccount":{"iban":"BE16690375703426"},
				 "remittanceInformationUnstructured":" lunch ","remittanceInformationStructured":"+++090/9337/55493+++","bankTransactionCode":"PMNT-ICDT-ESCT"}],
				"_links":{"account":"/accounts/test-account-001","next":"/psd2/v2/accounts/test-account-001/transactions?page=2"}}}`)(w, r, body)
		case "2":
			reply(200, `{"transactions":{"booked":[{"transactionId":"t2","bookingDate":"2026-09-30","transactionAmount":{"currency":"EUR","amount":"11.22"},
				"debtorName":"Employer","debtorAccount":{"iban":"BE63380242772874"},"proprietaryBankTransactionCode":"0150"}],
				"_links":{"account":"/accounts/test-account-001","next":"/psd2/v2/accounts/test-account-001/transactions?page=2"}}}`)(w, r, body)
		}
	}
	c := newTestClient(t, "kbc", srv)
	ctx := context.Background()
	p1, err := c.Transactions(ctx, session("kbc"), obsdk.TxQuery{AccountID: "test-account-001"})
	if err != nil {
		t.Fatal(err)
	}
	tx := p1.Transactions[0]
	if tx.ID != "t1" || tx.Direction != obsdk.Debit || tx.Counterparty.Name != "Shop" || tx.Counterparty.Identifiers[0].Value != "BE63380242772874" ||
		tx.Remittance[0] != "lunch" || tx.ReferenceNumber != "+++090/9337/55493+++" || tx.BankCode != "PMNT-ICDT-ESCT" {
		t.Fatalf("transaction %+v", tx)
	}
	if p1.NextCursor != "/psd2/v2/accounts/test-account-001/transactions?page=2" {
		t.Fatalf("cursor %q", p1.NextCursor)
	}
	p2, err := c.Transactions(ctx, session("kbc"), obsdk.TxQuery{AccountID: "test-account-001", Cursor: p1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	tx = p2.Transactions[0]
	if tx.Direction != obsdk.Credit || tx.Counterparty.Name != "Employer" || tx.BankCode != "0150" {
		t.Fatalf("transaction %+v", tx)
	}
	if p2.NextCursor != "" {
		t.Fatalf("a next link to the same page should end paging, got %q", p2.NextCursor)
	}
	if _, err := c.Transactions(ctx, session("kbc"), obsdk.TxQuery{AccountID: "test-account-001", Cursor: "/psd2/v2/accounts/other/transactions?page=2"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("a cursor of another account should be refused, got %v", err)
	}
	if _, err := c.Transactions(ctx, session("kbc"), obsdk.TxQuery{AccountID: "test-account-001", Status: []obsdk.TxStatus{obsdk.TxPending}}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("pending should be unsupported, got %v", err)
	}
}

func TestCursorForms(t *testing.T) {
	c := newTestClient(t, "kbc", nil)
	for _, cur := range []string{
		"/psd2/v2/accounts/a1/transactions?page=2",
		"/accounts/a1/transactions?page=2",
		"https://be.psd2.sandbox.kbc-group.com/psd2/v2/accounts/a1/transactions?page=2",
	} {
		r, err := c.cursorRequest("/accounts/a1", cur)
		if err != nil || r.path != "/accounts/a1/transactions" || r.query.Get("page") != "2" {
			t.Errorf("%s: %+v %v", cur, r, err)
		}
	}
}

func TestRefresh(t *testing.T) {
	f, srv := newFake(t)
	f.h["POST /ASK/oauth/token/1"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		form, _ := url.ParseQuery(string(body))
		switch form.Get("refresh_token") {
		case "rt":
			if form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "PSDBE-NBB-0123456789" {
				t.Errorf("refresh form %v", form)
			}
			reply(200, `{"access_token":"AT2","expires_in":1800,"token_type":"bearer","refresh_token":"RT2","scope":"AIS"}`)(w, r, body)
		case "RT2":
			reply(200, `{"access_token":"AT3","expires_in":1800,"token_type":"bearer","scope":"AIS"}`)(w, r, body)
		default:
			reply(400, `{"error":"invalid_grant"}`)(w, r, body)
		}
	}
	c := newTestClient(t, "kbc", srv)
	ctx := context.Background()
	s, err := c.Refresh(ctx, session("kbc"))
	if err != nil {
		t.Fatal(err)
	}
	if s.AccessToken != "AT2" || s.RefreshToken != "RT2" || s.Generation != 1 {
		t.Fatalf("refreshed session %+v", s)
	}
	s, err = c.Refresh(ctx, s)
	if err != nil || s.AccessToken != "AT3" || s.RefreshToken != "RT2" {
		t.Fatalf("without a new refresh token the current one stays: %+v %v", s, err)
	}
	old := session("kbc")
	old.RefreshToken = "used"
	_, err = c.Refresh(ctx, old)
	var re *obsdk.RefreshError
	if !errors.As(err, &re) || re.Temporary || !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("a rotated refresh token should need re-authorisation, got %v", err)
	}
	expired := session("kbc")
	past := frozen.Add(-time.Hour)
	expired.Consents[consentKind] = obsdk.Consent{ID: "cons-1", Kind: consentKind, ValidUntil: &past}
	if _, err := c.Refresh(ctx, expired); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("an expired consent should need re-authorisation, got %v", err)
	}
}

func TestDisconnect(t *testing.T) {
	f, srv := newFake(t)
	f.h["DELETE /psd2/v2/consents/cons-1"] = reply(405, `{"tppMessages":[{"category":"ERROR","code":"SERVICE_INVALID"}]}`)
	c := newTestClient(t, "kbc", srv)
	res, err := c.Disconnect(context.Background(), session("kbc"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Closed) != 0 || res.Failed[consentKind] == "" || res.Session.AccessToken != "at" {
		t.Fatalf("an unsupported deletion is reported and leaves the session: %+v", res)
	}
	f.h["DELETE /psd2/v2/consents/cons-1"] = reply(204, ``)
	res, _ = c.Disconnect(context.Background(), session("kbc"))
	if len(res.Closed) != 1 || res.Session.AccessToken != "" || len(res.Session.Consents) != 0 {
		t.Fatalf("a deleted consent clears the session: %+v", res)
	}
}

func payment(typ obsdk.PaymentType) obsdk.PaymentRequest {
	return obsdk.PaymentRequest{
		Type: typ, PSU: obsdk.PSUContext{IP: "203.0.113.7"},
		Transfers: []obsdk.Transfer{{
			Amount:     obsdk.Money{Amount: "12.50", Currency: "EUR"},
			Creditor:   obsdk.Creditor{Name: "Jan Peeters", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "BE63380242772874"}},
			Remittance: []string{"Invoice 42"},
			EndToEndID: "E2E-1",
		}},
	}
}

func TestPaymentFlow(t *testing.T) {
	f, srv := newFake(t)
	status := "RCVD"
	f.h["POST /psd2/v2/payments/sepa-credit-transfers"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("TPP-Redirect-URI") != "https://example.com/cb" || r.Header.Get("PSU-IP-Address") != "203.0.113.7" || r.Header.Get("Authorization") != "" {
			t.Errorf("payment headers %v", r.Header)
		}
		want := `{"endToEndIdentification":"E2E-1","instructedAmount":{"currency":"EUR","amount":"12.50"},"creditorAccount":{"iban":"BE63380242772874"},` +
			`"creditorName":"Jan Peeters","remittanceInformationUnstructured":"Invoice 42","requestedExecutionDate":"2026-10-17"}`
		if string(body) != want {
			t.Errorf("payment body\n got %s\nwant %s", body, want)
		}
		reply(201, `{"transactionStatus":"RCVD","paymentId":"nqItDdrASV","_links":{"scaRedirect":"/ASK/psd2/sca?paymentId=nqItDdrASV","status":"/v2/payments/sepa-credit-transfers/nqItDdrASV/status"}}`)(w, r, body)
	}
	f.h["GET /psd2/v2/payments/sepa-credit-transfers/nqItDdrASV/status"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		reply(200, `{"transactionStatus":"`+status+`"}`)(w, r, body)
	}
	c := newTestClient(t, "kbc", srv)
	ctx := context.Background()
	st, err := c.InitiatePayment(ctx, payment(obsdk.PaymentSEPA))
	if err != nil {
		t.Fatal(err)
	}
	if st.Redirect.URL != srv.URL+"/ASK/psd2/sca?paymentId=nqItDdrASV" || st.Payment.ID != "nqItDdrASV" || st.Payment.Status != obsdk.PaymentReceived {
		t.Fatalf("step %+v %+v", st.Redirect, st.Payment)
	}
	_, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://example.com/cb"})
	var fe *obsdk.FlowError
	if !errors.As(err, &fe) || fe.Payment == nil || !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("an unsigned payment should fail with the payment attached, got %v", err)
	}
	status = "ACSP"
	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Payment.Status != obsdk.PaymentInProgress || done.Payment.BankStatus != "ACSP" {
		t.Fatalf("done %+v", done.Payment)
	}
	status = "ACSC"
	res, err := c.PaymentStatus(ctx, done.Payment.Ref, obsdk.PaymentCallOptions{})
	if err != nil || res.Data.Status != obsdk.PaymentCompleted || !res.Data.Final {
		t.Fatalf("status %+v %v", res, err)
	}
	if _, err := c.CancelPayment(ctx, done.Payment.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("cancel should be unsupported, got %v", err)
	}
	if _, err := newTestClient(t, "cbc", srv).PaymentStatus(ctx, done.Payment.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("a KBC payment ref on a CBC client should be refused, got %v", err)
	}
}

func TestCrossBorderBody(t *testing.T) {
	r := payment(obsdk.PaymentCrossBorder)
	r.ExecutionDate, r.ChargeBearer = "2026-10-20", obsdk.ChargeBearerShared
	r.Debtor = &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "BE16690375703426"}}
	tr := &r.Transfers[0]
	tr.Remittance, tr.Reference = nil, &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}
	tr.Creditor.Agent = &obsdk.Agent{BIC: "CHASUS33", MemberID: "021000021"}
	tr.Creditor.Address = &obsdk.PostalAddress{Street: "Main St", BuildingNumber: "1", Town: "New York", PostCode: "10001", Country: "US"}
	spec, _ := obsdk.Lookup("kbc")
	ps, _ := spec.PaymentSpec("BE", obsdk.Personal, obsdk.PaymentCrossBorder)
	if err := ps.Validate(r, frozen); err != nil {
		t.Fatal(err)
	}
	b, err := buildBody(r, frozen)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(b)
	want := `{"endToEndIdentification":"E2E-1","debtorAccount":{"iban":"BE16690375703426","currency":"EUR"},"instructedAmount":{"currency":"EUR","amount":"12.50"},` +
		`"creditorAccount":{"iban":"BE63380242772874"},"creditorAgent":"CHASUS33","creditorName":"Jan Peeters",` +
		`"creditorAddress":{"street":"Main St","buildingNumber":"1","city":"New York","postalCode":"10001","country":"US"},` +
		`"creditorBankCode":"021000021","chargeBearer":"SHAR","remittanceInformationStructured":{"reference":"RF18539007547034","referenceType":"SCOR","referenceIssuer":"ISO"},` +
		`"requestedExecutionDate":"2026-10-20"}`
	if string(got) != want {
		t.Fatalf("body\n got %s\nwant %s", got, want)
	}
	tr.Creditor.Address = &obsdk.PostalAddress{Town: "New York"}
	if _, err := buildBody(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("an address without country should be refused, got %v", err)
	}
}

func TestBelgianReference(t *testing.T) {
	r := payment(obsdk.PaymentSEPAInstant)
	r.Transfers[0].Remittance, r.Transfers[0].Reference = nil, &obsdk.Reference{Scheme: obsdk.ReferenceBE, Value: "123456789002"}
	spec, _ := obsdk.Lookup("kbc")
	ps, _ := spec.PaymentSpec("BE", obsdk.Personal, obsdk.PaymentSEPAInstant)
	if err := ps.Validate(r, frozen); err != nil {
		t.Fatal(err)
	}
	b, _ := buildBody(r, frozen)
	got, _ := json.Marshal(b.Structured)
	if want := `{"reference":"123456789002","referenceType":"SCOR","referenceIssuer":"BBA"}`; string(got) != want {
		t.Fatalf("structured %s, want %s", got, want)
	}
}

func TestExecutionDateIsTodayInBrussels(t *testing.T) {
	late := time.Date(2026, 10, 17, 23, 30, 0, 0, time.UTC) // already the 18th in Brussels
	b, _ := buildBody(payment(obsdk.PaymentSEPAInstant), late)
	if b.RequestedExecutionDate != "2026-10-18" {
		t.Fatalf("requestedExecutionDate %s", b.RequestedExecutionDate)
	}
	spec, _ := obsdk.Lookup("kbc")
	ps, _ := spec.PaymentSpec("BE", obsdk.Personal, obsdk.PaymentSEPAInstant)
	r := payment(obsdk.PaymentSEPAInstant)
	r.ExecutionDate = "2026-10-20"
	if err := ps.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("instant payments take no execution date, got %v", err)
	}
}

func TestPaymentRejected(t *testing.T) {
	f, srv := newFake(t)
	c := newTestClient(t, "kbc", srv)
	ctx := context.Background()
	f.h["POST /psd2/v2/payments/instant-sepa-credit-transfers"] = reply(400, `{"tppMessages":[{"category":"ERROR","code":"FORMAT_ERROR","text":"creditorName"}]}`)
	_, err := c.InitiatePayment(ctx, payment(obsdk.PaymentSEPAInstant))
	var ae *obsdk.APIError
	if !errors.As(err, &ae) || ae.Code != "FORMAT_ERROR" || errors.Is(err, obsdk.ErrPaymentRejected) {
		t.Fatalf("a format error is the request's fault, got %v", err)
	}
	f.h["POST /psd2/v2/payments/instant-sepa-credit-transfers"] = reply(400, `{"tppMessages":[{"category":"ERROR","code":"PAYMENT_FAILED"}]}`)
	if _, err := c.InitiatePayment(ctx, payment(obsdk.PaymentSEPAInstant)); !errors.Is(err, obsdk.ErrPaymentRejected) {
		t.Fatalf("PAYMENT_FAILED should be a rejection, got %v", err)
	}
	r := payment(obsdk.PaymentSEPA)
	r.PSU.IP = ""
	if _, err := c.InitiatePayment(ctx, r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("a payment without PSU IP should be refused, got %v", err)
	}
}
