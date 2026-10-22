package luxhub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
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

var frozen = time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)

func bankByKey(t *testing.T, key string) bank {
	t.Helper()
	for _, b := range banks {
		if b.key == key {
			return b
		}
	}
	t.Fatalf("no bank %q", key)
	return bank{}
}

func TestEndpoints(t *testing.T) {
	lu, be := obsdk.Target{Country: "LU"}, obsdk.Target{Country: "BE"}
	raif, bdl, bcee := bankByKey(t, "raiffeisenlu"), bankByKey(t, "banquedeluxembourg"), bankByKey(t, "spuerkeess")
	api := func(h hosts) string { return h.api }
	tok := func(h hosts) string { return h.token }
	auth := func(h hosts) string { return h.authorize }
	for _, c := range []struct{ got, want string }{
		{raif.endpoint(api)(obsdk.Sandbox, lu, ""), "https://ccralull-psd2api-sbx.luxhub.com/bg"},
		{raif.endpoint(api)(obsdk.Production, lu, ""), "https://ccralull-psd2api.luxhub.com/bg"},
		{raif.endpoint(tok)(obsdk.Sandbox, lu, ""), "https://ccralull-psd2api-sbx.luxhub.com/api/oauth/token"},
		{raif.endpoint(auth)(obsdk.Production, lu, ""), "https://ccralull-cb.luxhub.com/api/oauth/authorize"},
		{bdl.endpoint(api)(obsdk.Production, be, ""), "https://bluxbe41-psd2api.luxhub.com/bg"},
		{bdl.endpoint(api)(obsdk.Production, obsdk.Target{Country: "DE"}, ""), ""},
		{bcee.endpoint(api)(obsdk.Sandbox, lu, ""), "https://sbopenbank.bcee.lu/bg"},
		{bcee.endpoint(auth)(obsdk.Production, lu, ""), "https://cbopenbank.bcee.lu/api/oauth/authorize"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

func TestKeyID(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: new(big.Int).SetUint64(0x53d0c3f63caee406),
		Issuer: pkix.Name{CommonName: "Mock-eIDAS IntermediateCA", OrganizationalUnit: []string{"TST"}, Organization: []string{"LUXHUB SA"},
			Locality: []string{"Strassen"}, Province: []string{"Luxembourg"}, Country: []string{"LU"}}}
	// The keyId of LUXHUB's signing example.
	want := "SN=53d0c3f63caee406,CA=CN=Mock-eIDAS IntermediateCA,OU=TST,O=LUXHUB SA,L=Strassen,ST=Luxembourg,C=LU"
	if got := keyID(cert); got != want {
		t.Errorf("keyID = %q, want %q", got, want)
	}
}

func TestRegistration(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Profiles {
		if seen[p.Info.Bank] {
			t.Errorf("bank %q registered twice", p.Info.Bank)
		}
		seen[p.Info.Bank] = true
		for _, v := range p.Info.Variants {
			if p.BaseURL(v.Env, obsdk.Target{Country: v.Country}, "") == "" {
				t.Errorf("%s %s %s: no API root", p.Info.Bank, v.Country, v.Env)
			}
		}
		if (len(p.Info.Payments) > 0) != (len(p.Products) > 0) {
			t.Errorf("%s: payment specs and products disagree", p.Info.Bank)
		}
	}
}

func testSeal(t *testing.T) *obsdk.Seal {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0xabc123), Subject: pkix.Name{CommonName: "obsdk", Country: []string{"LU"}},
		NotBefore: frozen, NotAfter: frozen.AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &obsdk.Seal{Key: key, Certificate: cert}
}

// fakeHub is a LUXHUB bank as its documentation describes it: client
// credentials for the resources, an authorisation code for the accounts.
type fakeHub struct {
	t     *testing.T
	mu    sync.Mutex
	calls []string
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.t
	h.calls = append(h.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/oauth/token" {
		_ = r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok || id != "cid" || secret != "s3cret" || r.PostForm.Has("client_id") {
			t.Errorf("token request: basic %v %q, form %v", ok, id, r.PostForm)
		}
		switch r.PostForm.Get("grant_type") + " " + r.PostForm.Get("scope") {
		case "client_credentials AIS":
			io.WriteString(w, `{"access_token":"cc-ais","token_type":"Bearer","expires_in":300}`)
		case "client_credentials PIS:payment":
			io.WriteString(w, `{"access_token":"cc-pis","token_type":"Bearer","expires_in":300}`)
		case "authorization_code AIS:cons-1":
			io.WriteString(w, `{"access_token":"user","token_type":"Bearer","expires_in":3600,"refresh_token":"rt"}`)
		default:
			t.Errorf("token request %v", r.PostForm)
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_request"}`)
		}
		return
	}
	for _, hd := range []string{"Signature", "Digest", "Date", "TPP-Signature-Certificate", "X-Request-ID"} {
		if r.Header.Get(hd) == "" {
			t.Errorf("%s %s: no %s header", r.Method, r.URL.Path, hd)
		}
	}
	if sig := r.Header.Get("Signature"); !strings.Contains(sig, `keyId="SN=abc123,CA=`) || !strings.Contains(sig, `algorithm="rsa-sha256"`) {
		t.Errorf("Signature %q", sig)
	}
	auth := r.Header.Get("Authorization")
	switch r.Method + " " + r.URL.Path {
	case "POST /bg/v1/consents":
		if auth != "Bearer cc-ais" {
			t.Errorf("consent created with %q", auth)
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"consentStatus":"received","consentId":"cons-1","_links":{"self":{"href":"/bg/v1/consents/cons-1"},"status":{"href":"/bg/v1/consents/cons-1/status"}}}`)
	case "GET /bg/v1/consents/cons-1/status", "GET /bg/v1/consents/cons-1":
		if auth != "Bearer cc-ais" {
			t.Errorf("consent read with %q", auth)
		}
		io.WriteString(w, `{"consentStatus":"valid","validUntil":"2027-04-19"}`)
	case "GET /bg/v1/accounts":
		if auth != "Bearer user" || r.Header.Get("Consent-ID") != "cons-1" {
			t.Errorf("accounts read with %q / %q", auth, r.Header.Get("Consent-ID"))
		}
		io.WriteString(w, `{"accounts":[{"resourceId":"acc-1","iban":"LU280019400644750000","currency":"EUR","name":"Compte courant"}]}`)
	case "POST /bg/v1/payments/sepa-credit-transfers":
		if auth != "Bearer cc-pis" {
			t.Errorf("payment created with %q", auth)
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"transactionStatus":"RCVD","paymentId":"pay-1","_links":{"self":{"href":"/bg/v1/payments/sepa-credit-transfers/pay-1"},"status":{"href":"/bg/v1/payments/sepa-credit-transfers/pay-1/status"}}}`)
	case "GET /bg/v1/payments/sepa-credit-transfers/pay-1/status":
		if auth != "Bearer cc-pis" {
			t.Errorf("payment status read with %q", auth)
		}
		io.WriteString(w, `{"transactionStatus":"ACSP"}`)
	default:
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
		io.WriteString(w, `{"tppMessages":[{"category":"ERROR","code":"RESOURCE_UNKNOWN"}]}`)
	}
}

func newClient(t *testing.T, srv *httptest.Server) obsdk.Client {
	t.Helper()
	ids := 0
	c, err := obsdk.New(obsdk.Target{Bank: "raiffeisenlu", Country: "LU"}, obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "s3cret", RedirectURL: "https://app.example/cb"},
		HTTPClient:  srv.Client(),
		Seal:        testSeal(t),
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { ids++; return fmt.Sprintf("%s-%d", p, ids) },
		Extra: map[string]string{"base_url": srv.URL + "/bg", "oauth_token_url": srv.URL + "/api/oauth/token",
			"oauth_authorize_url": "https://ccralull-cb-sbx.luxhub.com/api/oauth/authorize"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConnectAndPay(t *testing.T) {
	h := &fakeHub{t: t}
	srv := httptest.NewTLSServer(h)
	defer srv.Close()
	c := newClient(t, srv)
	ctx := context.Background()
	psu := obsdk.PSUContext{IP: "203.0.113.7"}

	st, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: psu})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(st.Redirect.URL)
	if err != nil || st.Kind != obsdk.StepRedirect || u.Host != "ccralull-cb-sbx.luxhub.com" || u.Query().Get("scope") != "AIS:cons-1" ||
		u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("connect step: %+v", st)
	}
	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb?code=abc&state=" + u.Query().Get("state")})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Session.AccessToken != "user" || len(done.Accounts) != 1 {
		t.Fatalf("done: %+v", done)
	}

	st, err = c.InitiatePayment(ctx, obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, PSU: psu,
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "LU280019400644750000"}},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "12.50", Currency: "EUR"},
			Creditor: obsdk.Creditor{Name: "Payee", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "LU120010001234567891"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(st.Redirect.URL)
	if u.Query().Get("scope") != "PIS:pay-1" {
		t.Fatalf("payment step: %+v", st)
	}
	done, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb?code=xyz&state=" + u.Query().Get("state")})
	if err != nil {
		t.Fatal(err)
	}
	if done.Payment == nil || done.Payment.Status != obsdk.PaymentInProgress {
		t.Fatalf("payment done: %+v", done.Payment)
	}
}

func TestNeedsSealAndSecret(t *testing.T) {
	cfg := obsdk.Config{Env: obsdk.Sandbox, HTTPClient: http.DefaultClient,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "s", RedirectURL: "https://app.example/cb"}}
	var ce *obsdk.ConfigError
	if _, err := obsdk.New(obsdk.Target{Bank: "spuerkeess", Country: "LU"}, cfg); !errors.As(err, &ce) {
		t.Errorf("a client without a seal: err = %v, want a ConfigError", err)
	}
	cfg.Seal, cfg.Credentials.ClientSecret = testSeal(t), ""
	if _, err := obsdk.New(obsdk.Target{Bank: "spuerkeess", Country: "LU"}, cfg); !errors.As(err, &ce) {
		t.Errorf("a client without a secret: err = %v, want a ConfigError", err)
	}
}
