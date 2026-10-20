package redsys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	"github.com/slatecrane/obsdk/internal/berlingroup"
	"github.com/slatecrane/obsdk/obsdktest"
)

func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

var frozen = time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

func TestASPSPCode(t *testing.T) {
	for in, want := range map[string]string{"bbva": "BBVA", " CaixaBank ": "caixabank", "bancsabadell": "BancSabadell",
		"newbank2": "newbank2"} {
		if got, err := ASPSPCode(in); err != nil || got != want {
			t.Errorf("ASPSPCode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "x", "BBVA/v1", "caixa bank"} {
		if _, err := ASPSPCode(in); err == nil {
			t.Errorf("ASPSPCode(%q): want an error", in)
		}
	}
}

// testSeal is an RSA seal whose certificate carries an organizationIdentifier.
func testSeal(t *testing.T, orgID string) *obsdk.Seal {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0x5d803f65), NotBefore: frozen.Add(-time.Hour), NotAfter: frozen.Add(time.Hour),
		Subject: pkix.Name{CommonName: "obsdk test TPP", Country: []string{"ES"},
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: orgID}}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &obsdk.Seal{Key: key, Certificate: cert}
}

func TestClientID(t *testing.T) {
	seal := testSeal(t, "PSDES-BDE-3DFD21")
	if got := clientID(obsdk.Config{Seal: seal}); got != "PSDES-BDE-3DFD21" {
		t.Errorf("from the seal: %q", got)
	}
	if got := clientID(obsdk.Config{Seal: seal, Credentials: obsdk.Credentials{ClientID: "PSDES-BDE-OTHER"}}); got != "PSDES-BDE-OTHER" {
		t.Errorf("configured: %q", got)
	}
}

// fakeHub is a minimal Redsys hub: OAuth pre-step, consents, accounts and
// payments for one bank, checking what replays cannot (headers, the form of
// the token request, path versions).
type fakeHub struct {
	t        *testing.T
	mu       sync.Mutex
	srv      *httptest.Server
	verifier string // the PKCE verifier the token request carried
	calls    []string
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.t
	h.calls = append(h.calls, r.Method+" "+r.URL.Path)
	body, _ := io.ReadAll(r.Body)
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if r.URL.Path == "/oauth/BBVA/token" {
		f, _ := url.ParseQuery(string(body))
		switch f.Get("grant_type") {
		case "authorization_code":
			if f.Get("client_id") != "PSDES-BDE-3DFD21" || f.Get("code") != "the-code" || f.Get("redirect_uri") != "https://app.example/cb" {
				t.Errorf("token request %v", f)
			}
			h.verifier = f.Get("code_verifier")
			reply(200, map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 300, "refresh_token": "rt-1"})
		case "refresh_token":
			if f.Get("refresh_token") != "rt-1" || f.Get("client_id") != "PSDES-BDE-3DFD21" {
				t.Errorf("refresh request %v", f)
			}
			reply(200, map[string]any{"access_token": "at-2", "token_type": "Bearer", "expires_in": 300})
		default:
			t.Errorf("token grant %q", f.Get("grant_type"))
		}
		return
	}
	// Every XS2A request: signed, with the bearer token.
	if a := r.Header.Get("Authorization"); a != "Bearer at-1" && a != "Bearer at-2" {
		t.Errorf("%s %s: Authorization %q", r.Method, r.URL.Path, a)
	}
	for _, k := range []string{"Digest", "Signature", "TPP-Signature-Certificate", "X-Request-ID"} {
		if r.Header.Get(k) == "" {
			t.Errorf("%s %s: no %s", r.Method, r.URL.Path, k)
		}
	}
	if !strings.Contains(r.Header.Get("Signature"), `headers="digest x-request-id`) {
		t.Errorf("Signature %q", r.Header.Get("Signature"))
	}
	if r.Header.Get("TPP-Nok-Redirect-URI") != "" {
		t.Error("TPP-Nok-Redirect-URI sent (the hub allows 50 characters)")
	}
	const cons, pay = "/api/BBVA/v1/consents/c-1", "/api/BBVA/v1/payments/sepa-credit-transfers/p-1"
	switch r.Method + " " + r.URL.Path {
	case "POST /api/BBVA/v1.1/consents":
		if r.Header.Get("TPP-Redirect-URI") != "https://app.example/cb" {
			t.Errorf("TPP-Redirect-URI %q", r.Header.Get("TPP-Redirect-URI"))
		}
		reply(201, map[string]any{"consentStatus": "received", "consentId": "c-1", "_links": map[string]any{
			"scaRedirect": map[string]string{"href": "https://bank.example/sca"}, "status": map[string]string{"href": "/v1/consents/c-1/status"}}})
	case "GET " + cons + "/status":
		reply(200, map[string]string{"consentStatus": "valid"})
	case "GET " + cons:
		reply(200, map[string]any{"validUntil": "2027-04-17", "consentStatus": "valid"})
	case "GET /api/BBVA/v1/accounts":
		if r.Header.Get("Consent-ID") != "c-1" {
			t.Errorf("Consent-ID %q", r.Header.Get("Consent-ID"))
		}
		reply(200, map[string]any{"accounts": []map[string]any{{"resourceId": "a-1", "iban": "ES2501822200160201933547", "currency": "EUR"}}})
	case "POST /api/BBVA/v1.1/payments/sepa-credit-transfers":
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		if _, ok := b["endToEndIdentification"]; ok {
			t.Errorf("payment body has endToEndIdentification: %s", body)
		}
		reply(201, map[string]any{"transactionStatus": "RCVD", "paymentId": "p-1", "_links": map[string]any{
			"scaRedirect": map[string]string{"href": "https://bank.example/sca"}}})
	case "GET " + pay + "/status":
		reply(200, map[string]string{"transactionStatus": "ACSC"})
	default:
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		reply(404, map[string]any{})
	}
}

func newFake(t *testing.T) (*fakeHub, obsdk.Client) {
	t.Helper()
	h := &fakeHub{t: t}
	h.srv = httptest.NewServer(h)
	t.Cleanup(h.srv.Close)
	reg := obsdk.NewRegistry()
	reg.Register(berlingroup.Integration(Profile))
	n := 0
	cfg := obsdk.Config{Env: obsdk.Sandbox, HTTPClient: h.srv.Client(), Seal: testSeal(t, "PSDES-BDE-3DFD21"),
		Credentials: obsdk.Credentials{RedirectURL: "https://app.example/cb"},
		Extra:       map[string]string{ParamASPSP: "bbva", "base_url": h.srv.URL + "/api/BBVA", "oauth_url": h.srv.URL + "/oauth/BBVA"},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { n++; return p + "-" + string(rune('a'+n)) }}
	c, err := reg.New(obsdk.Target{Bank: Bank, Country: "ES"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h, c
}

// login follows a pre-step redirect: checks the authorisation request and
// returns the callback the hub would send.
func login(t *testing.T, h *fakeHub, st *obsdk.Step, scope string) string {
	t.Helper()
	if st.Kind != obsdk.StepRedirect || st.Redirect == nil {
		t.Fatalf("step %+v, want the login redirect", st)
	}
	u, err := url.Parse(st.Redirect.URL)
	if err != nil || u.Path != "/oauth/BBVA/authorize" {
		t.Fatalf("login URL %q", st.Redirect.URL)
	}
	q := u.Query()
	if q.Get("client_id") != "PSDES-BDE-3DFD21" || q.Get("scope") != scope || q.Get("response_type") != "code" ||
		q.Get("redirect_uri") != "https://app.example/cb" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("authorize query %v", q)
	}
	t.Cleanup(func() {
		sum := sha256.Sum256([]byte(h.verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
			t.Error("code_verifier does not match code_challenge")
		}
	})
	return "https://app.example/cb?code=the-code&state=" + url.QueryEscape(q.Get("state"))
}

func TestConnectWithPreStep(t *testing.T) {
	h, c := newFake(t)
	ctx := context.Background()
	st, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Session != nil {
		t.Error("session before the login")
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: login(t, h, st, "AIS")})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect.URL != "https://bank.example/sca" {
		t.Fatalf("step %+v, want the consent approval", st)
	}
	if st.Session == nil || st.Session.AccessToken != "at-1" {
		t.Fatalf("approval step session %+v, want the token", st.Session)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	s := st.Session
	if st.Kind != obsdk.StepDone || s == nil || s.AccessToken != "at-1" || s.RefreshToken != "rt-1" || s.Consents["ais"].ID != "c-1" ||
		len(st.Accounts) != 1 {
		t.Fatalf("done step %+v, session %+v", st, s)
	}

	// Refresh renews the token first, then checks the consent with it.
	ns, err := c.Refresh(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if ns.AccessToken != "at-2" || ns.RefreshToken != "rt-1" {
		t.Errorf("refreshed session %+v", ns)
	}
	want := []string{"POST /oauth/BBVA/token", "POST /api/BBVA/v1.1/consents", "GET /api/BBVA/v1/consents/c-1/status",
		"GET /api/BBVA/v1/consents/c-1", "GET /api/BBVA/v1/accounts", "POST /oauth/BBVA/token", "GET /api/BBVA/v1/consents/c-1/status"}
	if strings.Join(h.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(h.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestPaymentWithPreStep(t *testing.T) {
	h, c := newFake(t)
	ctx := context.Background()
	req := obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, PSU: obsdk.PSUContext{IP: "203.0.113.7"},
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "ES2501822200160201933547"}},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "12.34", Currency: "EUR"},
			Creditor: obsdk.Creditor{Name: "Lucía García", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "ES9121000418450200051332"}}}}}
	st, err := c.InitiatePayment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if st.Payment != nil {
		t.Errorf("payment %+v before it exists", st.Payment)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: login(t, h, st, "PIS")})
	if err != nil {
		t.Fatal(err)
	}
	if st.Session == nil || st.Payment == nil || st.Payment.ID != "p-1" {
		t.Fatalf("approval step %+v", st)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepDone || st.Session == nil || st.Payment.Status != obsdk.PaymentCompleted {
		t.Fatalf("done step %+v", st)
	}

	if _, err := c.PaymentStatus(ctx, st.Payment.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("status without a session: %v", err)
	}
	res, err := c.PaymentStatus(ctx, st.Payment.Ref, obsdk.PaymentCallOptions{Session: st.Session})
	if err != nil || res.Data.Status != obsdk.PaymentCompleted {
		t.Errorf("status: %+v, %v", res, err)
	}
	expired := st.Session.Clone()
	past := frozen.Add(-time.Minute)
	expired.AccessExpiresAt = &past
	if _, err := c.PaymentStatus(ctx, st.Payment.Ref, obsdk.PaymentCallOptions{Session: expired}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("status with an expired token: %v", err)
	}

	// The payment's session starts the next payment without a login.
	req.Session = st.Session
	st, err = c.InitiatePayment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect.URL != "https://bank.example/sca" {
		t.Errorf("second payment step %+v, want the approval without a login", st)
	}
	logins := 0
	for _, c := range h.calls {
		if c == "POST /oauth/BBVA/token" {
			logins++
		}
	}
	if logins != 1 {
		t.Errorf("%d code exchanges, want 1", logins)
	}
}
