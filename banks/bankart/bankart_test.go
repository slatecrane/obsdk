package bankart

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
	"github.com/slatecrane/obsdk/internal/flowstate"
	"github.com/slatecrane/obsdk/obsdktest"
)

var frozen = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

const testIBAN = "SI56051001001033999"

// jwt is an unsigned token with the given sub, shaped like Bankart's.
func jwt(sub string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(map[string]any{"sub": sub, "scope": "psd2:acc"}) + ".c2ln"
}

func TestTokenAccount(t *testing.T) {
	for tok, want := range map[string]string{
		jwt(testIBAN):                  testIBAN,
		jwt("si56 0510 0100 1033 999"): testIBAN,
		jwt("user-1"):                  "",
		"opaque-token":                 "",
	} {
		if got, err := tokenAccount(tok); err != nil || got != want {
			t.Errorf("tokenAccount(%q) = %q, %v; want %q", tok, got, err, want)
		}
	}
	if _, err := tokenAccount("a.!!!.c"); err == nil {
		t.Error("unreadable payload: want an error")
	}
}

func TestURLs(t *testing.T) {
	b := banks[0]
	for _, c := range []struct{ got, want string }{
		{b.baseURL(obsdk.Sandbox, obsdk.Target{}, ""), "https://api.bankart.si/psd2/nlb/sandbox"},
		{b.baseURL(obsdk.Production, obsdk.Target{}, ""), "https://api.bankart.si/psd2/nlb"},
		{b.oauthURL(obsdk.Sandbox, obsdk.Target{}, ""), "https://api.bankart.si/psd2/nlb/sandbox/oauth2"},
		{b.oauthURL(obsdk.Production, obsdk.Target{}, ""), "https://api-oauth.bankart.si/psd2/nlb/oauth"},
	} {
		if c.got != c.want {
			t.Errorf("got %s, want %s", c.got, c.want)
		}
	}
}

// fakeBank is a minimal Bankart bank: the OAuth login, consents, accounts
// and payments, checking what replays cannot (headers, where the token goes,
// the payment root).
type fakeBank struct {
	t     *testing.T
	mu    sync.Mutex
	srv   *httptest.Server
	calls []string
}

func (h *fakeBank) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if r.Header.Get("X-IBM-Client-Id") != "app-1" {
		t.Errorf("%s %s: X-IBM-Client-Id %q", r.Method, r.URL.Path, r.Header.Get("X-IBM-Client-Id"))
	}
	if r.URL.Path == "/psd2/nlb/sandbox/oauth2/token" {
		f, _ := url.ParseQuery(string(body))
		if f.Get("grant_type") != "authorization_code" || f.Get("client_id") != "app-1" || f.Get("client_secret") != "secret-1" ||
			f.Get("code") != "the-code" || f.Get("redirect_uri") != "https://app.example/cb" {
			t.Errorf("token request %v", f)
		}
		reply(200, map[string]any{"access_token": jwt(testIBAN), "token_type": "Bearer", "expires_in": 300})
		return
	}
	// Only the creating requests carry the token.
	creating := r.Method == http.MethodPost
	if got := r.Header.Get("Authorization"); (got != "") != creating || creating && got != "Bearer "+jwt(testIBAN) {
		t.Errorf("%s %s: Authorization %q", r.Method, r.URL.Path, got)
	}
	if got := r.Header.Get("Initialized-By-PSU"); got != "true" && got != "false" {
		t.Errorf("%s %s: Initialized-By-PSU %q", r.Method, r.URL.Path, got)
	}
	const cons, pay = "/psd2/nlb/sandbox/v1/consents/c-1", "/psd2/nlb/sandbox/pay/v1/payments/sepa-credit-transfers/p-1"
	switch r.Method + " " + r.URL.Path {
	case "POST /psd2/nlb/sandbox/v1/consents":
		var b struct {
			Access map[string][]map[string]string `json:"access"`
		}
		_ = json.Unmarshal(body, &b)
		if len(b.Access["accounts"]) != 1 || b.Access["accounts"][0]["iban"] != testIBAN || len(b.Access["transactions"]) != 1 {
			t.Errorf("consent body %s", body)
		}
		if r.Header.Get("Initialized-By-PSU") != "true" {
			t.Error("consent: Initialized-By-PSU is not true")
		}
		reply(201, map[string]any{"consentStatus": "received", "consentId": "c-1", "_links": map[string]any{
			"scaRedirect": map[string]string{"href": "https://bank.example/sca"},
			"status":      map[string]string{"href": "https://api.bankart.si/psd2/nlb/sandbox/v1/consents/c-1/status"},
			"scaStatus":   map[string]string{"href": "/v1/consents/c-1/authorisations/a-1"}}})
	case "GET " + cons + "/authorisations/a-1":
		reply(200, map[string]any{}) // as the sandbox: no scaStatus, the consent status decides
	case "GET " + cons + "/status":
		reply(200, map[string]string{"consentStatus": "valid"})
	case "GET " + cons:
		reply(200, map[string]any{"validUntil": "2027-04-18", "consentStatus": "valid"})
	case "GET /psd2/nlb/sandbox/v1/accounts":
		if r.Header.Get("Consent-ID") != "c-1" {
			t.Errorf("Consent-ID %q", r.Header.Get("Consent-ID"))
		}
		reply(200, map[string]any{"accounts": []map[string]any{{"resourceId": "a-1", "iban": testIBAN, "currency": "EUR"}}})
	case "POST /psd2/nlb/sandbox/pay/v1/payments/sepa-credit-transfers":
		var b struct {
			DebtorAccount map[string]string `json:"debtorAccount"`
		}
		_ = json.Unmarshal(body, &b)
		if b.DebtorAccount["iban"] != testIBAN {
			t.Errorf("payment body %s: want the login's account as debtor", body)
		}
		reply(201, map[string]any{"transactionStatus": "RCVD", "paymentId": "p-1", "_links": map[string]any{
			"scaRedirect": map[string]string{"href": "https://bank.example/sca"},
			"status":      map[string]string{"href": "https://api.bankart.si/psd2/nlb/sandbox/pay/v1/payments/sepa-credit-transfers/p-1/status"}}})
	case "GET " + pay + "/status":
		reply(200, map[string]string{"transactionStatus": "ACSC"})
	default:
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		reply(404, map[string]any{"httpCode": "404", "httpMessage": "Not Found", "moreInformation": "No resources match requested URI"})
	}
}

func newFake(t *testing.T) (*fakeBank, obsdk.Client) {
	t.Helper()
	h := &fakeBank{t: t}
	h.srv = httptest.NewServer(h)
	t.Cleanup(h.srv.Close)
	reg := obsdk.NewRegistry()
	reg.Register(berlingroup.Integration(Profiles[0]))
	n := 0
	c, err := reg.New(obsdk.Target{Bank: NLBBank, Country: "SI"}, obsdk.Config{Env: obsdk.Sandbox, HTTPClient: h.srv.Client(),
		Credentials: obsdk.Credentials{ClientID: "app-1", ClientSecret: "secret-1", RedirectURL: "https://app.example/cb"},
		Extra:       map[string]string{"base_url": h.srv.URL + "/psd2/nlb/sandbox", "oauth_url": h.srv.URL + "/psd2/nlb/sandbox/oauth2"},
		Now:         func() time.Time { return frozen },
		NewID:       func(string) string { n++; return "id-" + string(rune('a'+n%26)) }})
	if err != nil {
		t.Fatal(err)
	}
	return h, c
}

// login checks the login redirect and returns its callback.
func login(t *testing.T, st *obsdk.Step, scope, iban string) string {
	t.Helper()
	if st.Kind != obsdk.StepRedirect || st.Redirect == nil {
		t.Fatalf("step %+v, want the login redirect", st)
	}
	u, err := url.Parse(st.Redirect.URL)
	if err != nil || !strings.HasSuffix(u.Path, "/psd2/nlb/sandbox/oauth2/authorize") {
		t.Fatalf("login URL %q", st.Redirect.URL)
	}
	q := u.Query()
	if q.Get("scope") != scope || q.Get("client_id") != "app-1" || q.Get("response_type") != "code" || q.Get("iban") != iban {
		t.Errorf("authorize query %v", q)
	}
	return "https://app.example/cb?code=the-code&state=" + url.QueryEscape(q.Get("state"))
}

// noToken fails when a step's state or session holds the access token.
func noToken(t *testing.T, st *obsdk.Step) {
	t.Helper()
	var f map[string]any
	if err := flowstate.Decode(st.State, &f); err == nil && (f["create_token"] != nil || f["session"] != nil) {
		t.Errorf("flow state keeps the token: %v", f)
	}
	if st.Session != nil && st.Session.AccessToken != "" {
		t.Errorf("step session has the token")
	}
}

func TestConnect(t *testing.T) {
	h, c := newFake(t)
	ctx := context.Background()
	st, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: login(t, st, "psd2:acc", "")})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect.URL != "https://bank.example/sca" {
		t.Fatalf("step %+v, want the consent approval", st)
	}
	noToken(t, st)
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	s := st.Session
	if st.Kind != obsdk.StepDone || s == nil || s.AccessToken != "" || s.Consents["ais"].ID != "c-1" || len(st.Accounts) != 1 {
		t.Fatalf("done step %+v, session %+v", st, s)
	}
	if _, err := c.Refresh(ctx, s); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	want := []string{"POST /psd2/nlb/sandbox/oauth2/token", "POST /psd2/nlb/sandbox/v1/consents",
		"GET /psd2/nlb/sandbox/v1/consents/c-1/authorisations/a-1", "GET /psd2/nlb/sandbox/v1/consents/c-1/status",
		"GET /psd2/nlb/sandbox/v1/consents/c-1", "GET /psd2/nlb/sandbox/v1/accounts",
		"GET /psd2/nlb/sandbox/v1/consents/c-1/status"}
	if strings.Join(h.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(h.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestConnectNamedAccount(t *testing.T) {
	_, c := newFake(t)
	ctx := context.Background()
	st, err := c.Connect(ctx, obsdk.ConnectRequest{Values: map[string]string{"iban": "SI57 0510 0100 1044 999"}})
	if err != nil {
		t.Fatal(err)
	}
	// The user picked another account at the login than the one named.
	_, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: login(t, st, "psd2:acc", "SI57051001001044999")})
	if !errors.Is(err, obsdk.ErrInvalidRequest) || !strings.Contains(err.Error(), testIBAN) {
		t.Errorf("err = %v, want the mismatch", err)
	}
}

func TestPayment(t *testing.T) {
	h, c := newFake(t)
	ctx := context.Background()
	st, err := c.InitiatePayment(ctx, obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, PSU: obsdk.PSUContext{IP: "203.0.113.7"},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "12.34", Currency: "EUR"}, Remittance: []string{"Invoice 7"},
			Creditor: obsdk.Creditor{Name: "Janez Novak", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "SI56610000018109471"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: login(t, st, "psd2:pay", "")})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Payment == nil || st.Payment.ID != "p-1" {
		t.Fatalf("approval step %+v", st)
	}
	noToken(t, st)
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepDone || st.Payment.Status != obsdk.PaymentCompleted {
		t.Fatalf("done step %+v", st)
	}
	// Reading the payment needs no session.
	res, err := c.PaymentStatus(ctx, st.Payment.Ref, obsdk.PaymentCallOptions{})
	if err != nil || res.Data.Status != obsdk.PaymentCompleted {
		t.Errorf("status: %+v, %v", res, err)
	}
	if h.calls[1] != "POST /psd2/nlb/sandbox/pay/v1/payments/sepa-credit-transfers" {
		t.Errorf("calls %v", h.calls)
	}
}

func TestGatewayError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"httpCode":"401","httpMessage":"Unauthorized","moreInformation":"Invalid client id or secret."}`)
	}))
	defer srv.Close()
	reg := obsdk.NewRegistry()
	reg.Register(berlingroup.Integration(Profiles[0]))
	c, err := reg.New(obsdk.Target{Bank: NLBBank, Country: "SI"}, obsdk.Config{Env: obsdk.Sandbox, HTTPClient: srv.Client(),
		Credentials: obsdk.Credentials{ClientID: "wrong", RedirectURL: "https://app.example/cb"}, Extra: map[string]string{"base_url": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	s := &obsdk.Session{Bank: NLBBank, Country: "SI", Env: obsdk.Sandbox, Integration: Profiles[0].ID,
		Consents: map[string]obsdk.Consent{"ais": {ID: "c-1", Kind: "ais"}}}
	_, err = c.Accounts(context.Background(), s, obsdk.CallOptions{})
	var ae *obsdk.APIError
	if !errors.As(err, &ae) || !strings.Contains(ae.Text, "Invalid client id") {
		t.Errorf("err = %v", err)
	}
}

// TestScenarios replays the reads recorded against the static sandbox (with
// the consent id its FAQ documents; see docs/bankart.md).
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }
