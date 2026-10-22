package berlingroup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// TestOAuthServer runs a consent and a payment against a fake bank that puts
// OAuth around every resource (Profile.OAuth, as LUXHUB): client-credentials
// tokens to create and read, a fixed authorisation endpoint, and the code
// exchanged with its scope for the account calls' token.
func TestOAuthServer(t *testing.T) {
	var mu sync.Mutex
	var challenge string
	grants := map[string]int{}
	write := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
	needs := func(w http.ResponseWriter, r *http.Request, auth string) bool {
		if got := r.Header.Get("Authorization"); got != auth {
			t.Errorf("%s %s: Authorization %q, want %q", r.Method, r.URL.Path, got, auth)
			write(w, 401, `{"tppMessages":[{"category":"ERROR","code":"TOKEN_INVALID"}]}`)
			return false
		}
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f := r.PostForm
		if id, secret, ok := r.BasicAuth(); !ok || id != "cid" || secret != "secret" {
			t.Errorf("token request without the client's Basic credentials")
		}
		mu.Lock()
		defer mu.Unlock()
		grants[f.Get("grant_type")+" "+f.Get("scope")]++
		switch f.Get("grant_type") {
		case "client_credentials":
			write(w, 200, `{"access_token":"CC-`+f.Get("scope")+`","token_type":"Bearer","expires_in":300}`)
		case "authorization_code":
			if f.Get("code") != "CODE" || f.Get("scope") != "AIS:c1" || pkceChallenge(f.Get("code_verifier")) != challenge {
				write(w, 400, `{"error":"invalid_grant"}`)
				return
			}
			write(w, 200, `{"access_token":"USER","token_type":"Bearer","expires_in":3600,"refresh_token":"RT"}`)
		default:
			t.Errorf("grant_type %q", f.Get("grant_type"))
		}
	})
	mux.HandleFunc("POST /bg/v1/consents", func(w http.ResponseWriter, r *http.Request) {
		if needs(w, r, "Bearer CC-AIS") {
			write(w, 201, `{"consentStatus":"received","consentId":"c1","_links":{"self":{"href":"/bg/v1/consents/c1"}}}`)
		}
	})
	for _, p := range []string{"GET /bg/v1/consents/c1/status", "GET /bg/v1/consents/c1"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if needs(w, r, "Bearer CC-AIS") {
				write(w, 200, `{"consentStatus":"valid","validUntil":"2027-01-16"}`)
			}
		})
	}
	mux.HandleFunc("GET /bg/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		if needs(w, r, "Bearer USER") {
			write(w, 200, `{"accounts":[{"resourceId":"a1","iban":"LU280019400644750000","currency":"EUR"}]}`)
		}
	})
	mux.HandleFunc("POST /bg/v1/payments/sepa-credit-transfers", func(w http.ResponseWriter, r *http.Request) {
		if needs(w, r, "Bearer CC-PIS:payment") {
			write(w, 201, `{"transactionStatus":"RCVD","paymentId":"p1","_links":{"self":{"href":"/bg/v1/payments/sepa-credit-transfers/p1"}}}`)
		}
	})
	mux.HandleFunc("GET /bg/v1/payments/sepa-credit-transfers/p1/status", func(w http.ResponseWriter, r *http.Request) {
		if needs(w, r, "Bearer CC-PIS:payment") {
			write(w, 200, `{"transactionStatus":"ACSC"}`)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := Profile{
		ID: "oauthsrv-bg", Info: obsdk.Info{Bank: "oauthsrv", Name: "OAuth Bank",
			Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapPayments},
			Payments:     []obsdk.PaymentSpec{CreditTransferSpec(obsdk.PaymentSEPA, SpecOptions{})}},
		BaseURL:    func(obsdk.Env, obsdk.Target, string) string { return srv.URL + "/bg" },
		Approaches: []string{Redirect},
		Products:   map[obsdk.PaymentType]string{obsdk.PaymentSEPA: "sepa-credit-transfers"},
		OAuth: &OAuthServer{
			Authorize:         func(obsdk.Env, obsdk.Target, string) string { return "https://cb.bank.example/api/oauth/authorize" },
			Token:             func(obsdk.Env, obsdk.Target, string) string { return srv.URL + "/api/oauth/token" },
			ClientCredentials: true, PISScope: "PIS:payment", ExchangeScope: true,
		},
		OAuthClientAuth: func(cfg obsdk.Config, _ string, _ url.Values, h http.Header) error {
			r := &http.Request{Header: h}
			r.SetBasicAuth(cfg.Credentials.ClientID, cfg.Credentials.ClientSecret.Reveal())
			return nil
		},
	}
	ids := 0
	c, err := Integration(p).Factory(obsdk.Config{Env: obsdk.Sandbox, HTTPClient: srv.Client(),
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "secret", RedirectURL: "https://app.example/cb"},
		Now:         func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
		NewID:       func(p string) string { ids++; return fmt.Sprintf("%s-%d", p, ids) }}, obsdk.Target{Bank: "oauthsrv", Country: "LU"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	st, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || !strings.HasPrefix(st.Redirect.URL, "https://cb.bank.example/api/oauth/authorize?") {
		t.Fatalf("want a redirect to the fixed authorisation endpoint, got %+v", st)
	}
	q := mustQuery(t, st.Redirect.URL)
	if q.Get("scope") != "AIS:c1" || q.Get("client_id") != "cid" || q.Get("redirect_uri") != "https://app.example/cb" {
		t.Errorf("authorisation URL %s", st.Redirect.URL)
	}
	challenge = q.Get("code_challenge")
	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb?code=CODE&state=" + q.Get("state")})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Session.AccessToken != "USER" || done.Session.RefreshToken != "RT" || len(done.Accounts) != 1 {
		t.Fatalf("done step: %+v", done)
	}

	st, err = c.InitiatePayment(ctx, obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, PSU: obsdk.PSUContext{IP: "203.0.113.7"},
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "LU120010001234567891"}},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "1.00", Currency: "EUR"},
			Creditor: obsdk.Creditor{Name: "Payee", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "LU280019400644750000"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	q = mustQuery(t, st.Redirect.URL)
	if st.Kind != obsdk.StepRedirect || q.Get("scope") != "PIS:p1" {
		t.Fatalf("payment redirect: %+v", st)
	}
	done, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb?code=PAYCODE&state=" + q.Get("state")})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Payment == nil || done.Payment.Status != obsdk.PaymentCompleted {
		t.Fatalf("payment done step: %+v", done)
	}
	mu.Lock()
	defer mu.Unlock()
	if grants["authorization_code PIS:p1"] != 0 || grants["client_credentials AIS"] == 0 || grants["client_credentials PIS:payment"] == 0 {
		t.Errorf("token requests: %v", grants)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}
