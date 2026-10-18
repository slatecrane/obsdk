package berlingroup

import (
	"context"
	"errors"
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

// oauthBank is a fake hub bank with the OAuth SCA approach: banks live under
// /xs2a/<bank code>/v1, the scaOAuth link points to RFC 8414 metadata, and
// account calls need the bearer token.
type oauthBank struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	challenge string // code_challenge seen on the authorisation URL (set by the test)
	token     string // access token account calls must carry
	refreshed int
}

func newOAuthBank(t *testing.T) *oauthBank {
	b := &oauthBank{t: t, token: "AT1"}
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
	mux.HandleFunc("POST /xs2a/12345678/v1/consents", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("TPP-Redirect-Preferred") != "true" || r.Header.Get("TPP-Redirect-URI") != "https://app.example/cb" {
			t.Errorf("consent request headers: %v", r.Header)
		}
		write(w, 201, `{"consentStatus":"received","consentId":"c1","_links":{
			"scaOAuth":{"href":"`+b.srv.URL+`/.well-known/oauth-authorization-server"},
			"scaStatus":{"href":"`+b.srv.URL+`/xs2a/12345678/v1/consents/c1/authorisations/a1"}}}`)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, `{"issuer":"x","authorization_endpoint":"`+b.srv.URL+`/authorize?inst=12345678","token_endpoint":"`+b.srv.URL+`/token"}`)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f := r.PostForm
		b.mu.Lock()
		defer b.mu.Unlock()
		if f.Get("client_id") != "PSDDE-TEST-1" {
			t.Errorf("token request client_id = %q", f.Get("client_id"))
		}
		switch f.Get("grant_type") {
		case "authorization_code":
			if f.Get("code") != "CODE" || pkceChallenge(f.Get("code_verifier")) != b.challenge || f.Get("redirect_uri") != "https://app.example/cb" {
				write(w, 400, `{"error":"invalid_grant"}`)
				return
			}
			write(w, 200, `{"access_token":"AT1","token_type":"Bearer","expires_in":"3600","refresh_token":"RT1"}`)
		case "refresh_token":
			if f.Get("refresh_token") != "RT1" {
				write(w, 400, `{"error":"invalid_grant","error_description":"expired"}`)
				return
			}
			b.refreshed++
			b.token = "AT2"
			write(w, 200, `{"access_token":"AT2","token_type":"Bearer","expires_in":3600}`)
		default:
			t.Errorf("grant_type %q", f.Get("grant_type"))
		}
	})
	mux.HandleFunc("GET /xs2a/12345678/v1/consents/c1/authorisations/a1", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, `{"scaStatus":"finalised"}`)
	})
	mux.HandleFunc("GET /xs2a/12345678/v1/consents/c1/status", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, `{"consentStatus":"valid"}`)
	})
	mux.HandleFunc("GET /xs2a/12345678/v1/consents/c1", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, `{"consentStatus":"valid","validUntil":"2027-01-16"}`)
	})
	mux.HandleFunc("GET /xs2a/12345678/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		want := "Bearer " + b.token
		b.mu.Unlock()
		if r.Header.Get("Authorization") != want || r.Header.Get("Consent-ID") != "c1" {
			write(w, 401, `{"tppMessages":[{"category":"ERROR","code":"TOKEN_INVALID"}]}`)
			return
		}
		write(w, 200, `{"accounts":[{"resourceId":"acc1","iban":"DE86999999990000001000","currency":"EUR","ownerName":"Erika Mustermann"}]}`)
	})
	b.srv = httptest.NewServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

func (b *oauthBank) profile() Profile {
	return Profile{
		ID: "hub-bg", Info: obsdk.Info{Bank: "hub", Name: "Hub Bank", Capabilities: []obsdk.Capability{obsdk.CapAccounts}},
		BaseURL: func(_ obsdk.Env, _ obsdk.Target, inst string) string {
			if inst == "" {
				return ""
			}
			return b.srv.URL + "/xs2a/" + inst
		},
		Institution: &Institution{Param: "bank_code", Normalize: func(s string) (string, error) {
			if len(s) != 8 {
				return "", errors.New("eight digits")
			}
			return s, nil
		}},
		Consent: ConsentBankOffered,
	}
}

func (b *oauthBank) client(t *testing.T, extra map[string]string) obsdk.Client {
	t.Helper()
	ids := 0
	cfg := obsdk.Config{Env: obsdk.Sandbox, Extra: extra, HTTPClient: b.srv.Client(),
		Credentials: obsdk.Credentials{ClientID: "PSDDE-TEST-1", RedirectURL: "https://app.example/cb"},
		Now:         func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) },
		NewID:       func(p string) string { ids++; return fmt.Sprintf("%s-%d", p, ids) }}
	c, err := Integration(b.profile()).Factory(cfg, obsdk.Target{Bank: "hub", Country: "DE"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOAuthConnectAndRefresh(t *testing.T) {
	b := newOAuthBank(t)
	ctx := context.Background()
	c := b.client(t, map[string]string{"bank_code": "12345678"})

	st, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect == nil {
		t.Fatalf("want a redirect step, got %+v", st)
	}
	u, _ := url.Parse(st.Redirect.URL)
	q := u.Query()
	for k, want := range map[string]string{"response_type": "code", "client_id": "PSDDE-TEST-1", "scope": "AIS:c1",
		"code_challenge_method": "S256", "redirect_uri": "https://app.example/cb", "inst": "12345678"} {
		if q.Get(k) != want {
			t.Errorf("authorisation URL %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if u.Path != "/authorize" || q.Get("state") == "" || len(q.Get("code_challenge")) != 43 {
		t.Errorf("authorisation URL %s", st.Redirect.URL)
	}
	b.challenge = q.Get("code_challenge")

	if _, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb?code=CODE&state=forged"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Errorf("a callback with another state: err = %v, want ErrAuthFailed", err)
	}

	// The resumed flow carries the bank code: a client without one finishes it.
	done, err := b.client(t, nil).Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb?code=CODE&state=" + q.Get("state")})
	if err != nil {
		t.Fatal(err)
	}
	s := done.Session
	if done.Kind != obsdk.StepDone || s == nil || len(done.Accounts) != 1 {
		t.Fatalf("done step: %+v", done)
	}
	if s.AccessToken != "AT1" || s.RefreshToken != "RT1" || s.AccessExpiresAt == nil ||
		!s.AccessExpiresAt.Equal(time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)) {
		t.Errorf("tokens: %q %q %v", s.AccessToken, s.RefreshToken, s.AccessExpiresAt)
	}
	if s.Meta[metaInstitution] != "12345678" || s.Meta[metaTokenURL] != b.srv.URL+"/token" {
		t.Errorf("session meta: %v", s.Meta)
	}

	// Any client reaches the session's bank; one configured for another bank refuses.
	if _, err := b.client(t, nil).Accounts(ctx, s, obsdk.CallOptions{}); err != nil {
		t.Errorf("accounts with the session's bank code: %v", err)
	}
	if _, err := b.client(t, map[string]string{"bank_code": "87654321"}).Accounts(ctx, s, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("accounts with a client for another bank: err = %v, want ErrInvalidRequest", err)
	}

	ns, err := c.Refresh(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if ns.AccessToken != "AT2" || ns.RefreshToken != "RT1" || b.refreshed != 1 || ns.Generation <= s.Generation {
		t.Errorf("refreshed session: %q %q, refreshes %d, generation %d -> %d", ns.AccessToken, ns.RefreshToken, b.refreshed, s.Generation, ns.Generation)
	}
	if _, err := c.Accounts(ctx, ns, obsdk.CallOptions{}); err != nil {
		t.Errorf("accounts with the refreshed token: %v", err)
	}

	bad := ns.Clone()
	bad.RefreshToken = "RT-old"
	var re *obsdk.ReauthError
	if _, err := c.Refresh(ctx, bad); !errors.As(err, &re) {
		t.Errorf("refresh with a rejected refresh token: err = %v, want a ReauthError", err)
	}
}

func TestInstitutionRequired(t *testing.T) {
	b := newOAuthBank(t)
	var ce *obsdk.ConfigError
	if _, err := b.client(t, nil).Connect(context.Background(), obsdk.ConnectRequest{}); !errors.As(err, &ce) || !strings.Contains(ce.Error(), "bank_code") {
		t.Errorf("connect without a bank code: err = %v, want a ConfigError naming bank_code", err)
	}
	_, err := Integration(b.profile()).Factory(obsdk.Config{Env: obsdk.Sandbox, Extra: map[string]string{"bank_code": "123"}},
		obsdk.Target{Bank: "hub", Country: "DE"})
	if !errors.As(err, &ce) {
		t.Errorf("an invalid bank code: err = %v, want a ConfigError", err)
	}
}

func TestPaymentRefKeepsInstitution(t *testing.T) {
	b := newOAuthBank(t)
	c := b.client(t, map[string]string{"bank_code": "12345678"}).(*client)
	pay, err := c.paymentOf(&payState{Type: obsdk.PaymentSEPA, Product: "sepa-credit-transfers", ID: "p1"}, "ACSC", nil)
	if err != nil {
		t.Fatal(err)
	}
	cc, p, err := b.client(t, nil).(*client).decodeRef(pay.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if cc.base != b.srv.URL+"/xs2a/12345678" || p.ID != "p1" {
		t.Errorf("decodeRef: base %q, payment %+v", cc.base, p)
	}
}
