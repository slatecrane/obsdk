package samlink

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
	"github.com/slatecrane/obsdk/obsdktest"
)

var frozen = time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

func TestClientAuthSandbox(t *testing.T) {
	cfg := obsdk.Config{Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "id", ClientSecret: "secret"},
		Extra: map[string]string{ParamSubscriptionKey: "sub"}, NewID: func(string) string { return "req-1" }}
	form, h := url.Values{"grant_type": {"authorization_code"}}, http.Header{}
	if err := clientAuth(cfg, "https://auth.example/token", form, h); err != nil {
		t.Fatal(err)
	}
	if got := h.Get("Authorization"); got != "Basic aWQ6c2VjcmV0" {
		t.Errorf("Authorization = %q", got)
	}
	if h.Get("Ocp-Apim-Subscription-Key") != "sub" || h.Get("X-Request-ID") != "req-1" || form.Has("client_assertion") {
		t.Errorf("headers %v, form %v", h, form)
	}
}

func TestClientAuthProduction(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := obsdk.Config{Env: obsdk.Production, Credentials: obsdk.Credentials{ClientID: "PSDFI-FINFSA-1234567-8"},
		Extra: map[string]string{ParamAPIKey: "api"}, Seal: &obsdk.Seal{Key: key},
		Now: func() time.Time { return frozen }, NewID: func(string) string { return "jti-1" }}
	form, h := url.Values{}, http.Header{}
	tokenURL := "https://authservice.samlink.fi/sp/oauthproxy/token"
	if err := clientAuth(cfg, tokenURL, form, h); err != nil {
		t.Fatal(err)
	}
	if h.Get("apikey") != "api" || h.Get("Authorization") != "" {
		t.Errorf("headers %v", h)
	}
	if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %q", form.Get("client_assertion_type"))
	}
	parts := strings.Split(form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		t.Fatalf("assertion %q", form.Get("client_assertion"))
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	var head map[string]any
	var claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &head)
	_ = json.Unmarshal(cb, &claims)
	if head["alg"] != "RS256" || len(head) != 2 {
		t.Errorf("header %v", head)
	}
	want := map[string]any{"iss": "PSDFI-FINFSA-1234567-8", "sub": "PSDFI-FINFSA-1234567-8", "aud": tokenURL, "jti": "jti-1",
		"iat": float64(frozen.Unix()), "exp": float64(frozen.Add(5 * time.Minute).Unix())}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, claims[k], v)
		}
	}

	cfg.Seal = nil
	if err := clientAuth(cfg, tokenURL, url.Values{}, http.Header{}); err == nil {
		t.Error("production without a seal: want an error")
	}
}

func TestHeaders(t *testing.T) {
	h := http.Header{}
	headers(obsdk.Config{Env: obsdk.Production, Extra: map[string]string{ParamAPIKey: "api", ParamSubscriptionKey: "sub"}}, h)
	if h.Get("apikey") != "api" || h.Get("Ocp-Apim-Subscription-Key") != "" {
		t.Errorf("production headers %v", h)
	}
	h = http.Header{}
	headers(obsdk.Config{Env: obsdk.Sandbox, Extra: map[string]string{ParamSubscriptionKey: "sub"}}, h)
	if h.Get("Ocp-Apim-Subscription-Key") != "sub" || h.Get("apikey") != "" {
		t.Errorf("sandbox headers %v", h)
	}
}

func TestPaymentSpec(t *testing.T) {
	spec, ok := Profiles[0].Info.PaymentSpec("FI", obsdk.Personal, obsdk.PaymentSEPA)
	if !ok {
		t.Fatal("no SEPA spec")
	}
	base := obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, Transfers: []obsdk.Transfer{{
		Amount:   obsdk.Money{Amount: "10.00", Currency: "EUR"},
		Creditor: obsdk.Creditor{Name: "Matti Meikäläinen", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI1445760010038426"}},
	}}}
	for ref, ok := range map[obsdk.Reference]bool{
		{Scheme: obsdk.ReferenceFI, Value: "1232"}:             true,
		{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}: true,
		{Scheme: obsdk.ReferenceFI, Value: "1233"}:             false,
		{Scheme: obsdk.ReferenceOCR, Value: "1234567897"}:      false,
	} {
		r := base
		r.Transfers = []obsdk.Transfer{base.Transfers[0]}
		ref := ref
		r.Transfers[0].Reference = &ref
		if err := spec.Validate(r, frozen); (err == nil) != ok {
			t.Errorf("reference %v: err = %v", ref, err)
		}
	}
	for _, f := range spec.Fields {
		if f.Path == obsdk.FieldEndToEndID {
			t.Error("the end-to-end id is offered, but the reference takes its place")
		}
	}
}

// Booked transactions are paged by entry reference: a date range goes with
// both ends, the next page names only entryReferenceFrom, and a page without
// a relevantEntryReference is the last. Pending ones go without dates. The
// sandbox books nothing, so this is from the documentation.
func TestTransactionsPaging(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("Ocp-Apim-Subscription-Key") != "sub" || r.Header.Get("Authorization") != "Bearer AT" || r.Header.Get("Consent-ID") != "c1" {
			t.Errorf("headers %v", r.Header)
		}
		q := r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case q.Get("bookingStatus") == "pending":
			fmt.Fprint(w, `{"account":{"iban":"FI3745760010038400"},"transactions":{"pending":[{"valueDate":"2026-10-19","transactionAmount":{"currency":"EUR","amount":"12.34"},"creditorName":"Payee","debtorAccount":{"iban":"FI3745760010038400"}}]}}`)
		case q.Get("entryReferenceFrom") == "":
			fmt.Fprint(w, `{"account":{"iban":"FI3745760010038400"},"relevantEntryReference":"000000000001016","transactions":{"booked":[{"entryReference":"000000000001017","bookingDate":"2026-10-05","transactionAmount":{"currency":"EUR","amount":"-50.00"},"creditorName":"JANE DOE"},{"entryReference":"000000000001016","bookingDate":"2026-10-04","transactionAmount":{"currency":"EUR","amount":"5.59"},"debtorName":"JOHN DOE"}]}}`)
		default:
			fmt.Fprint(w, `{"account":{"iban":"FI3745760010038400"},"relevantEntryReference":null,"transactions":{"booked":[{"entryReference":"000000000001015","bookingDate":"2026-10-01","transactionAmount":{"currency":"EUR","amount":"-1.00"},"creditorName":"SHOP"}]}}`)
		}
	}))
	defer srv.Close()
	reg := obsdk.NewRegistry()
	reg.Register(berlingroup.Integration(Profiles[0]))
	cfg := obsdk.Config{Env: obsdk.Sandbox, HTTPClient: srv.Client(), Now: func() time.Time { return frozen },
		Credentials: obsdk.Credentials{ClientID: "id", ClientSecret: "secret", RedirectURL: "https://app.example/cb"},
		Extra:       map[string]string{ParamSubscriptionKey: "sub", "base_url": srv.URL + "/psd2"}}
	c, err := reg.New(obsdk.Target{Bank: SaastopankkiBank, Country: "FI"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &obsdk.Session{Integration: Profiles[0].ID, Bank: SaastopankkiBank, Country: "FI", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		AccessToken: "AT", Consents: map[string]obsdk.Consent{"ais": {ID: "c1", Kind: "ais", Status: "valid"}}}
	ctx := context.Background()

	p1, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "sp-01-01", From: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Transactions) != 2 || p1.NextCursor == "" {
		t.Fatalf("page 1: %d transactions, cursor %q", len(p1.Transactions), p1.NextCursor)
	}
	p2, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "sp-01-01", Cursor: p1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Transactions) != 1 || p2.NextCursor != "" {
		t.Fatalf("page 2: %d transactions, cursor %q", len(p2.Transactions), p2.NextCursor)
	}
	pend, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "sp-01-01", Status: []obsdk.TxStatus{obsdk.TxPending}})
	if err != nil {
		t.Fatal(err)
	}
	if tx := pend.Transactions[0]; tx.Direction != obsdk.Debit || tx.Amount.Amount != "-12.34" {
		t.Errorf("pending payment: %+v", tx)
	}
	want := []string{
		"/psd2/v2/accounts/sp-01-01/transactions?bookingStatus=booked&dateFrom=2026-09-01&dateTo=2026-10-19",
		"/psd2/v2/accounts/sp-01-01/transactions?bookingStatus=booked&entryReferenceFrom=000000000001016",
		"/psd2/v2/accounts/sp-01-01/transactions?bookingStatus=pending",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
}

// TestScenarios replays the scenarios recorded against the Samlink sandbox.
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }
