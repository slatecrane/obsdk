package nordea

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestClient(t *testing.T, srv *httptest.Server, key *rsa.PrivateKey, seg obsdk.Segment) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "secret", RedirectURL: "https://example.com"},
		Seal:        &obsdk.Seal{Key: key},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{},
	}
	if srv != nil {
		cfg.HTTPClient, cfg.Extra[paramBaseURL] = srv.Client(), srv.URL
	}
	c, err := obsdk.New(obsdk.Target{Bank: "nordea", Country: "FI", Segment: seg}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func session(seg obsdk.Segment) *obsdk.Session {
	exp := frozen.Add(time.Hour)
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "FI", Segment: seg, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "at", RefreshToken: "rt", AccessExpiresAt: &exp}
}

var sigRE = regexp.MustCompile(`^keyId="([^"]+)",algorithm="rsa-sha256",headers="([^"]+)",signature="([^"]+)"$`)

// verify checks the HTTP Signature the way Nordea does.
func verify(t *testing.T, r *http.Request, body []byte, key *rsa.PublicKey) {
	t.Helper()
	m := sigRE.FindStringSubmatch(r.Header.Get("Signature"))
	if m == nil || m[1] != "cid" {
		t.Fatalf("signature header: %q", r.Header.Get("Signature"))
	}
	var lines []string
	for _, h := range strings.Fields(m[2]) {
		if h == "(request-target)" {
			lines = append(lines, h+": "+strings.ToLower(r.Method)+" "+r.URL.RequestURI())
			continue
		}
		lines = append(lines, h+": "+r.Header.Get(h))
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	sig, _ := base64.StdEncoding.DecodeString(m[3])
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify over %q: %v", strings.Join(lines, "\n"), err)
	}
	if d := r.Header.Get("Digest"); d != "" {
		want := digestOf(body)
		if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			f, _ := url.ParseQuery(string(body))
			want = digestOf([]byte(decodedForm(f)))
		}
		if d != want {
			t.Fatalf("digest %s, want %s", d, want)
		}
	}
	if r.Header.Get("X-IBM-Client-Id") != "cid" || r.Header.Get("X-IBM-Client-Secret") != "secret" {
		t.Fatal("client credentials missing")
	}
}

func TestRequiresRSASeal(t *testing.T) {
	_, err := obsdk.New(obsdk.Target{Bank: "nordea", Country: "FI"}, obsdk.Config{
		Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "c", ClientSecret: "s", RedirectURL: "https://x"}})
	var ce *obsdk.ConfigError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "seal") {
		t.Fatalf("want a config error naming seal, got %v", err)
	}
}

func TestDecodedForm(t *testing.T) {
	f := url.Values{"redirect_uri": {"https://example.com/cb?x=1"}, "code": {"a+b"}, "grant_type": {"authorization_code"}}
	if got := decodedForm(f); got != "code=a+b&grant_type=authorization_code&redirect_uri=https://example.com/cb?x=1" {
		t.Fatalf("got %q", got)
	}
}

// TestConnectFlow drives Connect and Resume against a fake Nordea: the
// authorize call must not follow the 302, and every call must be signed.
func TestConnectFlow(t *testing.T) {
	key := rsaKey(t)
	var authorize map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		verify(t, r, body, &key.PublicKey)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/business/v5/authorize":
			_ = json.Unmarshal(body, &authorize)
			http.Redirect(w, r, "https://login.nordea.example/?session=1", http.StatusFound)
		case "/business/v5/authorize/token":
			f, _ := url.ParseQuery(string(body))
			if f.Get("code") != "the-code" || f.Get("redirect_uri") != "https://example.com" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at","expires_in":3599,"token_type":"Bearer","refresh_token":"rt"}`))
		case "/business/v4/accounts":
			if r.Header.Get("Authorization") != "Bearer at" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"response":{"accounts":[{"_id":"FI38-EUR","country":"FI","account_numbers":[{"value":"FI3815903000105518","_type":"IBAN"}],
				"currency":"EUR","account_name":"Toren Oy","account_holder":"Toren Oy Holder","product":"SHEKKITILI","account_type":"Current",
				"available_balance":"13216.34","booked_balance":"13200.00","credit_limit":"10000.00","bank":{"bic":"NDEAFIHH"}}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, key, obsdk.Business)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{Capabilities: []obsdk.Capability{obsdk.CapTransactions}, ConsentValidityDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	if st.Redirect.URL != "https://login.nordea.example/?session=1" {
		t.Fatalf("redirect: %+v", st.Redirect)
	}
	if authorize["country"] != "FI" || authorize["duration"] != float64(180*24*60) || authorize["state"] != "state-1" ||
		strings.Join(toStrings(authorize["scope"]), ",") != "ACCOUNTS_BASIC,ACCOUNTS_DETAILS,ACCOUNTS_TRANSACTIONS" {
		t.Fatalf("authorize body: %v", authorize)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com?code=the-code&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	a := done.Accounts[0]
	if a.ID != "FI38-EUR" || a.OwnerName != "Toren Oy Holder" || a.Usage != "ORGA" || a.Type != "CACC" || a.BIC != "NDEAFIHH" ||
		a.CreditLimit.Amount != "10000.00" || len(a.Balances) != 2 || a.Balances[0].Kind != obsdk.BalanceInterimAvailable {
		t.Fatalf("account: %+v", a)
	}
	s := done.Session
	if s.AccessToken != "at" || s.RefreshToken != "rt" || !s.Consents[consentKind].ValidUntil.Equal(frozen.AddDate(0, 0, 180)) {
		t.Fatalf("session: %+v", s)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com?code=x&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: %v", err)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestParseTransactions(t *testing.T) {
	body := `{"response":{"transactions":[
	 {"transaction_id":"b1","currency":"EUR","booking_date":"2026-10-15","value_date":"2026-10-15","transaction_date":"2026-10-14","type_description":"Korttiosto",
	  "narrative":"GBP 31.20 Heathrow","message":"GBP 31.20 Heathrow","status":"billed","reference":"795622333023","counterparty_name":"Avis","amount":"-37.06"},
	 {"transaction_id":"r1","currency":"EUR","booking_date":"2026-10-16","status":"reserved","counterparty_name":"Kiosk","amount":"-2.00"},
	 {"transaction_id":"c1","currency":"EUR","booking_date":"2026-10-16","status":"billed","counterparty_name":"Employer","counterparty_account":"FI7473834510057469","amount":"1500.00"}],
	 "_links":[{"rel":"next","href":"/v5/accounts/A/transactions?continuation_key=key-2"}]}}`
	page, err := parseTransactions([]byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Transactions) != 2 || page.NextCursor != "key-2" {
		t.Fatalf("booked only, cursor: %+v", page)
	}
	b := page.Transactions[0]
	if b.Direction != obsdk.Debit || b.Amount.Amount != "-37.06" || b.Counterparty.Name != "Avis" || b.ReferenceNumber != "795622333023" ||
		b.BankCodeText != "Korttiosto" || b.TransactionDate != "2026-10-14" || b.Remittance[0] != "GBP 31.20 Heathrow" {
		t.Fatalf("booked: %+v", b)
	}
	c := page.Transactions[1]
	if c.Direction != obsdk.Credit || c.Counterparty.Identifiers[0].Scheme != "IBAN" {
		t.Fatalf("credit: %+v", c)
	}
	page, _ = parseTransactions([]byte(body), []obsdk.TxStatus{obsdk.TxPending})
	if len(page.Transactions) != 1 || page.Transactions[0].ID != "r1" {
		t.Fatalf("pending: %+v", page.Transactions)
	}
}

func TestTransactionsQuery(t *testing.T) {
	key := rsaKey(t)
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verify(t, r, nil, &key.PublicKey)
		got = r.URL.Query()
		_, _ = w.Write([]byte(`{"response":{"transactions":[]}}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, key, obsdk.Personal)
	_, err := c.Transactions(context.Background(), session(obsdk.Personal), obsdk.TxQuery{AccountID: "A",
		From: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), To: frozen, Cursor: "key-2"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("from_date") != "2026-09-01" || got.Get("to_date") != "2026-10-16" || got.Get("continuation_key") != "key-2" {
		t.Fatalf("query: %v", got)
	}
	if _, err := c.Transactions(context.Background(), session(obsdk.Personal), obsdk.TxQuery{AccountID: "a/b"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("bad id: %v", err)
	}
}

func TestErrorClassification(t *testing.T) {
	c := newTestClient(t, nil, rsaKey(t), obsdk.Personal)
	mk := func(status int, body string) *resp {
		return &resp{status: status, header: http.Header{}, body: []byte(body)}
	}
	env := `{"group_header":{"message_identification":"m1","http_code":%d},"error":{"failures":[{"code":"%s","description":"d"}]}}`
	var ae *obsdk.APIError
	if err := c.apiErr(opAccounts, mk(401, strings.Replace(strings.Replace(env, "%d", "401", 1), "%s", "error.token.expired", 1))); !errors.Is(err, obsdk.ErrAccessExpired) || !errors.As(err, &ae) || ae.Code != "error.token.expired" || ae.RequestID != "m1" {
		t.Fatalf("401: %v", err)
	}
	if err := c.apiErr(opTransactions, mk(403, `{}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("403: %v", err)
	}
	if err := c.apiErr(opRefresh, mk(400, `{"error":"invalid_grant","error_description":"expired"}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("refresh: %v", err)
	}
	if err := c.apiErr(opAccounts, mk(429, `{}`)); !errors.Is(err, obsdk.ErrRateLimited) {
		t.Fatalf("429: %v", err)
	}
}
