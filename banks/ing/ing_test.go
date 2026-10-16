package ing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func selfSigned(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: frozen, NotAfter: frozen.AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTestClient(t *testing.T, srv *httptest.Server, key crypto.Signer) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: SandboxClientID, RedirectURL: "https://www.example.com/"},
		HTTPClient:  http.DefaultClient,
		Seal:        &obsdk.Seal{Key: key, Certificate: selfSigned(t, key)},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{},
	}
	if srv != nil {
		cfg.HTTPClient, cfg.Extra[paramBaseURL] = srv.Client(), srv.URL
	}
	c, err := obsdk.New(obsdk.Target{Bank: "ing", Country: "NL"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func session() *obsdk.Session {
	exp := frozen.Add(15 * time.Minute)
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "NL", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "at", RefreshToken: "rt", AccessExpiresAt: &exp}
}

func TestRequiresSealCertificate(t *testing.T) {
	key := rsaKey(t)
	_, err := obsdk.New(obsdk.Target{Bank: "ing", Country: "NL"}, obsdk.Config{
		Env: obsdk.Sandbox, HTTPClient: http.DefaultClient, Seal: &obsdk.Seal{Key: key},
		Credentials: obsdk.Credentials{ClientID: "cid", RedirectURL: "https://x"}})
	var ce *obsdk.ConfigError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "seal") {
		t.Fatalf("want a config error naming seal, got %v", err)
	}
}

func TestDigestOfEmptyBody(t *testing.T) {
	if got := digestOf(nil); got != "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" {
		t.Fatalf("digest of empty body: %s", got)
	}
}

// TestJWSSignature checks ING's detached JWS: the protected header, the
// empty payload and a PS256 signature over header + signed HTTP headers.
func TestJWSSignature(t *testing.T) {
	key := rsaKey(t)
	c := newTestClient(t, nil, key)
	target, digest := "get /v4/accounts/a/transactions?limit=10&next=x%3D%3D", digestOf(nil)
	sig, err := c.signJWS(target, digest, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sig, ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("want header..signature, got %q", sig)
	}
	hb, err := b64url.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(c.cfg.Seal.Certificate.Raw)
	if h["alg"] != "PS256" || h["b64"] != false || h["x5t#S256"] != b64url.EncodeToString(fp[:]) || h["sigT"] != "2026-10-16T12:00:00Z" {
		t.Fatalf("unexpected protected header: %s", hb)
	}
	if !strings.HasPrefix(string(hb), `{"b64":false,"x5t#S256":`) {
		t.Fatalf("header field order changed: %s", hb)
	}
	input := parts[0] + ".(request-target): " + target + "\ndigest: " + digest + "\ncontent-type: application/json"
	sum := sha256.Sum256([]byte(input))
	raw, _ := b64url.DecodeString(parts[2])
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], raw, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestJWSSignatureEC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, nil, key)
	sig, err := c.signJWS("get /v4/accounts", digestOf(nil), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sig, ".")
	raw, _ := b64url.DecodeString(parts[2])
	if len(raw) != 64 {
		t.Fatalf("ES256 signature must be r||s (64 bytes), got %d", len(raw))
	}
	input := parts[0] + ".(request-target): get /v4/accounts\ndigest: " + digestOf(nil) + "\ncontent-type: application/json"
	sum := sha256.Sum256([]byte(input))
	r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(&key.PublicKey, sum[:], r, s) {
		t.Fatal("ES256 signature does not verify")
	}
}

func TestAccountIDs(t *testing.T) {
	for _, ref := range []accountRef{
		{resourceID: "r1"},
		{resourceID: "r1", currency: "USD"},
		{resourceID: "r1", card: true},
	} {
		got, err := parseAccountID(ref.id())
		if err != nil || got != ref {
			t.Fatalf("round trip of %+v: %+v, %v", ref, got, err)
		}
	}
	for _, bad := range []string{"", "~EUR", "../x", "a/b"} {
		if _, err := parseAccountID(bad); !errors.Is(err, obsdk.ErrInvalidRequest) {
			t.Fatalf("%q: want ErrInvalidRequest, got %v", bad, err)
		}
	}
}

func TestToAccountsMultiCurrencyAndCards(t *testing.T) {
	raws := []json.RawMessage{
		json.RawMessage(`{"resourceId":"m","iban":"BE74310018305707","name":"Elie","currency":"EUR","product":"ING Lion Account","_links":{"transactions":{"href":"/v4/accounts/m/transactions?currency=EUR"}}}`),
		json.RawMessage(`{"resourceId":"m","iban":"BE74310018305707","name":"Elie","currency":"GBP","product":"ING Lion Account","_links":{"transactions":{"href":"/v4/accounts/m/transactions?currency=GBP"}}}`),
		json.RawMessage(`{"resourceId":"s","iban":"BE12310075932292","name":"Louise","currency":"EUR","product":"ING Green Account"}`),
		json.RawMessage(`{"resourceId":"c","maskedPan":"5248 **** **** 1234","name":"E","currency":"EUR","product":"CREDITCARD","_links":{"transactions":{"href":"/v2/card-accounts/c/transactions"}}}`),
	}
	accs, err := toAccounts(raws)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{accs[0].ID, accs[1].ID, accs[2].ID, accs[3].ID}
	if strings.Join(ids, ",") != "m~EUR,m~GBP,s,card~c" {
		t.Fatalf("ids: %v", ids)
	}
	if accs[0].StableID == "" || accs[0].StableID == accs[1].StableID {
		t.Fatalf("currencies of one account need distinct stable ids: %q %q", accs[0].StableID, accs[1].StableID)
	}
	if accs[3].Type != "CARD" || accs[3].Identifiers[0].Scheme != "MASKED_PAN" || accs[3].StableID == "" {
		t.Fatalf("card account: %+v", accs[3])
	}
	if accs[2].OwnerName != "Louise" || accs[2].Product != "ING Green Account" {
		t.Fatalf("names: %+v", accs[2])
	}
}

const txBody = `{"account":{"iban":"NL69INGB0123456789","currency":"EUR"},"transactions":{
 "booked":[{"transactionId":"b1","endToEndId":"NOTPROVIDED","bookingDate":"2026-10-16","valueDate":"2026-10-16","executionDateTime":"2026-10-15T09:00:00Z",
  "transactionAmount":{"currency":"EUR","amount":100.10},"debtorName":"Bob","debtorAccount":{"iban":"NL31RABO0000000000"},
  "transactionType":"Diversen","remittanceInformationUnstructured":"line one<br>line two<br>",
  "remittanceInformationStructured":{"referenceType":"SCOR","reference":"RF18539007547034"}}],
 "pending":[{"transactionId":"p1","endToEndId":"e2e","executionDateTime":"2026-10-16T08:00:00Z","transactionAmount":{"currency":"EUR","amount":-5.5},
  "creditorName":"Shop","creditorAccount":{"iban":"NL02ABNA0123456789"}}],
 "info":[{"transactionId":"i1","endToEndId":"x","executionDateTime":"2026-10-16T08:00:00Z","transactionAmount":{"currency":"EUR","amount":-40}}],
 "standingOrderAgreementInformation":[],
 "_links":{"next":{"href":"/v4/accounts/a/transactions?next=abc%3D%3D"}}}}`

func TestParseTransactions(t *testing.T) {
	page, err := parseTransactions([]byte(txBody), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Transactions) != 1 || page.NextCursor != "/v4/accounts/a/transactions?next=abc%3D%3D" {
		t.Fatalf("booked only by default, cursor kept: %+v", page)
	}
	b := page.Transactions[0]
	if b.Amount.Amount != "100.10" || b.Direction != obsdk.Credit || b.Counterparty.Name != "Bob" ||
		b.EndToEndID != "" || b.TransactionDate != "2026-10-15" || b.ReferenceNumber != "RF18539007547034" ||
		strings.Join(b.Remittance, "|") != "line one|line two" || b.BankCodeText != "Diversen" {
		t.Fatalf("booked mapping: %+v", b)
	}

	page, _ = parseTransactions([]byte(txBody), false, []obsdk.TxStatus{obsdk.TxPending})
	if len(page.Transactions) != 2 {
		t.Fatalf("pending and info: %+v", page.Transactions)
	}
	p := page.Transactions[0]
	if p.Status != obsdk.TxPending || p.Direction != obsdk.Debit || p.Amount.Amount != "-5.5" || p.Counterparty.Name != "Shop" || p.EndToEndID != "e2e" {
		t.Fatalf("pending mapping: %+v", p)
	}
	if page.Transactions[1].ID != "i1" || page.Transactions[1].Status != obsdk.TxPending {
		t.Fatalf("info must come back as pending: %+v", page.Transactions[1])
	}
}

func TestParseCardTransactions(t *testing.T) {
	body := `{"cardAccount":{"maskedPan":"5248 **** **** 1234","currency":"EUR"},"cardTransactions":{"booked":[
	 {"cardTransactionId":"c1","transactionDate":"2026-10-14","bookingDate":"2026-10-15","transactionAmount":{"currency":"EUR","amount":-12.30},"transactionDetails":"CAFE AMSTERDAM"}],
	 "pending":[],"_links":{"next":{"href":"/v2/card-accounts/c/transactions?next=n"}}}}`
	page, err := parseTransactions([]byte(body), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Transactions) != 1 || page.NextCursor != "/v2/card-accounts/c/transactions?next=n" {
		t.Fatalf("card page: %+v", page)
	}
	tx := page.Transactions[0]
	if tx.ID != "c1" || tx.Direction != obsdk.Debit || tx.Amount.Amount != "-12.30" || tx.Counterparty.Name != "CAFE AMSTERDAM" || tx.TransactionDate != "2026-10-14" {
		t.Fatalf("card mapping: %+v", tx)
	}
}

func TestBalanceAmountsStayExact(t *testing.T) {
	bals, err := parseBalances([]byte(`{"balances":[{"balanceType":"interimBooked","balanceAmount":{"currency":"EUR","amount":-1000.57},"lastChangeDateTime":"2026-10-16T09:00:00Z"},
	 {"balanceType":"expected","balanceAmount":{"currency":"EUR","amount":0.10},"referenceDate":"2026-10-15"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if bals[0].Amount.Amount != "-1000.57" || bals[0].Kind != obsdk.BalanceInterimBooked || bals[0].ReferenceDate != "2026-10-16" {
		t.Fatalf("balance 0: %+v", bals[0])
	}
	if bals[1].Amount.Amount != "0.10" || bals[1].Kind != obsdk.BalanceOther || bals[1].ReferenceDate != "2026-10-15" {
		t.Fatalf("balance 1: %+v", bals[1])
	}
}

func TestConnectRedirect(t *testing.T) {
	c := newTestClient(t, nil, rsaKey(t))
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{Capabilities: []obsdk.Capability{obsdk.CapTransactions}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(st.Redirect.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "myaccount.sandbox.ing.com" || u.Path != "/authorize/v2/NL" || q.Get("client_id") != SandboxClientID ||
		q.Get("scope") != scopeTransactions || q.Get("response_type") != "code" || q.Get("state") != "state-1" ||
		q.Get("redirect_uri") != "https://www.example.com/" {
		t.Fatalf("redirect: %s", st.Redirect.URL)
	}
	if got := scopes(nil); got != scopeBalances+" "+scopeTransactions {
		t.Fatalf("default scopes: %q", got)
	}
	if got := scopes([]obsdk.Capability{obsdk.CapAccounts}); got != scopeBalances {
		t.Fatalf("accounts only: %q", got)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://www.example.com/?code=x&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: want ErrAuthFailed, got %v", err)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://www.example.com/?error=access_denied&state=state-1"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("denied: want ErrAuthFailed, got %v", err)
	}
}

// TestResumeRetriesWhileGrantIsProcessed covers ING's advice to retry the
// accounts call when it answers 404 right after the code exchange.
func TestResumeRetriesWhileGrantIsProcessed(t *testing.T) {
	var accountCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") == "client_credentials" {
				_, _ = w.Write([]byte(`{"access_token":"app","expires_in":900,"client_id":"` + SandboxClientID + `"}`))
				return
			}
			if r.Header.Get("Authorization") != "Bearer app" || r.Form.Get("code") != "the-code" || r.Form.Get("redirect_uri") != "https://www.example.com/" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"cust","expires_in":900,"refresh_token":"ref","refresh_token_expires_in":"2592000","token_type":"Bearer"}`))
		case "/v4/accounts":
			if r.Header.Get("X-JWS-Signature") == "" || r.Header.Get("Digest") == "" || r.Header.Get("Content-Type") != "application/json" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if accountCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"tppMessages":[{"category":"ERROR","code":"NOT_FOUND","text":"3.2 Not Found"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"accounts":[{"resourceId":"r","iban":"NL69INGB0123456789","name":"A","currency":"EUR","product":"Betaalrekening"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, rsaKey(t))
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "?code=the-code&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || len(done.Accounts) != 1 || accountCalls.Load() != 2 {
		t.Fatalf("want done with 1 account after a retry, got %+v (calls %d)", done, accountCalls.Load())
	}
	s := done.Session
	if s.AccessToken != "cust" || s.RefreshToken != "ref" || s.RefreshExpiresAt == nil || !s.RefreshExpiresAt.Equal(frozen.Add(30*24*time.Hour)) {
		t.Fatalf("session: %+v", s)
	}
}

func TestErrorClassification(t *testing.T) {
	c := newTestClient(t, nil, rsaKey(t))
	mk := func(status int, body string) *resp {
		return &resp{status: status, header: http.Header{}, body: []byte(body)}
	}
	if err := c.apiErr(opAccounts, mk(401, `{"message":"Unauthorized"}`)); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Fatalf("401: %v", err)
	}
	if err := c.apiErr(opBalances, mk(403, `{"tppMessages":[{"category":"ERROR","code":"SERVICE_BLOCKED","text":"1.1"}]}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("403: %v", err)
	}
	if err := c.apiErr(opRefresh, mk(400, `{"error":"invalid_grant","error_description":"Refresh token is revoked."}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("refresh: %v", err)
	}
	if err := c.apiErr(opTransactions, mk(429, `{}`)); !errors.Is(err, obsdk.ErrRateLimited) {
		t.Fatalf("429: %v", err)
	}
	var ae *obsdk.APIError
	if err := c.apiErr(opTransactions, mk(500, `{"tppMessages":[{"code":"ING_ERROR","text":"3.1 - Internal Server Error"}]}`)); !errors.As(err, &ae) || ae.Code != "ING_ERROR" {
		t.Fatalf("500: %v", err)
	}
}

func TestTransactionsRejectsForeignCursor(t *testing.T) {
	c := newTestClient(t, nil, rsaKey(t))
	for _, cur := range []string{"https://evil.example/v4/accounts/a/transactions?next=x", "/v4/accounts/a/balances", "v4/accounts/a/transactions"} {
		_, err := c.Transactions(context.Background(), session(), obsdk.TxQuery{AccountID: "a", Cursor: cur})
		if !errors.Is(err, obsdk.ErrInvalidRequest) {
			t.Fatalf("cursor %q: want ErrInvalidRequest, got %v", cur, err)
		}
	}
}
