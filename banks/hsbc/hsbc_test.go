package hsbc

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
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// testCert makes a self-signed certificate whose subject has the attribute
// order of HSBC's sandbox certificates (O, L, C, organizationIdentifier, CN).
func testCert(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	attr := func(oid asn1.ObjectIdentifier, v string) []pkix.AttributeTypeAndValue {
		return []pkix.AttributeTypeAndValue{{Type: oid, Value: v}}
	}
	subject := pkix.RDNSequence{
		attr(asn1.ObjectIdentifier{2, 5, 4, 10}, "obsdk"),
		attr(asn1.ObjectIdentifier{2, 5, 4, 7}, "London"),
		attr(asn1.ObjectIdentifier{2, 5, 4, 6}, "GB"),
		attr(asn1.ObjectIdentifier{2, 5, 4, 97}, "PSDGB-TEST-1"),
		attr(asn1.ObjectIdentifier{2, 5, 4, 3}, "test, tpp"),
	}
	raw, err := asn1.Marshal(subject)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), RawSubject: raw, NotBefore: frozen, NotAfter: frozen.AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTestClient(t *testing.T, srv *httptest.Server, key *rsa.PrivateKey, target obsdk.Target) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", RedirectURL: "https://app.example/cb"},
		HTTPClient:  http.DefaultClient,
		Seal:        &obsdk.Seal{Key: key, KeyID: "kid-1", Certificate: testCert(t, key)},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{},
	}
	if srv != nil {
		cfg.HTTPClient = srv.Client()
		cfg.Extra[paramBaseURL] = srv.URL
	}
	if target.Bank == "" {
		target = obsdk.Target{Bank: "hsbc", Country: "GB"}
	}
	c, err := obsdk.New(target, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func session(c *client) *obsdk.Session {
	return &obsdk.Session{Version: 1, Bank: c.brand.bank, Country: c.target.Country, Segment: c.target.Segment, Env: obsdk.Sandbox,
		Integration: c.integrationID(), AccessToken: "at", RefreshToken: "rt",
		Consents: map[string]obsdk.Consent{consentKind: {ID: "consent-1", Kind: consentKind}}}
}

// decodeJWT checks a PS256 signature and returns the header and claims.
func decodeJWT(t *testing.T, jwt string, pub *rsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", jwt)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(pub, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("bad signature: %v", err)
	}
	var h, c map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &h)
	_ = json.Unmarshal(cb, &c)
	return h, c
}

func TestConfigChecks(t *testing.T) {
	cfg := obsdk.Config{Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "cid", RedirectURL: "https://x"}}
	var ce *obsdk.ConfigError
	if _, err := obsdk.New(obsdk.Target{Bank: "hsbc", Country: "GB"}, cfg); !errors.As(err, &ce) || !strings.Contains(err.Error(), "tls_client_cert") {
		t.Fatalf("want a tls_client_cert config error, got %v", err)
	}
	cfg.HTTPClient = http.DefaultClient
	if _, err := obsdk.New(obsdk.Target{Bank: "hsbc", Country: "GB"}, cfg); !errors.As(err, &ce) || !strings.Contains(err.Error(), "seal") {
		t.Fatalf("want a seal config error, got %v", err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg.Seal = &obsdk.Seal{Key: ec, KeyID: "k"}
	if _, err := obsdk.New(obsdk.Target{Bank: "hsbc", Country: "GB"}, cfg); !errors.As(err, &ce) || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("want an RSA config error, got %v", err)
	}
}

func TestBrands(t *testing.T) {
	key := testKey(t)
	cases := []struct {
		target    obsdk.Target
		host, api string
	}{
		{obsdk.Target{Bank: "hsbc", Country: "GB"}, "https://secure.sandbox.ob.hsbc.co.uk", "/obie/open-banking/v4.0/aisp"},
		{obsdk.Target{Bank: "hsbc", Country: "GB", Segment: obsdk.Business}, "https://secure.sandbox.ob.business.hsbc.co.uk", "/obie/open-banking/v4.0/aisp"},
		{obsdk.Target{Bank: "hsbc", Country: "MT"}, "https://secure.sandbox.ob.hsbc.com.mt", "/obie/open-banking/v3.1/aisp"},
		{obsdk.Target{Bank: "firstdirect", Country: "GB"}, "https://secure.sandbox.ob.firstdirect.com", "/obie/open-banking/v4.0/aisp"},
		{obsdk.Target{Bank: "mandsbank", Country: "GB"}, "https://secure.sandbox.ob.mandsbank.com", "/obie/open-banking/v4.0/aisp"},
	}
	for _, tc := range cases {
		c := newTestClient(t, nil, key, tc.target)
		if c.host != tc.host || c.apiPath("aisp") != tc.api {
			t.Errorf("%v: host %s path %s, want %s %s", tc.target, c.host, c.apiPath("aisp"), tc.host, tc.api)
		}
	}
	prod := brands[0]
	if prod.apiHost(obsdk.Production) != "https://api.ob.hsbc.co.uk" || prod.authURL(obsdk.Production) != "https://ob.hsbc.co.uk/obie/open-banking/v1.1/oauth2/authorize" {
		t.Errorf("production hosts: %s %s", prod.apiHost(obsdk.Production), prod.authURL(obsdk.Production))
	}
	cfg := obsdk.Config{Env: obsdk.Sandbox, HTTPClient: http.DefaultClient, Seal: &obsdk.Seal{Key: key, KeyID: "k"}}
	if _, err := obsdk.New(obsdk.Target{Bank: "firstdirect", Country: "GB", Segment: obsdk.Business}, cfg); !errors.Is(err, obsdk.ErrUnsupportedTarget) {
		t.Errorf("first direct business: want ErrUnsupportedTarget, got %v", err)
	}
}

func TestRFC2253(t *testing.T) {
	key := testKey(t)
	got := rfc2253(testCert(t, key).RawSubject)
	want := `CN=test\, tpp,organizationIdentifier=PSDGB-TEST-1,C=GB,L=London,O=obsdk`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestClientAssertionAndRequestObject(t *testing.T) {
	key := testKey(t)
	c := newTestClient(t, nil, key, obsdk.Target{})
	a, err := c.clientAssertion()
	if err != nil {
		t.Fatal(err)
	}
	h, cl := decodeJWT(t, a, &key.PublicKey)
	if h["kid"] != "kid-1" || cl["iss"] != "cid" || cl["sub"] != "cid" || cl["aud"] != "https://secure.sandbox.ob.hsbc.co.uk"+tokenPath {
		t.Errorf("assertion: header %v claims %v", h, cl)
	}
	ro, err := c.signRequestObject("consent-9", "https://app.example/cb", "st", "nonce", "accounts")
	if err != nil {
		t.Fatal(err)
	}
	_, cl = decodeJWT(t, ro, &key.PublicKey)
	intent := cl["claims"].(map[string]any)["id_token"].(map[string]any)["openbanking_intent_id"].(map[string]any)
	if cl["aud"] != "https://secure.sandbox.ob.hsbc.co.uk" || cl["scope"] != "openid accounts" || intent["value"] != "consent-9" ||
		cl["nonce"] != "nonce" || cl["exp"].(float64)-cl["iat"].(float64) > 30*60 {
		t.Errorf("request object claims: %v", cl)
	}
}

func TestSignBody(t *testing.T) {
	key := testKey(t)
	c := newTestClient(t, nil, key, obsdk.Target{})
	body := []byte(`{"Data":{}}`)
	sig, err := c.signBody(body)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sig, ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("want a detached JWS, got %q", sig)
	}
	h, _ := decodeJWT(t, parts[0]+"."+base64.RawURLEncoding.EncodeToString(body)+"."+parts[2], &key.PublicKey)
	if h[claimTAN] != defaultTAN || !strings.HasPrefix(h[claimISS].(string), "CN=test") || h[claimIAT].(float64) != float64(frozen.Unix()) || len(h["crit"].([]any)) != 3 {
		t.Errorf("JWS header: %v", h)
	}
	c.cfg.Seal.Certificate = nil
	var ce *obsdk.ConfigError
	if _, err := c.signBody(body); !errors.As(err, &ce) {
		t.Errorf("without a certificate: want a config error, got %v", err)
	}
}

func TestToAccount(t *testing.T) {
	v4, err := toAccount(json.RawMessage(`{"AccountId":"1","Currency":"GBP","AccountCategory":"Business","AccountTypeCode":"SVGS",
		"Description":"BMM ACCOUNT","Account":[{"SchemeName":"UK.OBIE.SortCodeAccountNumber","Identification":"40400411111111","Name":"Ann"},
		{"SchemeName":"UK.OBIE.IBAN","Identification":"GB12HSBC40400411111111"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if v4.Type != "SVGS" || v4.Usage != "ORGA" || v4.Product != "BMM ACCOUNT" || v4.OwnerName != "Ann" || len(v4.Identifiers) != 2 ||
		v4.Identifiers[0].Scheme != obsdk.SchemeSortCodeAccount || v4.StableID == "" {
		t.Errorf("v4.0 account: %+v", v4)
	}
	v31, err := toAccount(json.RawMessage(`{"AccountId":"2","Currency":"EUR","AccountType":"Personal","AccountSubType":"CurrentAccount",
		"Account":[{"SchemeName":"UK.OBIE.IBAN","Identification":"MT84MALT011000012345MTLCAST001S"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if v31.Type != "CACC" || v31.Usage != "PRIV" || v31.Product != "CurrentAccount" || v31.Identifiers[0].Scheme != obsdk.SchemeIBAN {
		t.Errorf("v3.1 account: %+v", v31)
	}
}

func TestToBalance(t *testing.T) {
	for typ, want := range map[string]obsdk.BalanceKind{"ITBD": obsdk.BalanceInterimBooked, "InterimAvailable": obsdk.BalanceInterimAvailable,
		"CLBD": obsdk.BalanceClosingBooked, "OPBD": obsdk.BalanceOpeningBooked, "FWAV": obsdk.BalanceOther} {
		b := toBalance(balanceJSON{Type: typ, CreditDebitIndicator: "Debit", DateTime: "2026-10-16T10:00:00+00:00", Amount: amountJSON{"5.00", "GBP"}})
		if b.Kind != want || b.Amount.Amount != "-5.00" || b.ReferenceDate != "2026-10-16" {
			t.Errorf("%s: %+v", typ, b)
		}
	}
}

func TestToTransaction(t *testing.T) {
	tx, ok, err := toTransaction(json.RawMessage(`{"TransactionId":"t1","CreditDebitIndicator":"Credit","Status":"PDNG",
		"BookingDateTime":"2026-10-16T00:00:00+00:00","Amount":{"Amount":"12.00","Currency":"GBP"},
		"DebtorAccount":{"SchemeName":"UK.OBIE.SortCodeAccountNumber","Identification":"11111122222222","Name":"Bob"},
		"MerchantDetails":{"MerchantCategoryCode":"5411"}}`))
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if tx.Status != obsdk.TxPending || tx.Direction != obsdk.Credit || tx.Amount.Amount != "12.00" || tx.Counterparty.Name != "Bob" ||
		tx.Counterparty.Identifiers[0].Scheme != obsdk.SchemeSortCodeAccount || tx.MerchantCategory != "5411" {
		t.Errorf("tx: %+v", tx)
	}
	if _, ok, _ := toTransaction(json.RawMessage(`{"Status":"RJCT","CreditDebitIndicator":"Debit","Amount":{"Amount":"1","Currency":"GBP"}}`)); ok {
		t.Error("rejected entries must be skipped")
	}
	if s, _ := txStatus("Booked"); s != obsdk.TxBooked {
		t.Errorf("v3.1 Booked: %s", s)
	}
}

func TestTransactionsPaging(t *testing.T) {
	var srv *httptest.Server
	var queries []string
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		next := ""
		if r.URL.Query().Get("page") == "" {
			next = srv.URL + r.URL.Path + "?page=1"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Data": map[string]any{"Transaction": []any{map[string]any{"TransactionId": "t", "Status": "BOOK", "CreditDebitIndicator": "Debit",
				"BookingDateTime": "2026-10-16T00:00:00+00:00", "Amount": map[string]string{"Amount": "1.00", "Currency": "GBP"}}}},
			"Links": map[string]string{"Next": next},
		})
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t), obsdk.Target{})
	s := session(c)
	ctx := context.Background()
	p1, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "a", From: frozen.AddDate(0, 0, -30), To: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(queries[0], "fromBookingDateTime=2026-09-17T12%3A00%3A00") || p1.NextCursor == "" || len(p1.Transactions) != 1 {
		t.Fatalf("page 1: query %q, %+v", queries[0], p1.TxPage)
	}
	p2, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "a", Cursor: p1.NextCursor})
	if err != nil || p2.NextCursor != "" || queries[1] != "page=1" {
		t.Fatalf("page 2: %v %q %+v", err, queries[1], p2)
	}
	// The access token must never go to a host the cursor names.
	if _, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "a", Cursor: "https://evil.example/accounts/a/transactions"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("foreign cursor: want ErrInvalidRequest, got %v", err)
	}
}

func TestErrorClassification(t *testing.T) {
	c := newTestClient(t, nil, testKey(t), obsdk.Target{})
	mk := func(status int, body string) *resp {
		return &resp{status: status, header: http.Header{}, body: []byte(body)}
	}
	var re *obsdk.ReauthError
	if err := c.apiErr(opAccounts, mk(403, `{"Id":"x","Code":"403","Message":"Forbidden","Errors":[{"ErrorCode":"U008","Message":"Unauthorised Access!"}]}`)); !errors.As(err, &re) || re.Reason != "access_not_granted" {
		t.Errorf("403 on accounts: %v", err)
	}
	if err := c.apiErr(opBalances, mk(401, `{}`)); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("401: %v", err)
	}
	if err := c.apiErr(opRefresh, mk(400, `{"error":"invalid_grant","error_description":"expired"}`)); !errors.As(err, &re) || re.Reason != "refresh_token_invalid" {
		t.Errorf("refresh: %v", err)
	}
	var rl *obsdk.RateLimitedError
	r := mk(429, `{}`)
	r.header.Set("Retry-After", "7")
	if err := c.apiErr(opAccounts, r); !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Errorf("429: %v", err)
	}
	var ae *obsdk.APIError
	if err := c.apiErr(opPayConsent, mk(400, `{"Id":"req-1","Code":"400","Message":"Bad Request","Errors":[{"ErrorCode":"UK.OBIE.Signature.InvalidClaim","Message":"Invalid Claims"}]}`)); !errors.As(err, &ae) ||
		ae.Code != "UK.OBIE.Signature.InvalidClaim" || ae.RequestID != "req-1" {
		t.Errorf("400: %v", err)
	}
}

func TestConnectAuthorizeURL(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case tokenPath:
			_ = r.ParseForm()
			if r.Form.Get("client_assertion_type") != assertionType || r.Form.Get("client_assertion") == "" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"cc","token_type":"Bearer","expires_in":3600}`))
		case "/obie/open-banking/v4.0/aisp/account-access-consents":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Data":{"ConsentId":"c-1","Status":"AWAU"},"Risk":{}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t), obsdk.Target{})
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.Redirect.URL)
	q := u.Query()
	if u.Host != "sandbox.ob.hsbc.co.uk" || q.Get("scope") != "openid accounts" || q.Get("response_type") != "code id_token" || q.Get("request") == "" || q.Get("state") != "state-1" {
		t.Errorf("authorize URL: %s", st.Redirect.URL)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://app.example/cb#code=x&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Errorf("state mismatch: want ErrAuthFailed, got %v", err)
	}
}
