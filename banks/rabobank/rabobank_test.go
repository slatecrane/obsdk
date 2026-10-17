package rabobank

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func selfSigned(t *testing.T, key *rsa.PrivateKey, serial int64) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"}, NotBefore: frozen, NotAfter: frozen.AddDate(1, 0, 0)}
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

func newTestClient(t *testing.T, srv *httptest.Server, key *rsa.PrivateKey) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "secret", RedirectURL: "https://example.com/cb"},
		HTTPClient:  http.DefaultClient,
		Seal:        &obsdk.Seal{Key: key, Certificate: selfSigned(t, key, 1523433508)},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{},
	}
	if srv != nil {
		cfg.HTTPClient = srv.Client()
		cfg.Extra[paramBaseURL] = srv.URL + "/openapi/sandbox"
		cfg.Extra[paramOAuthURL] = srv.URL + "/oauth2"
	}
	c, err := obsdk.New(obsdk.Target{Bank: "rabobank", Country: "NL"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func session() *obsdk.Session {
	exp := frozen.Add(time.Hour)
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "NL", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "at", RefreshToken: "rt", AccessExpiresAt: &exp,
		Consents: map[string]obsdk.Consent{consentKind: {ID: "cons-1", Kind: consentKind}}, Meta: map[string]string{}}
}

// ---- signing ----

// Rabobank's documentation signs its examples with an older sandbox
// certificate (serial 1523433508) and shows that certificate's
// TPP-Signature-Certificate value. Its signatures must verify over the
// signing strings we build.
const docCert = "MIIDkDCCAnigAwIBAgIEWs3AJDANBgkqhkiG9w0BAQsFADCBiTELMAkGA1UEBhMCTkwxEDAOBgNVBAgMB1V0cmVjaHQxEDAOBgNVBAcMB1V0cmVjaHQxETAPBgNVBAoMCFJhYm9iYW5rMRwwGgYDVQQLDBNPbmxpbmUgVHJhbnNhY3Rpb25zMSUwIwYDVQQDDBxQU0QyIEFQSSBQSSBTZXJ2aWNlcyBTYW5kYm94MB4XDTE4MDQxMTA3NTgyOFoXDTIzMDQxMTA3NTgyOFowgYkxCzAJBgNVBAYTAk5MMRAwDgYDVQQIDAdVdHJlY2h0MRAwDgYDVQQHDAdVdHJlY2h0MREwDwYDVQQKDAhSYWJvYmFuazEcMBoGA1UECwwTT25saW5lIFRyYW5zYWN0aW9uczElMCMGA1UEAwwcUFNEMiBBUEkgUEkgU2VydmljZXMgU2FuZGJveDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANoAjqGWUgCIm2F+0sBSEwLal+T3u+uldLikpxHCB8iL1GD7FrRjcA+MVsxhvHly7vRsHK+tQyMSaeK782RHpY33qxPLc8LmoQLb2EuiQxXj9POYkYBQ74qkrZnvKVlR3WoyQWeDOXnSY2wbNFfkP8ET4ElwyuIIEriwYhab0OIrnnrO8X82/SPZxHwEd3aQjQ6uhiw8paDspJbS5WjEfuwY16KVVUYlhbtAwGjvc6aK0NBm+LH9fMLpAE6gfGZNy0gzMDorVNbkQK1IoAGD8p9ZHdB0F3FwkILEjUiQW6nK+/fKDNJ0TBbpgZUpY8bR460qzxKdeZ1yPDqX2Cjh6fkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAYL4iD6noMJAt63kDED4RB2mII/lssvHhcxuDpOm3Ims9urubFWEpvV5TgIBAxy9PBinOdjhO1kGJJnYi7F1jv1qnZwTV1JhYbvxv3+vk0jaiu7Ew7G3ASlzruXyMhN6t6jk9MpaWGl5Uw1T+gNRUcWQRR44g3ahQRIS/UHkaV+vcpOa8j186/1X0ULHfbcVQk4LMmJeXqNs8sBAUdKU/c6ssvj8jfJ4SfrurcBhY5UBTOdQOXTPY85aU3iFloerx7Oi9EHewxInOrU5XzqqTz2AQPXezexVeAQxP27lzqCmYC7CFiam6QBr06VebkmnPLfs76n8CDc1cwE6gUl0rMA=="

func TestDocSignatureVectors(t *testing.T) {
	der, _ := base64.StdEncoding.DecodeString(docCert)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber.String() != "1523433508" {
		t.Fatalf("keyId should be the decimal serial, got %s", cert.SerialNumber)
	}
	cases := []struct {
		name   string
		header http.Header
		sig    string
	}{
		{"account information", http.Header{
			"Date": {"Tue, 13 Sep 2022 09:51:01 GMT"}, "Digest": {digestOf(nil)},
			"X-Request-Id": {"95126d8f-ae9d-4ac3-ac9e-c357dcd78811"},
		}, "t7b3deOMrTmOs+mjuY43mMcgpttrIWrkEGRmdEXaiurqrl0BO9hPOk4k+7OKmPWbxqE8nBFFSVSDU7+t84cUdjB3VTsl94rPuPVj/4XKwrqzKcmPHQHZ87ENPHWSFEDuOnub0FrJ4pUImsZpbenkZX+I80MElJQ337jp904JzyA+WKi7SzPjgGTUGlujhRUu3kU4TDNkcLIaBrcok9mXFlJSZQuNaaKfz4kqeaBpG2p3ZjcICnuE1aYFu5VZoniJd3Bi3n0ygVyb/9BaGHYMYvDvKHHtw6So8YGTTO+LnLZmOTgjXKhDIdBOgtJ4PWxvrp0Iid/YaM+BHqZPu4N1bw=="},
		{"payment initiation", http.Header{
			"Date": {"Thu, 24 May 2022 06:53:05 GMT"}, "Digest": {"sha-512=97iSEKK+wtenUIu8DozlaGP+g2OjYy8F081o0gaLt4w6FomFJVEJktCPHEfrauwU48Tus44YStT8+q6erKA4Gg=="},
			"X-Request-Id": {"7d2da3f9-67d3-5034-b7cc-29f1a05ef1f5"}, "Tpp-Redirect-Uri": {"https://www.rabobank.nl"},
		}, "LW0sGv1Ptg8vTNVDzVCZv4l3TQSC565AMGlWOKNMAO7HorDeaswYhQO6Af0Y8fUmQsCRQOefC9JhjdXqjlJQXN7XYs2Zstg1FczWF4sExx2eAPquW5gwNyittSkg9Ln8wJ6/dnaZIa8KfzVWOH5wFPqb3mMmMn7RFAVpPp3hGEcrZAbTXglwyLTyr37/0beEBHC1sdjVkE+U6E7/lQs1IE0bgMS+qgIoncp+wVpELLg4FUe6CN5vC51exiud1sSxyScdNVbAhRK2XTgaxzQhN4VoYcztruxcyoVpYyK6sZK44lOO034i+HnUowrpTXV543p1u1O1q8Q4tnbQg+poYQ=="},
	}
	for _, tc := range cases {
		sum := sha512.Sum512([]byte(signingString(tc.header, signedHeaders(tc.header))))
		sig, _ := base64.StdEncoding.DecodeString(tc.sig)
		if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA512, sum[:], sig); err != nil {
			t.Errorf("%s: documented signature does not verify over our signing string: %v", tc.name, err)
		}
	}
}

func TestDigestOfEmptyBody(t *testing.T) {
	if got := digestOf(nil); got != "sha-512=z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==" {
		t.Fatalf("digest of empty body: %s", got)
	}
}

// docPayment is the SEPA example of Rabobank's signing documentation, with
// valid IBANs: the documented ones fail their check digits, so the SDK
// refuses them before calling the bank. TestPaymentBodyMatchesDocExample puts
// them back.
func docPayment() obsdk.PaymentRequest {
	return obsdk.PaymentRequest{
		Type:          obsdk.PaymentSEPA,
		PSU:           obsdk.PSUContext{IP: "203.0.113.7"},
		Debtor:        &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "NL82RABO1108003001"}},
		ExecutionDate: "2026-11-15",
		Transfers: []obsdk.Transfer{{
			Amount:     obsdk.Money{Amount: "10.25", Currency: "EUR"},
			EndToEndID: "PI-123456789",
			Remittance: []string{"Ref Number Merchant 235839479.3434"},
			Creditor: obsdk.Creditor{
				Name:    "Company",
				Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "NL83RABO0305224387"},
				Agent:   &obsdk.Agent{BIC: "RABONL2U"},
				Address: &obsdk.PostalAddress{Street: "Utrechtstraat", BuildingNumber: "8", PostCode: "2456RL", Town: "Utrecht", Country: "NL"},
			},
		}},
	}
}

// TestPaymentBodyMatchesDocExample: the body we build for the documented
// payment has the documented digest, i.e. the same bytes.
func TestPaymentBodyMatchesDocExample(t *testing.T) {
	r := docPayment()
	r.ExecutionDate = "2022-06-15"
	r.Debtor.Account.Value = "NL10RABO0912345678"
	r.Transfers[0].Creditor.Account.Value = "NL10RABO0123456789"
	b, err := buildBody(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(b)
	if got := digestOf(body); got != "sha-512=97iSEKK+wtenUIu8DozlaGP+g2OjYy8F081o0gaLt4w6FomFJVEJktCPHEfrauwU48Tus44YStT8+q6erKA4Gg==" {
		t.Fatalf("body differs from the documented example:\n%s", body)
	}
}

var sigRE = regexp.MustCompile(`^keyId="(\d+)",algorithm="rsa-sha512",headers="([a-z -]+)",signature="([^"]+)"$`)

// verifySigned checks a request the way Rabobank would.
func verifySigned(t *testing.T, r *http.Request, body []byte, key *rsa.PrivateKey) {
	t.Helper()
	if got := r.Header.Get("Digest"); got != digestOf(body) {
		t.Errorf("%s %s: digest %q does not match the body", r.Method, r.URL.Path, got)
	}
	if r.Header.Get("X-IBM-Client-Id") != "cid" || r.Header.Get("TPP-Signature-Certificate") == "" || r.Header.Get("Date") == "" {
		t.Errorf("%s %s: missing client id, certificate or date", r.Method, r.URL.Path)
	}
	m := sigRE.FindStringSubmatch(r.Header.Get("Signature"))
	if m == nil {
		t.Fatalf("%s %s: malformed Signature %q", r.Method, r.URL.Path, r.Header.Get("Signature"))
	}
	if m[1] != "1523433508" {
		t.Errorf("keyId = %s", m[1])
	}
	sum := sha512.Sum512([]byte(signingString(r.Header, strings.Fields(m[2]))))
	sig, _ := base64.StdEncoding.DecodeString(m[3])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, sum[:], sig); err != nil {
		t.Errorf("%s %s: signature does not verify: %v", r.Method, r.URL.Path, err)
	}
}

func TestRequiresRSASealWithCertificate(t *testing.T) {
	key := rsaKey(t)
	_, err := obsdk.New(obsdk.Target{Bank: "rabobank", Country: "NL"}, obsdk.Config{
		Env: obsdk.Sandbox, HTTPClient: http.DefaultClient, Seal: &obsdk.Seal{Key: key},
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "s", RedirectURL: "https://x"}})
	var ce *obsdk.ConfigError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "seal") {
		t.Fatalf("want a config error naming seal, got %v", err)
	}
}

// ---- fake server ----

type fake struct {
	t    *testing.T
	key  *rsa.PrivateKey
	seen []string
	h    map[string]func(w http.ResponseWriter, r *http.Request, body []byte)
}

func newFake(t *testing.T, key *rsa.PrivateKey) (*fake, *httptest.Server) {
	f := &fake{t: t, key: key, h: map[string]func(http.ResponseWriter, *http.Request, []byte){}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		k := r.Method + " " + r.URL.Path
		f.seen = append(f.seen, k)
		if !strings.HasPrefix(r.URL.Path, "/oauth2/") || strings.HasPrefix(r.URL.Path, "/oauth2/consents") {
			verifySigned(t, r, body, key)
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

const (
	aisPath = "/openapi/sandbox/payments/account-information/ais"
	pisPath = "/openapi/sandbox/payments/payment-initiation/pis/v1/payments/sepa-credit-transfers"
)

const accountsJSON = `{"accounts":[{"resourceId":"Tkw4MlJBQk8xMTA4MDAzMDAxOkVVUg","iban":"NL82RABO1108003001","currency":"EUR","ownerName":"J. Jansen","status":"enabled"}]}`

func TestConnect(t *testing.T) {
	key := rsaKey(t)
	f, srv := newFake(t, key)
	f.h["POST /oauth2/token"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if u, p, ok := r.BasicAuth(); !ok || u != "cid" || p != "secret" {
			t.Errorf("token call without client credentials")
		}
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "authorization_code" || form.Get("code") != "the-code" || form.Get("redirect_uri") != "https://example.com/cb" {
			t.Errorf("unexpected token form %v", form)
		}
		reply(200, `{"token_type":"bearer","access_token":"AT","expires_in":3600,"consented_on":1792238400,"metadata":"a:consentId 123a1a2a-888c-4015-8099-f88b080d0bbb","scope":"ais.balances.read ais.transactions.read-90days","refresh_token":"RT","refresh_token_expires_in":2592000}`)(w, r, body)
	}
	f.h["GET "+aisPath+"/accounts"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("Authorization") != "Bearer AT" {
			t.Errorf("accounts without the user's token")
		}
		reply(200, accountsJSON)(w, r, body)
	}
	c := newTestClient(t, srv, key)

	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.Redirect.URL)
	if u.Path != "/oauth2/authorize" || u.Query().Get("scope") != "ais.balances.read ais.transactions.read-90days" ||
		u.Query().Get("state") != "state-1" || u.Query().Get("client_id") != "cid" {
		t.Fatalf("unexpected authorize URL %s", st.Redirect.URL)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb?code=x&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch should fail auth, got %v", err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb?code=the-code&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	s := done.Session
	cons := s.Consents[consentKind]
	if s.AccessToken != "AT" || s.RefreshToken != "RT" || cons.ID != "123a1a2a-888c-4015-8099-f88b080d0bbb" {
		t.Fatalf("unexpected session %+v", s)
	}
	if want := time.Unix(1792238400, 0).UTC().AddDate(0, 0, 180); cons.ValidUntil == nil || !cons.ValidUntil.Equal(want) {
		t.Fatalf("consent should run 180 days from consented_on, got %v", cons.ValidUntil)
	}
	if len(done.Accounts) != 1 || done.Accounts[0].ID != "Tkw4MlJBQk8xMTA4MDAzMDAxOkVVUg" || done.Accounts[0].OwnerName != "J. Jansen" {
		t.Fatalf("unexpected accounts %+v", done.Accounts)
	}
}

func TestScopes(t *testing.T) {
	for _, tc := range []struct {
		caps []obsdk.Capability
		want string
	}{
		{nil, "ais.balances.read ais.transactions.read-90days"},
		{[]obsdk.Capability{obsdk.CapAccounts}, "ais.balances.read"},
		{[]obsdk.Capability{obsdk.CapTransactions}, "ais.transactions.read-90days"},
		{[]obsdk.Capability{obsdk.CapTransactionsHistory}, "ais.transactions.read-90days ais.transactions.read-history"},
	} {
		if got := scopes(tc.caps); got != tc.want {
			t.Errorf("scopes(%v) = %q, want %q", tc.caps, got, tc.want)
		}
	}
}

func TestBalancesAndErrors(t *testing.T) {
	key := rsaKey(t)
	f, srv := newFake(t, key)
	acc := aisPath + "/accounts/Tkw4MlJBQk8xMTA4MDAzMDAxOkVVUg"
	f.h["GET "+acc+"/balances"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("PSU-IP-Address") != "203.0.113.7" {
			t.Errorf("PSU-IP-Address not forwarded")
		}
		reply(200, `{"account":{"iban":"NL82RABO1108003001","currency":"EUR"},"balances":[{"balanceType":"expected","balanceAmount":{"amount":"-12.50","currency":"EUR"},"lastChangeDateTime":"2026-10-16T08:00:00Z"},{"balanceType":"interimBooked","balanceAmount":{"amount":"100.00","currency":"EUR"}}]}`)(w, r, body)
	}
	c := newTestClient(t, srv, key)
	res, err := c.Balances(context.Background(), session(), "Tkw4MlJBQk8xMTA4MDAzMDAxOkVVUg", obsdk.CallOptions{PSU: &obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	b := res.Data
	if len(b) != 2 || b[0].Kind != obsdk.BalanceOther || b[0].BankType != "expected" || b[0].Amount.Amount != "-12.50" ||
		b[0].ReferenceDate != "2026-10-16" || b[1].Kind != obsdk.BalanceInterimBooked {
		t.Fatalf("unexpected balances %+v", b)
	}

	f.h["GET "+acc+"/balances"] = reply(403, `{"httpCode":"403","httpMessage":"Forbidden","moreInformation":"CONSENT_INVALID"}`)
	if _, err := c.Balances(context.Background(), session(), "Tkw4MlJBQk8xMTA4MDAzMDAxOkVVUg", obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("CONSENT_INVALID should require re-authorisation, got %v", err)
	}
	f.h["GET "+acc+"/balances"] = reply(401, `{"httpCode":"401","httpMessage":"Unauthorized","moreInformation":"This server could not verify that you are authorized to access the URL"}`)
	if _, err := c.Balances(context.Background(), session(), "Tkw4MlJBQk8xMTA4MDAzMDAxOkVVUg", obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Fatalf("401 should mean an expired token, got %v", err)
	}
	f.h["GET "+acc+"/balances"] = reply(429, `{"httpCode":"429","httpMessage":"Too Many Requests"}`)
	if _, err := c.Balances(context.Background(), session(), "Tkw4MlJBQk8xMTA4MDAzMDAxOkVVUg", obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrRateLimited) {
		t.Fatalf("429 should be rate limiting, got %v", err)
	}
	if _, err := c.Balances(context.Background(), session(), "../x", obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("a path in the account id should be refused, got %v", err)
	}
}

func TestTransactionsPaging(t *testing.T) {
	key := rsaKey(t)
	f, srv := newFake(t, key)
	path := aisPath + "/accounts/acc1/transactions"
	f.h["GET "+path] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		q := r.URL.Query()
		if q.Get("nextPageToken") == "" {
			if q.Get("bookingStatus") != "booked" || q.Get("dateFrom") != "2026-09-01T00:00:00Z" || q.Get("dateTo") != "2026-10-17T12:00:00Z" || q.Get("size") != "500" {
				t.Errorf("unexpected first-page query %v", q)
			}
			reply(200, `{"account":{"iban":"NL82RABO1108003001"},"transactions":{"_links":{"account":{"href":"/accounts/acc1"},"next":{"href":"/accounts/acc1/transactions?bookingStatus=booked&nextPageToken=abc%3D%3D"}},
				"booked":[{"entryReference":"1001","bookingDate":"2026-10-01","valueDate":"2026-10-01","transactionAmount":{"amount":"-25.00","currency":"EUR"},"creditorName":"Albert Heijn","creditorAccount":{"iban":"NL20INGB0001234567"},"endToEndId":"NOTPROVIDED","remittanceInformationUnstructured":"Boodschappen","raboDetailedTransactionType":"2033","raboTransactionTypeName":"bc"}],
				"pending":[{"transactionAmount":{"amount":"40.00","currency":"EUR"},"debtorName":"","ultimateDebtor":"Werkgever BV","debtorAccount":{"iban":"NL91ABNA0417164300"},"remittanceInformationStructured":"1234567890123456"}]}}`)(w, r, body)
			return
		}
		if q.Get("nextPageToken") != "abc==" || q.Get("bookingStatus") != "booked" {
			t.Errorf("next page should repeat the next link's query, got %v", q)
		}
		reply(200, `{"transactions":{"_links":{"account":{"href":"/accounts/acc1"}},"booked":[]}}`)(w, r, body)
	}
	c := newTestClient(t, srv, key)
	q := obsdk.TxQuery{AccountID: "acc1", From: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), PageSize: 1000,
		Status: []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}}
	res, err := c.Transactions(context.Background(), session(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transactions) != 2 || res.NextCursor == "" {
		t.Fatalf("unexpected page %+v", res.TxPage)
	}
	out, in := res.Transactions[0], res.Transactions[1]
	if out.ID != "1001" || out.Direction != obsdk.Debit || out.Counterparty.Name != "Albert Heijn" || out.EndToEndID != "" ||
		out.BankCode != "2033" || len(out.Remittance) != 1 || out.Status != obsdk.TxBooked {
		t.Fatalf("unexpected booked transaction %+v", out)
	}
	if in.Direction != obsdk.Credit || in.Status != obsdk.TxPending || in.Counterparty.Name != "Werkgever BV" || in.ReferenceNumber != "1234567890123456" {
		t.Fatalf("unexpected pending transaction %+v", in)
	}
	q.Cursor = res.NextCursor
	res, err = c.Transactions(context.Background(), session(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transactions) != 0 || res.NextCursor != "" {
		t.Fatalf("last page should be empty without a cursor: %+v", res.TxPage)
	}
	if _, err := c.Transactions(context.Background(), session(), obsdk.TxQuery{AccountID: "acc1", Status: []obsdk.TxStatus{obsdk.TxPending}}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("pending alone should be unsupported, got %v", err)
	}
	if _, err := c.Transactions(context.Background(), session(), obsdk.TxQuery{AccountID: "acc1", Cursor: "/elsewhere"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("a cursor without nextPageToken should be refused, got %v", err)
	}
}

func TestRefreshAndDisconnect(t *testing.T) {
	key := rsaKey(t)
	f, srv := newFake(t, key)
	f.h["POST /oauth2/token"] = reply(200, `{"token_type":"bearer","access_token":"AT2","expires_in":3600,"consented_on":1792238400,"metadata":"a:consentId cons-1","refresh_token":"RT2","refresh_token_expires_in":2592000}`)
	f.h["DELETE /openapi/sandbox/oauth2/consents/cons-1"] = reply(204, "")
	c := newTestClient(t, srv, key)

	ns, err := c.Refresh(context.Background(), session())
	if err != nil {
		t.Fatal(err)
	}
	if ns.AccessToken != "AT2" || ns.RefreshToken != "RT2" || ns.Consents[consentKind].ID != "cons-1" {
		t.Fatalf("unexpected refreshed session %+v", ns)
	}
	f.h["POST /oauth2/token"] = reply(401, `{"error":"invalid_grant"}`)
	if _, err := c.Refresh(context.Background(), session()); !errors.Is(err, obsdk.ErrReauthRequired) || !errors.Is(err, obsdk.ErrRefreshFailed) {
		t.Fatalf("a used refresh token should need re-authorisation, got %v", err)
	}

	res, err := c.Disconnect(context.Background(), session())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Closed) != 1 || res.Session.AccessToken != "" || len(res.Session.Consents) != 0 {
		t.Fatalf("unexpected disconnect result %+v", res)
	}
}

func TestPaymentFlow(t *testing.T) {
	key := rsaKey(t)
	f, srv := newFake(t, key)
	status := "ACSP"
	f.h["POST "+pisPath] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("TPP-Redirect-URI") != "https://example.com/cb" || r.Header.Get("PSU-IP-Address") != "203.0.113.7" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected payment headers %v", r.Header)
		}
		if !strings.Contains(r.Header.Get("Signature"), `headers="date digest x-request-id tpp-redirect-uri"`) {
			t.Errorf("TPP-Redirect-URI must be signed: %s", r.Header.Get("Signature"))
		}
		reply(201, `{"_links":{"scaRedirect":{"href":"https://bankieren.rabobank.nl/klanten?paymentinitiationid=123e4567-e89b-42d3-a456-556642440005"}},"paymentId":"123e4567-e89b-42d3-a456-556642440005","transactionStatus":"ACTC"}`)(w, r, body)
	}
	f.h["GET "+pisPath+"/123e4567-e89b-42d3-a456-556642440005/status"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		reply(200, `{"transactionStatus":"`+status+`","fundsAvailable":"true"}`)(w, r, body)
	}
	f.h["DELETE "+pisPath+"/123e4567-e89b-42d3-a456-556642440005"] = reply(202, `{"_links":{"scaRedirect":{"href":"https://bankieren.rabobank.nl/klanten?paymentinitiationid=123e4567-e89b-42d3-a456-556642440005&flow=delete"}},"transactionStatus":"ACSP"}`)
	c := newTestClient(t, srv, key)

	st, err := c.InitiatePayment(context.Background(), docPayment())
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Payment == nil || st.Payment.Status != obsdk.PaymentReceived || !strings.Contains(st.Redirect.URL, "paymentinitiationid=") {
		t.Fatalf("unexpected first step %+v", st)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Payment.Status != obsdk.PaymentInProgress || done.Payment.BankStatus != "ACSP" {
		t.Fatalf("unexpected final step %+v", done.Payment)
	}

	status = "ACTC"
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("an unsigned payment should fail authorisation, got %v", err)
	}

	cs, err := c.CancelPayment(context.Background(), done.Payment.Ref, obsdk.PaymentCallOptions{PSU: &obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if cs.Kind != obsdk.StepRedirect || !strings.Contains(cs.Redirect.URL, "flow=delete") {
		t.Fatalf("a cancellation that needs signing should redirect, got %+v", cs)
	}
	status = "CANC"
	cd, err := c.Resume(context.Background(), cs.State, obsdk.StepInput{Callback: "https://example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if cd.Payment.Status != obsdk.PaymentCancelled || !cd.Payment.Final {
		t.Fatalf("unexpected cancellation result %+v", cd.Payment)
	}
}

func TestPaymentErrors(t *testing.T) {
	key := rsaKey(t)
	f, srv := newFake(t, key)
	c := newTestClient(t, srv, key)

	f.h["POST "+pisPath] = reply(400, `{"tppMessages":[{"category":"ERROR","code":"FORMAT_ERROR","path":"sepaCreditTransfer.creditorAccount.iban","text":"The IBAN format is invalid."}],"transactionStatus":"RJCT"}`)
	_, err := c.InitiatePayment(context.Background(), docPayment())
	var ae *obsdk.APIError
	if !errors.As(err, &ae) || ae.Code != "FORMAT_ERROR" || errors.Is(err, obsdk.ErrPaymentRejected) {
		t.Fatalf("a format error is the request's fault, not a rejection: %v", err)
	}
	f.h["POST "+pisPath] = reply(400, `{"tppMessages":[{"category":"ERROR","code":"PAYMENT_FAILED","text":"Payment failed"}],"transactionStatus":"RJCT"}`)
	if _, err := c.InitiatePayment(context.Background(), docPayment()); !errors.Is(err, obsdk.ErrPaymentRejected) {
		t.Fatalf("want a rejection, got %v", err)
	}

	r := docPayment()
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}
	if _, err := c.InitiatePayment(context.Background(), r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("description and reference together should be refused, got %v", err)
	}
	r = docPayment()
	r.PSU.IP = ""
	if _, err := c.InitiatePayment(context.Background(), r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("a payment without the user's IP should be refused, got %v", err)
	}
}

func TestCrossBorderBody(t *testing.T) {
	r := obsdk.PaymentRequest{
		Type: obsdk.PaymentCrossBorder, ChargeBearer: obsdk.ChargeBearerDebtor,
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "NL82RABO1108003001"}},
		Transfers: []obsdk.Transfer{{
			Amount: obsdk.Money{Amount: "10.25", Currency: "USD"},
			Creditor: obsdk.Creditor{Name: "Company", Account: obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "02100002112345678901234567"},
				Agent:   &obsdk.Agent{BIC: "BANKUS33XXX", ClearingSystem: "USABA", MemberID: "026009593"},
				Address: &obsdk.PostalAddress{Street: "5th Ave", BuildingNumber: "8C", PostCode: "5017", Town: "New York", Country: "US"}},
		}},
	}
	b, err := buildBody(r)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(b)
	want := `{"chargeBearer":"DEBT","clearingSystem":{"code":"USABA","value":"026009593"},"creditorAccount":{"currency":"USD","bban":"02100002112345678901234567"},"creditorAddress":{"buildingNumber":"8C","country":"US","postcode":"5017","streetName":"5th Ave","townName":"New York"},"creditorAgent":"BANKUS33XXX","creditorName":"Company","debtorAccount":{"iban":"NL82RABO1108003001"},"instructedAmount":{"content":"10.25","currency":"USD"}}`
	if string(got) != want {
		t.Fatalf("cross-border body:\n got %s\nwant %s", got, want)
	}
	info, _ := obsdk.Lookup(bankKey)
	spec, _ := info.PaymentSpec("NL", obsdk.Personal, obsdk.PaymentCrossBorder)
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatalf("valid cross-border request refused: %v", err)
	}
	r.ChargeBearer = ""
	if err := spec.Validate(r, frozen); err == nil {
		t.Fatal("cross-border payments need a charge bearer")
	}
}

func TestTokenConsentID(t *testing.T) {
	for in, want := range map[string]string{
		"a:consentId 123a1a2a-888c-4015-8099-f88b080d0bbb": "123a1a2a-888c-4015-8099-f88b080d0bbb",
		"": "", "a:consentId": "",
	} {
		if got := (&tokenResponse{Metadata: in}).consentID(); got != want {
			t.Errorf("consentID(%q) = %q, want %q", in, got, want)
		}
	}
}
