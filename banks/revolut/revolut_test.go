package revolut

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestClient(t *testing.T, srv *httptest.Server, key *rsa.PrivateKey) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", RedirectURL: "https://app.example/cb"},
		HTTPClient:  srv.Client(),
		Extra:       map[string]string{paramBaseURL: srv.URL},
		Seal:        &obsdk.Seal{Key: key, KeyID: "kid-1"},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
	}
	c, err := obsdk.New(obsdk.Target{Bank: "revolut", Country: "GB"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func session() *obsdk.Session {
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "GB", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "at", RefreshToken: "rt",
		Consents: map[string]obsdk.Consent{consentKind: {ID: "consent-1", Kind: consentKind}}}
}

func TestRequiresSealAndTransport(t *testing.T) {
	_, err := obsdk.New(obsdk.Target{Bank: "revolut", Country: "GB"}, obsdk.Config{
		Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "cid", RedirectURL: "https://x"}})
	var ce *obsdk.ConfigError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "tls_client_cert") || !strings.Contains(err.Error(), "seal") {
		t.Fatalf("want a config error naming tls_client_cert and seal, got %v", err)
	}
}

func TestToAccount(t *testing.T) {
	mk := func(ccy string) obsdk.Account {
		a, err := toAccount(json.RawMessage(`{"AccountId":"id-` + ccy + `","Currency":"` + ccy + `","AccountType":"Business",
			"AccountSubType":"Savings","Nickname":"Pot","Account":[{"SchemeName":"UK.OBIE.IBAN","Identification":"GB00REVO1","Name":"Ann"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	gbp, usd := mk("GBP"), mk("USD")
	if gbp.StableID == "" || gbp.StableID == usd.StableID {
		t.Fatalf("currency accounts sharing an IBAN need distinct stable ids: %q %q", gbp.StableID, usd.StableID)
	}
	if gbp.Identifiers[0] != (obsdk.Identifier{Scheme: "IBAN", Value: "GB00REVO1"}) || gbp.OwnerName != "Ann" ||
		gbp.Name != "Pot" || gbp.Type != "SVGS" || gbp.Usage != "ORGA" || gbp.Currency != "GBP" {
		t.Fatalf("unexpected mapping: %+v", gbp)
	}
}

func TestToBalance(t *testing.T) {
	b := toBalance(balanceJSON{CreditDebitIndicator: "Debit", Type: "InterimAvailable", DateTime: "2026-10-14T12:22:47.1Z",
		Amount: amountJSON{Amount: "12.50", Currency: "EUR"}})
	if b.Amount.Amount != "-12.50" || b.Kind != obsdk.BalanceInterimAvailable || b.ReferenceDate != "2026-10-14" {
		t.Fatalf("got %+v", b)
	}
	if z := toBalance(balanceJSON{CreditDebitIndicator: "Debit", Type: "Expected", Amount: amountJSON{Amount: "0.00"}}); z.Amount.Amount != "0.00" || z.Kind != obsdk.BalanceOther {
		t.Fatalf("zero debit balance: %+v", z)
	}
}

func TestToTransaction(t *testing.T) {
	debit, err := toTransaction(json.RawMessage(`{"AccountId":"a","TransactionId":"t1","CreditDebitIndicator":"Debit","Status":"Booked",
		"BookingDateTime":"2026-10-01T09:30:00.123Z","ValueDateTime":"2026-10-02T00:00:00Z","Amount":{"Amount":"4.20","Currency":"GBP"},
		"TransactionInformation":"Coffee","ProprietaryBankTransactionCode":{"Code":"CARD_PAYMENT","Issuer":"Revolut"},
		"SupplementaryData":{"StartedDate":"2026-09-30T22:00:00Z"},"Balance":{"CreditDebitIndicator":"Credit","Type":"InterimBooked","Amount":{"Amount":"95.80","Currency":"GBP"}},
		"MerchantDetails":{"MerchantName":"Cafe","MerchantCategoryCode":"5814"}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := obsdk.Transaction{ID: "t1", Status: obsdk.TxBooked, Direction: obsdk.Debit, Amount: obsdk.Money{Amount: "-4.20", Currency: "GBP"},
		BookingDate: "2026-10-01", ValueDate: "2026-10-02", TransactionDate: "2026-09-30", Counterparty: obsdk.Party{Name: "Cafe"},
		Remittance: []string{"Coffee"}, BankCode: "CARD_PAYMENT", MerchantCategory: "5814", BalanceAfter: &obsdk.Money{Amount: "95.80", Currency: "GBP"}}
	if debit.BalanceAfter == nil || *debit.BalanceAfter != *want.BalanceAfter {
		t.Fatalf("balance after: %+v", debit.BalanceAfter)
	}
	debit.Raw, debit.BalanceAfter, want.BalanceAfter = nil, nil, nil
	if fmt.Sprintf("%+v", debit) != fmt.Sprintf("%+v", want) {
		t.Fatalf("debit:\n got %+v\nwant %+v", debit, want)
	}

	credit, _ := toTransaction(json.RawMessage(`{"CreditDebitIndicator":"Credit","Status":"Pending","BookingDateTime":"2026-10-01T09:30:00Z",
		"Amount":{"Amount":"10","Currency":"EUR"},"DebtorAccount":{"SchemeName":"UK.OBIE.IBAN","Identification":"LT001","Name":"Bob"},
		"CreditorAccount":{"SchemeName":"UK.OBIE.IBAN","Identification":"GB002","Name":"Me"}}`))
	if credit.Status != obsdk.TxPending || credit.Direction != obsdk.Credit || credit.Amount.Amount != "10" ||
		credit.Counterparty.Name != "Bob" || credit.Counterparty.Identifiers[0].Value != "LT001" {
		t.Fatalf("credit: %+v", credit)
	}
}

func TestParseError(t *testing.T) {
	for body, want := range map[string]string{
		`{"Code":"400","Message":"Bad","Errors":[{"ErrorCode":"UK.OBIE.Field.Invalid","Message":"bad field"}]}`: "UK.OBIE.Field.Invalid|bad field",
		`{"error":"invalid_grant","error_description":"expired"}`:                                               "invalid_grant|expired",
		`{"code":9001,"message":"nope"}`:                                                                        "9001|nope",
		`not json`:                                                                                              "|not json",
	} {
		code, text := parseError([]byte(body))
		if got := code + "|" + text; got != want {
			t.Errorf("%s: got %q, want %q", body, got, want)
		}
	}
}

func TestRequestObject(t *testing.T) {
	key := testKey(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := newTestClient(t, srv, key)
	jwt, err := c.signRequestObject("consent-9", "https://app.example/cb", "st", "accounts")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("signature does not verify as PS256: %v", err)
	}
	var hdr map[string]string
	var claims requestObject
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(h, &hdr)
	_ = json.Unmarshal(p, &claims)
	if hdr["alg"] != "PS256" || hdr["kid"] != "kid-1" {
		t.Fatalf("header %v", hdr)
	}
	if claims.Claims.IDToken.Intent.Value != "consent-9" || claims.Aud != srv.URL || claims.State != "st" ||
		claims.ResponseType != "code id_token" || claims.Exp-claims.Nbf > 3600 || claims.Nbf != frozen.Unix() {
		t.Fatalf("claims %+v", claims)
	}
}

// fakeBank serves the token, consent and accounts endpoints for Connect/Resume.
func fakeBank(t *testing.T) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/token":
			_ = r.ParseForm()
			switch r.Form.Get("grant_type") {
			case "client_credentials":
				fmt.Fprint(w, `{"access_token":"cc","token_type":"Bearer","expires_in":2399}`)
			case "authorization_code":
				if r.Form.Get("code") != "good-code" {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"error":"invalid_grant","error_description":"bad code"}`)
					return
				}
				fmt.Fprint(w, `{"access_token":"at","token_type":"Bearer","expires_in":3599,"refresh_token":"rt","refresh_token_expires_at":1807000000}`)
			}
		case r.URL.Path == "/account-access-consents" && r.Method == http.MethodPost:
			if r.Header.Get("x-fapi-financial-id") != financialID || r.Header.Get("Authorization") != "Bearer cc" {
				t.Errorf("consent request headers: %v", r.Header)
			}
			w.WriteHeader(201)
			fmt.Fprint(w, `{"Data":{"ConsentId":"consent-1","Status":"AwaitingAuthorisation"}}`)
		case r.URL.Path == "/accounts":
			fmt.Fprint(w, `{"Data":{"Account":[{"AccountId":"acc-1","Currency":"GBP","AccountType":"Personal","AccountSubType":"CurrentAccount"}]}}`)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestConnectResume(t *testing.T) {
	srv := fakeBank(t)
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t))
	ctx := context.Background()

	step, err := c.Connect(ctx, obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(step.Redirect.URL)
	if step.Kind != obsdk.StepRedirect || u.Query().Get("state") != "state-1" || u.Query().Get("request") == "" {
		t.Fatalf("redirect step: %+v", step)
	}

	if _, err := c.Resume(ctx, step.State, obsdk.StepInput{Callback: "https://app.example/cb?code=good-code&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: want ErrAuthFailed, got %v", err)
	}
	if _, err := c.Resume(ctx, step.State, obsdk.StepInput{Callback: "https://app.example/cb?error=access_denied&state=state-1"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("user refused: want ErrAuthFailed, got %v", err)
	}
	if _, err := c.Resume(ctx, step.State, obsdk.StepInput{Callback: "code=bad-code&state=state-1"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("rejected code: want ErrAuthFailed, got %v", err)
	}

	done, err := c.Resume(ctx, step.State, obsdk.StepInput{Callback: "https://app.example/cb?code=good-code&id_token=x&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	s := done.Session
	if done.Kind != obsdk.StepDone || len(done.Accounts) != 1 || s.AccessToken != "at" || s.RefreshToken != "rt" ||
		s.Consents[consentKind].ID != "consent-1" || !s.AccessExpiresAt.Equal(frozen.Add(3599*time.Second)) || s.RefreshExpiresAt.Unix() != 1807000000 {
		t.Fatalf("done step: %+v session %+v", done, s)
	}
}

func TestCursorMustPointAtRevolut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected, got %s", r.URL)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t))
	for _, cur := range []string{"https://evil.example/accounts/a/transactions", "/accounts/a/transactions", "rv1.!!"} {
		if _, err := c.Transactions(context.Background(), session(), obsdk.TxQuery{AccountID: "a", Cursor: cur}); !errors.Is(err, obsdk.ErrInvalidRequest) {
			t.Errorf("cursor %q: want ErrInvalidRequest, got %v", cur, err)
		}
	}
}

// TestPaging walks a bank that ignores links and returns at most pageSize
// transactions, newest first, below toBookingDateTime (exclusive, second
// precision). Three transactions share a second across a page boundary.
// (With more same-second transactions than fit on a page, the rest of that
// second is unreachable through this filter; see the cursor type.)
func TestPaging(t *testing.T) {
	type tx struct{ id, at string }
	all := []tx{ // newest first
		{"t1", "2026-10-05T10:00:00Z"},
		{"t2", "2026-10-04T08:00:00.700Z"},
		{"t3", "2026-10-04T08:00:00.300Z"},
		{"t4", "2026-10-04T08:00:00.100Z"},
		{"t5", "2026-10-03T07:00:00Z"},
	}
	const pageSize = 3
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		var to time.Time
		if v := r.URL.Query().Get("toBookingDateTime"); v != "" {
			to, _ = time.Parse(isoSecond, v)
		}
		var out []string
		for _, x := range all {
			at, _ := time.Parse(time.RFC3339Nano, x.at)
			if (to.IsZero() || at.Before(to)) && len(out) < pageSize {
				out = append(out, fmt.Sprintf(`{"TransactionId":%q,"CreditDebitIndicator":"Debit","Status":"Booked","BookingDateTime":%q,"Amount":{"Amount":"1","Currency":"GBP"}}`, x.id, x.at))
			}
		}
		fmt.Fprintf(w, `{"Data":{"Transaction":[%s]},"Links":{"Self":"x"},"Meta":{}}`, strings.Join(out, ","))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t))

	seen := map[string]int{}
	q := obsdk.TxQuery{AccountID: "a", From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	for i := 0; ; i++ {
		if i > 10 {
			t.Fatalf("paging did not end; queries: %v", queries)
		}
		res, err := c.Transactions(context.Background(), session(), q)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range res.Transactions {
			seen[x.ID]++
		}
		if res.NextCursor == "" {
			break
		}
		q.Cursor = res.NextCursor
	}
	var ids []string
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s returned %d times", id, n)
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != "t1,t2,t3,t4,t5" {
		t.Fatalf("got %v; queries: %v", ids, queries)
	}
	for _, qs := range queries {
		if !strings.Contains(qs, "fromBookingDateTime=2026-01-01T00%3A00%3A00Z") {
			t.Errorf("query lost the start date: %s", qs)
		}
	}
}

func TestLinksNextWins(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"Data":{"Transaction":[{"TransactionId":"p","CreditDebitIndicator":"Credit","Status":"Pending","BookingDateTime":"2026-10-04T08:00:00Z","Amount":{"Amount":"1","Currency":"GBP"}}]},"Links":{"Next":%q}}`,
			srv.URL+"/accounts/a/transactions?page=2")
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t))
	res, err := c.Transactions(context.Background(), session(), obsdk.TxQuery{AccountID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.NextCursor != srv.URL+"/accounts/a/transactions?page=2" {
		t.Fatalf("cursor %q", res.NextCursor)
	}
	if len(res.Transactions) != 0 {
		t.Fatalf("pending transactions must be filtered out by default: %+v", res.Transactions)
	}
}

func TestErrorClassification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts":
			w.WriteHeader(401)
			fmt.Fprint(w, `{"Code":"401","Errors":[{"ErrorCode":"UK.OBIE.Resource.Unauthorized","Message":"Access token is invalid or expired"}]}`)
		case "/token":
			w.WriteHeader(429)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t))
	if _, err := c.Accounts(context.Background(), session(), obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Fatalf("401 on data: want ErrAccessExpired, got %v", err)
	}
	_, err := c.Refresh(context.Background(), session())
	var re *obsdk.RefreshError
	if !errors.As(err, &re) || !re.Temporary || !errors.Is(err, obsdk.ErrRateLimited) {
		t.Fatalf("429 on refresh: want a temporary rate-limited RefreshError, got %v", err)
	}
}
