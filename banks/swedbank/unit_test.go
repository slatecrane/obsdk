package swedbank

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// Pure-function tests: no HTTP, no registry, no fixtures.

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := expiry(now, 3600); got == nil || !got.Equal(now.Add(time.Hour)) {
		t.Errorf("seconds: %v", got)
	}
	if got := expiry(now, 0); got != nil {
		t.Errorf("zero: %v", got)
	}
	if got := expiry(now, 1.8e9); got == nil || got.Unix() != 1800000000 {
		t.Errorf("absolute time: %v", got)
	}
}

func TestParseTPP(t *testing.T) {
	cases := map[string]int{
		`{"tppMessages":[{"code":"A"},{"code":"B"}]}`: 2,
		`{"tppMessages":{"code":"A"}}`:                1,
		`{"tppMessages":"oops"}`:                      0,
		`{}`:                                          0,
		`not json`:                                    0,
	}
	for body, want := range cases {
		if got := parseTPP([]byte(body)); len(got) != want {
			t.Errorf("%s: %d messages, want %d", body, len(got), want)
		}
	}
}

func TestAPIErrClassification(t *testing.T) {
	body := func(code string) []byte {
		return []byte(fmt.Sprintf(`{"tppMessages":[{"category":"ERROR","code":%q,"text":"x"}]}`, code))
	}
	c := &client{}
	h := http.Header{}
	h.Set("Retry-After", "7")
	tests := []struct {
		name string
		op   string
		r    *resp
		is   []error
		not  []error
	}{
		{"expired token", opAccounts, &resp{status: 401, body: body("TOKEN_INVALID")}, []error{obsdk.ErrAccessExpired}, []error{obsdk.ErrReauthRequired}},
		{"not posted in transactions", opTransactions, &resp{status: 401, body: body("RESOURCE_NOT_POSTED")}, nil, []error{obsdk.ErrReauthRequired}},
		{"not posted elsewhere is a plain error", opBalances, &resp{status: 401, body: body("RESOURCE_NOT_POSTED")}, nil, []error{obsdk.ErrAccessExpired}},
		{"consent expired", opAccounts, &resp{status: 403, body: body("CONSENT_EXPIRED")}, []error{obsdk.ErrReauthRequired}, nil},
		{"consent not found while polling", opConsent, &resp{status: 404, body: body("")}, []error{obsdk.ErrReauthRequired}, nil},
		{"404 elsewhere", opAccounts, &resp{status: 404, body: body("")}, nil, []error{obsdk.ErrReauthRequired}},
		{"rate limit", opAccounts, &resp{status: 429, header: h}, []error{obsdk.ErrRateLimited}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.r.header == nil {
				tt.r.header = http.Header{}
			}
			err := c.apiErr(tt.op, tt.r)
			for _, want := range tt.is {
				if !errors.Is(err, want) {
					t.Errorf("%v should match %v", err, want)
				}
			}
			for _, no := range tt.not {
				if errors.Is(err, no) {
					t.Errorf("%v should not match %v", err, no)
				}
			}
			var apiErr *obsdk.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != tt.r.status {
				t.Errorf("APIError not reachable or wrong status: %v", err)
			}
		})
	}
	var np *notPostedError
	if !asNotPosted(c.apiErr(opTransactions, &resp{status: 401, header: http.Header{}, body: body("RESOURCE_NOT_POSTED")}), &np) {
		t.Error("transactions RESOURCE_NOT_POSTED must be recognised as notPostedError")
	}
	var rl *obsdk.RateLimitedError
	if err := c.apiErr(opAccounts, &resp{status: 429, header: h}); !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Errorf("retry after: %v", err)
	}
}

func TestToTransaction(t *testing.T) {
	out, err := toTransaction(json.RawMessage(`{"transactionId":"1","bookingDate":"2026-01-02","transactionAmount":{"amount":"-12.50","currency":"SEK"},
		"creditorName":"Shop","creditorAccount":{"iban":"SE11"},"remittanceInformationUnstructured":"u","remittanceInformationStructured":"s"}`), obsdk.TxBooked)
	if err != nil {
		t.Fatal(err)
	}
	if out.Direction != obsdk.Debit || out.Counterparty.Name != "Shop" || len(out.Counterparty.Identifiers) != 1 || out.Amount.Amount != "-12.50" ||
		len(out.Remittance) != 2 || out.Remittance[0] != "u" || len(out.Raw) == 0 {
		t.Errorf("outgoing: %+v", out)
	}
	in, err := toTransaction(json.RawMessage(`{"transactionAmount":{"amount":"3","currency":"SEK"},"debtorName":"Boss","debtorAccount":{"bban":"123"}}`), obsdk.TxPending)
	if err != nil {
		t.Fatal(err)
	}
	if in.Direction != obsdk.Credit || in.Counterparty.Name != "Boss" || in.Counterparty.Identifiers[0].Scheme != "BBAN" || in.Status != obsdk.TxPending {
		t.Errorf("incoming: %+v", in)
	}
	if _, err := toTransaction(json.RawMessage(`[1]`), obsdk.TxBooked); err == nil {
		t.Error("garbage must fail")
	}
}

func TestParseTransactionsCursor(t *testing.T) {
	p, err := parseTransactions([]byte(`{"_links":{"nextPage":{"href":"/accounts/a/transactions?x=1&pageId=NEXT"}},"transactions":{"booked":[{"transactionId":"a","transactionAmount":{"amount":"1","currency":"SEK"}}]}}`))
	if err != nil || p.NextCursor != "NEXT" || len(p.Transactions) != 1 {
		t.Fatalf("%v %+v", err, p)
	}
	if _, err := parseTransactions([]byte(`nope`)); err == nil {
		t.Error("garbage must fail")
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseStatementArchive(t *testing.T) {
	one := func(id string) string {
		return fmt.Sprintf(`{"transactions":{"booked":[{"transactionId":%q,"transactionAmount":{"amount":"1","currency":"SEK"}}]}}`, id)
	}
	page, err := parseStatementArchive(zipOf(t, map[string]string{"b.json": one("B"), "a.json": one("A")}))
	if err != nil || len(page.Transactions) != 2 || page.Transactions[0].ID != "A" {
		t.Fatalf("files are merged in name order: %v %+v", err, page.Transactions)
	}
	if page, err = parseStatementArchive([]byte(one("P"))); err != nil || len(page.Transactions) != 1 {
		t.Errorf("plain JSON accepted: %v", err)
	}
	if _, err = parseStatementArchive([]byte("junk")); err == nil {
		t.Error("junk must fail")
	}
	many := map[string]string{}
	for i := 0; i <= maxStatementFiles; i++ {
		many[fmt.Sprintf("f%04d.json", i)] = one("x")
	}
	if _, err = parseStatementArchive(zipOf(t, many)); err == nil || !strings.Contains(err.Error(), "files") {
		t.Errorf("file count cap: %v", err)
	}
	old := maxStatementBytes
	maxStatementBytes = 1 << 10
	defer func() { maxStatementBytes = old }()
	big := `{"transactions":{"booked":[]},"pad":"` + strings.Repeat("a", 2<<10) + `"}`
	if _, err = parseStatementArchive(zipOf(t, map[string]string{"big.json": big})); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("size cap: %v", err)
	}
}

func TestBookingStatus(t *testing.T) {
	cases := []struct {
		in   []obsdk.TxStatus
		want string
	}{
		{nil, "booked"},
		{[]obsdk.TxStatus{obsdk.TxBooked}, "booked"},
		{[]obsdk.TxStatus{obsdk.TxPending}, "pending"},
		{[]obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}, "both"},
	}
	for _, c := range cases {
		if got := bookingStatus(c.in); got != c.want {
			t.Errorf("%v: %s, want %s", c.in, got, c.want)
		}
	}
}

func TestRefsAndAccountRef(t *testing.T) {
	r := refs([]string{"SE123", "1234567"})
	if r[0]["iban"] != "SE123" || r[1]["bban"] != "1234567" {
		t.Errorf("refs = %v", r)
	}
	a := obsdk.Account{Identifiers: []obsdk.Identifier{{Scheme: "BBAN", Value: "B"}, {Scheme: "IBAN", Value: "I"}}}
	if accountRef(a) != "I" {
		t.Error("IBAN preferred over BBAN")
	}
	a.Identifiers = a.Identifiers[:1]
	if accountRef(a) != "B" || accountRef(obsdk.Account{}) != "" {
		t.Error("BBAN fallback / empty")
	}
}

// doerFunc is a hand-written HTTPDoer: the cheapest way to unit-test a method
// without any fixture files.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func reply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func newTestClient(t *testing.T, d obsdk.HTTPDoer) obsdk.Client {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, err := obsdk.New(obsdk.Target{Bank: "swedbank", Country: "SE"}, obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "shh", RedirectURL: "https://app.example/cb"},
		HTTPClient:  d,
		Now:         func() time.Time { return now },
		NewID:       func(string) string { return "fixed-id" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testSession() *obsdk.Session {
	exp := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	return &obsdk.Session{Version: 1, Bank: "swedbank", Country: "SE", Segment: obsdk.Personal, Env: obsdk.Sandbox, Integration: integrationID, AccessToken: "TOK", AccessExpiresAt: &exp,
		Consents: map[string]obsdk.Consent{"detailed": {ID: "C1"}}}
}

func TestAccountsRequestShape(t *testing.T) {
	var got *http.Request
	c := newTestClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		got = r
		return reply(200, `{"accounts":[{"resourceId":"a1","iban":"SE1","currency":"SEK"}]}`), nil
	}))
	res, err := c.Accounts(context.Background(), testSession(), obsdk.CallOptions{PSU: &obsdk.PSUContext{IP: "198.51.100.1", UserAgent: "ua"}})
	if err != nil || len(res.Data) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	if got.URL.Path != "/sandbox/v5/accounts" || got.Header.Get("Authorization") != "Bearer TOK" || got.Header.Get("Consent-ID") != "C1" ||
		got.Header.Get("X-Request-ID") != "fixed-id" || got.Header.Get("PSU-IP-Address") != "198.51.100.1" || got.URL.Query().Get("app-id") != "cid" {
		t.Errorf("request = %s %v %v", got.URL, got.Header, got.URL.Query())
	}
}

func TestAccountsTransportError(t *testing.T) {
	boom := errors.New("connection reset")
	c := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return nil, boom }))
	if _, err := c.Accounts(context.Background(), testSession(), obsdk.CallOptions{}); !errors.Is(err, boom) {
		t.Errorf("transport error must be wrapped, not replaced: %v", err)
	}
}

func TestAccountsRefusesExpiredToken(t *testing.T) {
	called := false
	c := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) { called = true; return reply(200, `{}`), nil }))
	s := testSession()
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.AccessExpiresAt = &past
	if _, err := c.Accounts(context.Background(), s, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) || called {
		t.Errorf("err=%v called=%t", err, called)
	}
}
