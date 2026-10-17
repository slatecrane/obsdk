package bunq

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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

var frozen = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// fakeBunq is a small stand-in for bunq's API and OAuth token endpoint.
type fakeBunq struct {
	t  *testing.T
	mu sync.Mutex

	installs     int
	sessions     int
	sessionToken string
	refuseOld    bool   // session-server refuses the first installation's token (403)
	refuseSecret bool   // session-server says the credentials are incorrect
	draftStatus  string // what GET draft-payment returns
	payments     []string
	seen         []string
	lastToken    url.Values
	lastDraft    map[string]any
}

func (f *fakeBunq) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if len(body) > 0 && r.URL.Path != "/oauth/token" {
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Bunq-Client-Signature"))
		sum := sha256.Sum256(body)
		if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			f.t.Errorf("%s %s: bad body signature: %v", r.Method, r.URL.Path, err)
		}
	}
	for _, h := range []string{"Cache-Control", "User-Agent", "X-Bunq-Client-Request-Id", "X-Bunq-Geolocation", "X-Bunq-Language", "X-Bunq-Region"} {
		if r.URL.Path != "/oauth/token" && r.Header.Get(h) == "" {
			f.t.Errorf("%s %s: missing %s", r.Method, r.URL.Path, h)
		}
	}
	reply := func(status int, v string) {
		w.Header().Set("X-Bunq-Client-Response-Id", "resp-1")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, v)
	}
	auth := r.Header.Get("X-Bunq-Client-Authentication")
	switch p := r.URL.Path; {
	case p == "/oauth/token":
		f.lastToken = r.URL.Query()
		if len(body) > 0 {
			f.t.Errorf("token exchange sent a body; bunq reads the query only")
		}
		if r.URL.Query().Get("code") != "good-code" {
			reply(400, `{"Error":[{"error_description":"Invalid hash \"bad\"."}]}`)
			return
		}
		reply(200, `{"access_token":"oauth-access","token_type":"bearer","state":"x"}`)
	case p == "/v1/installation":
		f.installs++
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		if !strings.Contains(in["client_public_key"], "BEGIN PUBLIC KEY") {
			f.t.Errorf("installation without a PEM public key: %q", in["client_public_key"])
		}
		reply(200, fmt.Sprintf(`{"Response":[{"Id":{"id":1}},{"Token":{"id":2,"token":"install-%d"}},{"ServerPublicKey":{"server_public_key":"x"}}]}`, f.installs))
	case p == "/v1/device-server":
		if !strings.HasPrefix(auth, "install-") {
			f.t.Errorf("device-server authenticated with %q", auth)
		}
		reply(200, `{"Response":[{"Id":{"id":3}}]}`)
	case p == "/v1/session-server":
		if f.refuseSecret {
			reply(400, `{"Error":[{"error_description":"User credentials are incorrect. Incorrect API key or IP address."}]}`)
			return
		}
		if f.refuseOld && auth == "install-1" {
			reply(403, `{"Error":[{"error_description":"Insufficient authentication."}]}`)
			return
		}
		f.sessions++
		f.sessionToken = fmt.Sprintf("session-%d", f.sessions)
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		if in["secret"] == "oauth-access" {
			reply(200, `{"Response":[{"Id":{"id":77}},{"Token":{"id":77,"token":"`+f.sessionToken+`"}},{"UserApiKey":{"id":555,
				"requested_by_user":{"UserPaymentServiceProvider":{"id":9,"session_timeout":324000}},
				"granted_by_user":{"UserCompany":{"id":42,"session_timeout":604800}}}}]}`)
			return
		}
		reply(200, `{"Response":[{"Id":{"id":77}},{"Token":{"id":77,"token":"`+f.sessionToken+`"}},{"UserPerson":{"id":42,"session_timeout":3600}}]}`)
	case auth != f.sessionToken:
		reply(403, `{"Error":[{"error_description":"Insufficient authentication."}]}`)
	case r.Method == "DELETE" && strings.HasPrefix(p, "/v1/session/"):
		reply(200, `{"Response":[]}`)
	case p == "/v1/user/42/monetary-account" || p == "/v1/user/555/monetary-account":
		user := strings.Split(p, "/")[3]
		reply(200, `{"Response":[{"MonetaryAccountBank":{"id":100,"updated":"2026-10-16 23:30:00.000000","description":"Main","currency":"EUR","display_name":"A. Tester",
			"balance":{"value":"12.34","currency":"EUR"},"overdraft_limit":{"value":"0.00","currency":"EUR"},
			"alias":[{"type":"EMAIL","value":"a@example.com","name":"a"},{"type":"IBAN","value":"NL98BUNQ2107727112","name":"A. Tester"}]}},
			{"MonetaryAccountSavings":{"id":101,"description":"Pot","currency":"EUR","balance":{"value":"1.00","currency":"EUR"},
			"alias":[{"type":"IBAN","value":"NL48BUNQ2107732086","name":"A. Tester"}]}}],
			"Pagination":{"older_url":null,"newer_url":null,"future_url":"/v1/user/`+user+`/monetary-account?newer_id=101"}}`)
	case p == "/v1/user/42/monetary-account/100/payment":
		older := r.URL.Query().Get("older_id")
		switch older {
		case "":
			reply(200, `{"Response":[
				{"Payment":{"id":5,"created":"2026-10-12 08:00:00.000000","amount":{"value":"-1.00","currency":"EUR"},"description":"too new","type":"BUNQ","sub_type":"PAYMENT","counterparty_alias":{"display_name":"X"}}},
				{"Payment":{"id":4,"created":"2026-10-09 22:30:00.000000","amount":{"value":"-2.50","currency":"EUR"},"description":" invoice 42 ","type":"EBA_SCT","sub_type":"SCT",
				 "counterparty_alias":{"iban":"NL14RABO0169202917","display_name":"Peter"},"balance_after_mutation":{"value":"9.84","currency":"EUR"}}}],
				"Pagination":{"older_url":"/v1/user/42/monetary-account/100/payment?count=2&older_id=4","newer_url":null}}`)
		case "4":
			reply(200, `{"Response":[
				{"Payment":{"id":3,"created":"2026-10-05 10:00:00.000000","amount":{"value":"100.00","currency":"EUR"},"type":"BUNQ","sub_type":"REQUEST","counterparty_alias":{"display_name":"Sugar Daddy"}}},
				{"Payment":{"id":2,"created":"2026-09-01 10:00:00.000000","amount":{"value":"1.00","currency":"EUR"},"type":"BUNQ","sub_type":"PAYMENT"}}],
				"Pagination":{"older_url":"/v1/user/42/monetary-account/100/payment?count=2&older_id=2"}}`)
		default:
			f.t.Errorf("paged past From: older_id=%s", older)
		}
	case p == "/v1/user/42/monetary-account/100/draft-payment" && r.Method == "POST":
		_ = json.Unmarshal(body, &f.lastDraft)
		reply(200, `{"Response":[{"Id":{"id":9046}}]}`)
	case p == "/v1/user/42/monetary-account/100/draft-payment/9046":
		if r.Method == "PUT" {
			var in map[string]string
			_ = json.Unmarshal(body, &in)
			if in["status"] != "REJECTED" || in["previous_updated_timestamp"] != "2026-10-17 10:00:00.000000" {
				f.t.Errorf("cancel sent %v", in)
			}
			f.draftStatus = "REJECTED"
			reply(200, `{"Response":[{"Id":{"id":9046}}]}`)
			return
		}
		obj := "null"
		if f.draftStatus == "ACCEPTED" {
			obj = `{"Payment":{"id":35930411}}`
		}
		reply(200, `{"Response":[{"DraftPayment":{"id":9046,"status":"`+f.draftStatus+`","updated":"2026-10-17 10:00:00.000000",
			"entries":[{"alias":{"iban":"NL98BUNQ2107727112"}}],"object":`+obj+`}}]}`)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, p)
		reply(404, `{"Error":[{"error_description":"Route not found."}]}`)
	}
}

func newFake(t *testing.T) (*fakeBunq, *client) {
	t.Helper()
	f := &fakeBunq{t: t, draftStatus: "PENDING"}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "csecret", RedirectURL: "http://localhost/cb"},
		HTTPClient:  srv.Client(),
		Seal:        &obsdk.Seal{Key: testKey},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra: map[string]string{
			paramBaseURL: srv.URL + "/v1", paramAuthURL: "https://oauth.example/auth", paramTokenURL: srv.URL + "/oauth/token",
		},
	}
	c, err := obsdk.New(obsdk.Target{Bank: "bunq", Country: "NL"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f, c.(*client)
}

func connectKey(t *testing.T, c *client) *obsdk.Session {
	t.Helper()
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{Method: methodAPIKey, Values: map[string]string{fieldAPIKey: "sandbox_key"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepDone || st.Session == nil {
		t.Fatalf("api_key with a pre-filled key should finish at once, got %s", st.Kind)
	}
	return st.Session
}

func TestOAuthRedirectFlow(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	st, err := c.Connect(ctx, obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.Redirect.URL)
	if u.Host != "oauth.example" || u.Query().Get("client_id") != "cid" || u.Query().Get("state") != "state-1" ||
		u.Query().Get("redirect_uri") != "http://localhost/cb" || u.Query().Get("response_type") != "code" {
		t.Fatalf("auth URL: %s", st.Redirect.URL)
	}
	if _, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "http://localhost/cb?code=good-code&state=other"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: %v", err)
	}
	if _, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "http://localhost/cb?code=bad&state=state-1"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("refused code: %v", err)
	}
	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "http://localhost/cb?code=good-code&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	if q := f.lastToken; q.Get("grant_type") != "authorization_code" || q.Get("client_secret") != "csecret" || q.Get("redirect_uri") != "http://localhost/cb" {
		t.Fatalf("token exchange query: %v", q)
	}
	s := done.Session
	if s.RefreshToken != "oauth-access" || s.AccessToken != "session-1" || s.Meta[metaUserID] != "555" || s.Meta[metaGrantedBy] != "UserCompany" {
		t.Fatalf("session: %+v", s)
	}
	// The shorter of the app's (324000 s) and the user's (604800 s) timeouts.
	if want := frozen.Add(324000 * time.Second); !s.AccessExpiresAt.Equal(want) {
		t.Fatalf("access expires %v, want %v", s.AccessExpiresAt, want)
	}
	cons := s.Consents["oauth"]
	if cons.ID != "555" || len(cons.Accounts) != 2 {
		t.Fatalf("consent: %+v", cons)
	}
	if len(done.Accounts) != 2 || done.Accounts[0].Usage != "ORGA" {
		t.Fatalf("accounts: %+v", done.Accounts)
	}
}

func TestAPIKeyInputStep(t *testing.T) {
	_, c := newFake(t)
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{Method: methodAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepInputRequired || st.Fields[0].Key != fieldAPIKey || st.Fields[0].Kind != obsdk.FieldSecret {
		t.Fatalf("step: %+v", st)
	}
	if strings.Contains(st.State, "sandbox_key") {
		t.Fatal("the key must not be in the state")
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Values: map[string]string{fieldAPIKey: " sandbox_key "}})
	if err != nil {
		t.Fatal(err)
	}
	if done.Session.RefreshToken != "sandbox_key" || done.Session.Meta[metaUserType] != "UserPerson" {
		t.Fatalf("session: %+v", done.Session)
	}
}

func TestConnectRefusedKey(t *testing.T) {
	f, c := newFake(t)
	f.refuseSecret = true
	_, err := c.Connect(context.Background(), obsdk.ConnectRequest{Method: methodAPIKey, Values: map[string]string{fieldAPIKey: "nope"}})
	if !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestAccountsAndBalances(t *testing.T) {
	_, c := newFake(t)
	s := connectKey(t, c)
	res, err := c.Accounts(context.Background(), s, obsdk.CallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a := res.Data[0]
	if a.ID != "100" || a.Identifiers[0].Value != "NL98BUNQ2107727112" || a.Type != "CACC" || a.Product != "Bank" ||
		a.BIC != bunqBIC || a.Usage != "PRIV" || a.CreditLimit != nil || a.Name != "Main" {
		t.Fatalf("account: %+v", a)
	}
	// Updated 23:30 UTC is the next day in Amsterdam.
	if b := a.Balances[0]; b.Kind != obsdk.BalanceInterimAvailable || b.Amount.Amount != "12.34" || b.ReferenceDate != "2026-10-17" {
		t.Fatalf("balance: %+v", b)
	}
	if res.Data[1].Type != "SVGS" {
		t.Fatalf("savings: %+v", res.Data[1])
	}
	if _, err := c.Balances(context.Background(), s, "../100", obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("bad id: %v", err)
	}
}

func TestTransactionsWindowAndCursor(t *testing.T) {
	_, c := newFake(t)
	s := connectKey(t, c)
	ctx := context.Background()
	q := obsdk.TxQuery{AccountID: "100", From: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC), PageSize: 2}
	p1, err := c.Transactions(ctx, s, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Transactions) != 1 || p1.NextCursor == "" {
		t.Fatalf("page 1: %+v", p1.TxPage)
	}
	tx := p1.Transactions[0]
	if tx.ID != "4" || tx.Direction != obsdk.Debit || tx.Amount.Amount != "-2.50" || tx.BookingDate != "2026-10-10" ||
		tx.Counterparty.Identifiers[0].Value != "NL14RABO0169202917" || tx.Remittance[0] != "invoice 42" ||
		tx.BalanceAfter.Amount != "9.84" || tx.BankCode != "EBA_SCT" {
		t.Fatalf("transaction: %+v", tx)
	}
	// The cursor carries the window: the caller need not repeat it.
	p2, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "100", Cursor: p1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Transactions) != 1 || p2.Transactions[0].ID != "3" || p2.NextCursor != "" {
		t.Fatalf("page 2 should stop at the first payment before From: %+v", p2.TxPage)
	}
	if p2.Transactions[0].Direction != obsdk.Credit {
		t.Fatal("incoming payment should be a credit")
	}
}

func TestTransactionsRejectsForeignCursor(t *testing.T) {
	_, c := newFake(t)
	s := connectKey(t, c)
	for _, link := range []string{"https://evil.example/v1/user/42/monetary-account/100/payment?older_id=1", "/v1/user/42/monetary-account/101/payment?older_id=1", "/v1/user/7/oauth-client"} {
		cur, _ := flowstate.Encode(txCursor{URL: link})
		if _, err := c.Transactions(context.Background(), s, obsdk.TxQuery{AccountID: "100", Cursor: cur}); !errors.Is(err, obsdk.ErrInvalidRequest) {
			t.Errorf("%s: %v", link, err)
		}
	}
	if _, err := c.Transactions(context.Background(), s, obsdk.TxQuery{AccountID: "100", Status: []obsdk.TxStatus{obsdk.TxPending}}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Errorf("pending: %v", err)
	}
}

func TestExpiredSessionAndRefresh(t *testing.T) {
	f, c := newFake(t)
	s := connectKey(t, c)
	ctx := context.Background()
	// bunq answers a dead session token with 403 "Insufficient authentication."
	stale := s.Clone()
	stale.AccessToken = "session-0"
	if _, err := c.Accounts(ctx, stale, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Fatalf("dead token: %v", err)
	}
	// A refused installation token leads to a new installation, not a new login.
	f.refuseOld = true
	ns, err := c.Refresh(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if f.installs != 2 || ns.Meta[metaInstallation] != "install-2" || ns.AccessToken != f.sessionToken || ns.Generation <= s.Generation {
		t.Fatalf("installs=%d session=%+v", f.installs, ns)
	}
	// A refused secret means logging in again.
	f.refuseSecret = true
	_, err = c.Refresh(ctx, ns)
	var re *obsdk.RefreshError
	if !errors.As(err, &re) || re.Temporary || !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Fatalf("refused secret: %v", err)
	}
}

func TestDisconnect(t *testing.T) {
	f, c := newFake(t)
	s := connectKey(t, c)
	res, err := c.Disconnect(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Session.AccessToken != "" || res.Session.RefreshToken != "" || res.Failed[methodAPIKey] == "" {
		t.Fatalf("disconnect: %+v", res)
	}
	if last := f.seen[len(f.seen)-1]; last != "DELETE /v1/session/77" {
		t.Fatalf("last call %s", last)
	}
}

func payment(debtor string) obsdk.PaymentRequest {
	return obsdk.PaymentRequest{
		Type:   obsdk.PaymentSEPA,
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: debtor}},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "4.20", Currency: "EUR"}, Remittance: []string{"obsdk test"},
			Creditor: obsdk.Creditor{Name: "Peter Example", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "NL14RABO0169202917"}}}},
	}
}

func TestPaymentApprovedInApp(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	r := payment("NL98BUNQ2107727112")
	if _, err := c.InitiatePayment(ctx, r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("no session: %v", err)
	}
	r.Session = connectKey(t, c)
	st, err := c.InitiatePayment(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepWait || !st.NeedsUser || st.Payment.Status != obsdk.PaymentReceived || st.Payment.ID != "9046" {
		t.Fatalf("step: %+v", st)
	}
	e := f.lastDraft["entries"].([]any)[0].(map[string]any)
	if ca := e["counterparty_alias"].(map[string]any); ca["value"] != "NL14RABO0169202917" || ca["name"] != "Peter Example" || ca["type"] != "IBAN" {
		t.Fatalf("draft entry: %v", e)
	}
	if strings.Contains(st.State, "sandbox_key") {
		t.Fatal("the long-lived key must not be in the payment state")
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{})
	if err != nil || st.Kind != obsdk.StepWait {
		t.Fatalf("still pending: %v %+v", err, st)
	}
	f.draftStatus = "ACCEPTED"
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{})
	if err != nil {
		t.Fatal(err)
	}
	if p := st.Payment; st.Kind != obsdk.StepDone || p.Status != obsdk.PaymentCompleted || !p.Final || p.Debtor.Value != "NL98BUNQ2107727112" {
		t.Fatalf("done: %+v", st.Payment)
	}
}

func TestPaymentRejectedAndCancel(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	s := connectKey(t, c)
	r := payment("NL91ABNA0417164300") // valid, but not one of the user's accounts
	r.Session = s
	var ve *obsdk.PaymentValidationError
	if _, err := c.InitiatePayment(ctx, r); !errors.As(err, &ve) || ve.Issues[0].Path != obsdk.FieldDebtorAccount || ve.Issues[0].Code != obsdk.IssueInvalid {
		t.Fatalf("debtor outside the session's accounts: %v", err)
	}
	r = payment("NL98BUNQ2107727112")
	r.Session = s
	st, err := c.InitiatePayment(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	ref := st.Payment.Ref
	done, err := c.CancelPayment(ctx, ref, obsdk.PaymentCallOptions{Session: s})
	if err != nil {
		t.Fatal(err)
	}
	if done.Payment.Status != obsdk.PaymentCancelled || done.Payment.BankStatus != "REJECTED" {
		t.Fatalf("cancel: %+v", done.Payment)
	}
	if _, err := c.CancelPayment(ctx, ref, obsdk.PaymentCallOptions{Session: s}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("second cancel: %v", err)
	}
	// Resuming the original wait now sees the rejection.
	_, err = c.Resume(ctx, st.State, obsdk.StepInput{})
	var fe *obsdk.FlowError
	if !errors.As(err, &fe) || fe.Payment == nil || fe.Payment.Status != obsdk.PaymentRejected || !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("rejected: %v", err)
	}
	if f.draftStatus != "REJECTED" {
		t.Fatal("cancel should have rejected the draft")
	}
	other := s.Clone()
	other.Meta[metaUserID] = "43"
	if _, err := c.PaymentStatus(ctx, ref, obsdk.PaymentCallOptions{Session: other}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("other user's session: %v", err)
	}
}

func TestRateLimitHint(t *testing.T) {
	_, c := newFake(t)
	r := &resp{status: 429, header: http.Header{}, body: []byte(`{"Error":[{"error_description":"Too many requests. You can do a maximum of 2 calls per 3 second to this endpoint."}]}`)}
	var rl *obsdk.RateLimitedError
	if err := c.apiErr(opAccounts, r); !errors.As(err, &rl) || rl.RetryAfter != 3*time.Second {
		t.Fatalf("got %v", err)
	}
}

func TestPaymentRefusalMapping(t *testing.T) {
	err := paymentErr(&obsdk.APIError{Status: 400, Text: "Account doesn't have enough money to complete the payment."})
	var pr *obsdk.PaymentRejectedError
	if !errors.As(err, &pr) || pr.Reason != "insufficient_funds" {
		t.Fatalf("got %v", err)
	}
}
