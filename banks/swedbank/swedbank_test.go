package swedbank_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	_ "github.com/slatecrane/obsdk/banks/swedbank"
)

var fixedNow = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// fake imitates the parts of Swedbank's API the SDK uses.
type fake struct {
	t  *testing.T
	mu sync.Mutex

	lastState      string
	rotateRefresh  bool
	pollCalls      int
	downloadCalls  int
	consentDecoupl bool // answer consents with the decoupled SCA approach
	consentsValid  bool // consents are valid immediately (extra scopes at login)
	consentBlocked bool // consents answer 401 SERVICE_BLOCKED (app not subscribed)
	multiBank      bool
	tokenStatus    int
	tokenN         int
	seen           []string
}

func (f *fake) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	q := r.URL.Query()
	f.seen = append(f.seen, r.Method+" "+p)
	switch {
	case p == "/psd2/authorize":
		f.lastState = q.Get("state")
		if q.Get("scope") != "PSD2sandbox" || q.Get("bic") != "SANDSESS" || q.Get("client_id") != "cid" {
			f.t.Errorf("bad authorize query: %v", q)
		}
		w.Header().Set("Location", "https://bank.example/login?session=1")
		w.WriteHeader(302)

	case p == "/psd2/token":
		f.tokenN++
		if f.tokenStatus != 0 {
			f.json(w, f.tokenStatus, map[string]any{"tppMessages": []map[string]string{{"category": "ERROR", "code": "TOKEN_ERROR", "text": "bad"}}})
			return
		}
		if q.Get("client_secret") != "shh" {
			f.t.Errorf("client_secret not sent")
		}
		w.Header().Set("login-method", "MOBILE_ID")
		resp := map[string]any{"access_token": fmt.Sprintf("AT%d", f.tokenN), "expires_in": 3600, "token_type": "Bearer", "scope": "PSD2sandbox"}
		if q.Get("grant_type") == "authorization_code" || f.rotateRefresh {
			resp["refresh_token"] = fmt.Sprintf("RT%d", f.tokenN)
		}
		f.json(w, 200, resp)

	case p == "/psd2/v5/available-authentication-methods":
		f.json(w, 200, map[string]any{"authenticationMethods": []map[string]string{{"authenticationMethodId": "MOBILE_ID", "authenticationType": "Mobile BankID"}}})

	case p == "/psd2/v5/authorize-decoupled" && r.Method == "POST":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["authenticationMethodId"] != "MOBILE_ID" || b["clientID"] != "cid" {
			f.t.Errorf("bad decoupled body: %v", b)
		}
		f.json(w, 201, map[string]any{
			"authorizeId": "A1", "psuMessage": "Login via TPP", "chosenScaMethod": map[string]string{"authenticationMethodId": "MOBILE_ID", "authenticationType": "Mobile BankID"},
			"_links":        map[string]any{"scaStatus": map[string]string{"href": "/psd2/v5/authorize-decoupled/authorize/A1"}},
			"challengeData": map[string]string{"autoStartToken": "tok-1"},
		})

	case p == "/psd2/v5/authorize-decoupled/authorize/A1" && r.Method == "GET":
		f.pollCalls++
		switch {
		case f.pollCalls == 1:
			f.json(w, 200, map[string]any{"scaStatus": "started"})
		case f.multiBank:
			f.json(w, 200, map[string]any{"scaStatus": "started", "tppMessages": map[string]string{"category": "ERROR", "code": "MISSING_BANK_ID", "text": "User must select bank"}})
		default:
			f.json(w, 200, map[string]any{"scaStatus": "finalised", "authorizationCode": "CODE-D"})
		}
	case p == "/psd2/v5/authorize-decoupled/authorize/A1" && r.Method == "PUT":
		var b struct{ PSUData struct{ BankID string } }
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.PSUData.BankID != "08999" {
			f.t.Errorf("bank id not forwarded: %+v", b)
		}
		f.json(w, 200, map[string]any{"scaStatus": "started", "authorizationCode": "CODE-D"})
	case p == "/psd2/available-bankids":
		f.json(w, 200, map[string]any{"availableBanks": []map[string]string{{"bankID": "08999", "name": "Swedbank"}, {"bankID": "08114", "name": "Savings Bank"}}})

	case p == "/sandbox/v5/consents" && r.Method == "POST":
		f.consent(w, r)
	case strings.HasSuffix(p, "/status") && strings.Contains(p, "/consents/"):
		f.json(w, 200, map[string]string{"consentStatus": "valid"})
	case strings.Contains(p, "/consents/") && strings.Contains(p, "/authorisations/") && r.Method == "GET":
		f.json(w, 200, map[string]string{"scaStatus": "finalised"})
	case strings.HasPrefix(p, "/sandbox/v5/consents/") && r.Method == "PUT":
		f.json(w, 200, map[string]any{"scaStatus": "started", "psuMessage": "Approve", "chosenScaMethod": map[string]string{"authenticationMethodId": "MOBILE_ID", "authenticationType": "x"},
			"challengeData": map[string]string{"autoStartToken": "tok-2"}, "_links": map[string]any{"scaStatus": map[string]string{"href": "/sandbox/v5/consents/C-D/authorisations/AU1"}}})
	case strings.HasPrefix(p, "/sandbox/v5/consents/") && r.Method == "DELETE":
		w.WriteHeader(204)

	case p == "/sandbox/v5/accounts" && r.Method == "GET":
		f.checkAIS(r)
		f.json(w, 200, map[string]any{"accounts": []map[string]any{
			{"resourceId": "acc1", "iban": "SE0000000000000000000001", "name": "Main", "ownerName": "Test User", "currency": "SEK", "product": "CURRENT", "cashAccountType": "CACC"},
		}})
	case p == "/sandbox/v5/accounts/acc1" && r.Method == "GET":
		f.json(w, 200, map[string]any{"account": map[string]any{"resourceId": "acc1", "iban": "SE0000000000000000000001", "currency": "SEK"}})
	case p == "/sandbox/v5/accounts/acc1/balances":
		f.checkAIS(r)
		f.json(w, 200, map[string]any{"balances": []map[string]any{
			{"balanceType": "interimBooked", "balanceAmount": map[string]string{"amount": "500.00", "currency": "SEK"}, "referenceDate": "2026-10-11"},
			{"balanceType": "interimAvailable", "balanceAmount": map[string]string{"amount": "650.00", "currency": "SEK"}},
		}})
	case p == "/sandbox/v5/accounts/acc1/transactions" && r.Method == "GET":
		f.checkAIS(r)
		if q.Get("pageId") == "" {
			f.json(w, 200, map[string]any{
				"_links": map[string]any{"nextPage": map[string]string{"href": "/acc1/transactions?pageId=P2"}},
				"transactions": map[string]any{
					"booked": []map[string]any{
						{"transactionId": "t1", "bookingDate": "2026-10-01", "transactionAmount": map[string]string{"amount": "-425.65", "currency": "SEK"}, "creditorName": "Shop", "creditorAccount": map[string]string{"iban": "SE99"}, "remittanceInformationUnstructured": "ref 1"},
						{"transactionId": "t2", "bookingDate": "2026-10-02", "transactionAmount": map[string]string{"amount": "1000.00", "currency": "SEK"}, "debtorName": "Employer"},
					},
					"pending": []map[string]any{{"transactionDate": "2026-10-03", "transactionAmount": map[string]string{"amount": "-5.00", "currency": "SEK"}}},
				}})
			return
		}
		f.json(w, 200, map[string]any{"transactions": map[string]any{"booked": []map[string]any{{"transactionId": "t3", "transactionAmount": map[string]string{"amount": "0.10", "currency": "SEK"}}}}})
	case p == "/sandbox/v5/accounts/acc1/transactions" && r.Method == "POST":
		f.json(w, 210, map[string]any{"statementId": "S1", "statementStatus": "signed", "_links": map[string]any{
			"download": map[string]string{"href": "/sandbox/v5/accounts/acc1/transactions/S1/download"}, "status": map[string]string{"href": "/sandbox/v5/accounts/acc1/transactions/S1/status"}}})
	case p == "/sandbox/v5/accounts/acc1/transactions/S1/download":
		f.downloadCalls++
		if f.downloadCalls == 1 {
			f.json(w, 428, map[string]any{"tppMessages": []map[string]string{{"category": "ERROR", "code": "RESOURCE_PENDING", "text": "later"}}})
			return
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for i, tx := range []string{"a1", "a2"} {
			fw, _ := zw.Create(fmt.Sprintf("acc1-%d.json", i))
			fmt.Fprintf(fw, `{"transactions":{"booked":[{"transactionId":%q,"bookingDate":"2025-01-0%d","transactionAmount":{"amount":"-1.00","currency":"SEK"}}]}}`, tx, i+1)
		}
		zw.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(buf.Bytes())
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(404)
	}
}

func (f *fake) checkAIS(r *http.Request) {
	q := r.URL.Query()
	if q.Get("bic") != "SANDSESS" || q.Get("app-id") != "cid" {
		f.t.Errorf("AIS query lacks bic/app-id: %v", q)
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer AT") || r.Header.Get("Consent-ID") == "" || r.Header.Get("X-Request-ID") == "" || r.Header.Get("Date") == "" {
		f.t.Errorf("AIS headers incomplete: %v", r.Header)
	}
}

func (f *fake) consent(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("PSU-IP-Address") == "" || r.Header.Get("PSU-User-Agent") == "" {
		f.t.Errorf("consent without PSU headers")
	}
	if f.consentBlocked {
		f.json(w, 401, map[string]any{"tppMessages": []map[string]string{{"category": "ERROR", "code": "SERVICE_BLOCKED", "text": "Endpoint not allowed"}}})
		return
	}
	var b struct {
		Access map[string]json.RawMessage `json:"access"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	id, status := "C-ALL", "valid"
	links := map[string]any{"status": map[string]string{"href": "/sandbox/v5/consents/C-ALL/status"}}
	switch {
	case b.Access["transactionsOver90Days"] != nil:
		id = "C-90"
	case b.Access["accounts"] != nil:
		id = "C-D"
		if !f.consentsValid {
			status = "received"
			links = map[string]any{"status": map[string]string{"href": "/sandbox/v5/consents/C-D/status"}}
			if r.Header.Get("TPP-Redirect-Preferred") == "true" {
				links["scaRedirect"] = map[string]string{"href": "https://bank.example/sca/1"}
			} else {
				links["startAuthorisationWithAuthenticationMethodSelection"] = map[string]string{"href": "/sandbox/v5/consents/C-D/authorisations/AU1"}
			}
		}
	}
	f.json(w, 201, map[string]any{"consentId": id, "consentStatus": status, "_links": links})
}

func setup(t *testing.T, f *fake) (obsdk.Client, *httptest.Server) {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := obsdk.New(obsdk.Target{Bank: "Swedbank", Country: "se"}, obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "shh", RedirectURL: "https://app.example/cb"},
		Extra:       map[string]string{"base_url": srv.URL},
		Now:         func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

var psu = obsdk.PSUContext{IP: "203.0.113.7", UserAgent: "test-agent"}

// drive runs a flow, answering steps with the given callback/values, until done.
func drive(t *testing.T, c obsdk.Client, step *obsdk.Step, answer func(*obsdk.Step) obsdk.StepInput) *obsdk.Step {
	t.Helper()
	for i := 0; i < 30 && step.Kind != obsdk.StepDone; i++ {
		var err error
		if step, err = c.Resume(context.Background(), step.State, answer(step)); err != nil {
			t.Fatalf("resume: %v", err)
		}
	}
	if step.Kind != obsdk.StepDone {
		t.Fatalf("flow did not finish; at %s", step.Kind)
	}
	return step
}

func TestConnectRedirect(t *testing.T) {
	f := &fake{}
	c, _ := setup(t, f)
	step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu})
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != obsdk.StepRedirect || step.Redirect.URL != "https://bank.example/login?session=1" || !step.NeedsUser {
		t.Fatalf("first step = %+v", step)
	}
	// Wrong state must be rejected.
	if _, err := c.Resume(context.Background(), step.State, obsdk.StepInput{Callback: "https://app.example/cb?access_code=X&state=evil"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: err = %v", err)
	}
	done := drive(t, c, step, func(s *obsdk.Step) obsdk.StepInput {
		switch s.Redirect.URL {
		case "https://bank.example/login?session=1":
			return obsdk.StepInput{Callback: "https://app.example/cb?access_code=CODE1&state=" + f.lastState}
		default: // consent approval: return from the bank, no parameters of interest
			return obsdk.StepInput{Callback: "https://app.example/cb?done=1"}
		}
	})
	s := done.Session
	if s.AccessToken != "AT1" || s.RefreshToken != "RT1" || s.Integration == "" || s.Bank != "swedbank" || s.Segment != obsdk.Personal {
		t.Fatalf("session = %+v", s)
	}
	if s.AccessExpiresAt == nil || !s.AccessExpiresAt.Equal(fixedNow.Add(time.Hour)) {
		t.Errorf("expiry = %v", s.AccessExpiresAt)
	}
	if s.Consents["detailed"].ID != "C-D" || s.Consents["allAccounts"].ID != "C-ALL" || s.Consents["detailed"].ValidUntil == nil {
		t.Errorf("consents = %+v", s.Consents)
	}
	if s.Meta["login_method"] != "MOBILE_ID" || s.Generation == 0 {
		t.Errorf("meta/generation = %+v / %d", s.Meta, s.Generation)
	}
	if len(done.Accounts) != 1 || done.Accounts[0].ID != "acc1" || done.Accounts[0].StableID == "" {
		t.Errorf("accounts = %+v", done.Accounts)
	}
	// The session survives serialization and restores the same implementation.
	b, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := obsdk.ParseSession(b)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := obsdk.Restore(s2, obsdk.Config{Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "shh", RedirectURL: "x"}, Extra: map[string]string{"base_url": "http://unused"}})
	if err != nil || c2.Info().Bank != "swedbank" {
		t.Fatalf("restore: %v", err)
	}
}

func TestConnectDecoupledMultiBank(t *testing.T) {
	f := &fake{multiBank: true, consentsValid: true}
	c, _ := setup(t, f)
	step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu, Method: "decoupled"})
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != obsdk.StepWait || step.Challenge == nil || step.Challenge.AutoStartToken != "tok-1" {
		t.Fatalf("first step = %+v", step)
	}
	sawBankChoice := false
	done := drive(t, c, step, func(s *obsdk.Step) obsdk.StepInput {
		if s.Kind == obsdk.StepInputRequired {
			sawBankChoice = true
			if s.Fields[0].Key != "bank_id" || len(s.Fields[0].Options) != 2 {
				t.Fatalf("fields = %+v", s.Fields)
			}
			return obsdk.StepInput{Values: map[string]string{"bank_id": "08999"}}
		}
		return obsdk.StepInput{}
	})
	if !sawBankChoice {
		t.Error("bank choice step never appeared")
	}
	if done.Session.Meta["auth_method"] != "MOBILE_ID" || done.Session.Meta["approach"] != "decoupled" {
		t.Errorf("meta = %+v", done.Session.Meta)
	}
}

func TestConnectDecoupledConsentApproval(t *testing.T) {
	f := &fake{}
	c, _ := setup(t, f)
	step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu, Method: "decoupled"})
	if err != nil {
		t.Fatal(err)
	}
	waits := 0
	done := drive(t, c, step, func(s *obsdk.Step) obsdk.StepInput {
		if s.Kind == obsdk.StepWait && s.Challenge != nil && s.Challenge.AutoStartToken == "tok-2" {
			waits++
			if s.Session == nil || s.Session.AccessToken == "" {
				t.Errorf("consent approval step carries no session: %+v", s.Session)
			}
		}
		return obsdk.StepInput{}
	})
	if waits == 0 || done.Session.Consents["detailed"].ID != "C-D" {
		t.Fatalf("consent approval step missing (waits=%d, consents=%+v)", waits, done.Session.Consents)
	}
}

// A failure after login must still hand the new session to the caller: the
// login has already invalidated any previous token.
func TestConnectFailureKeepsSession(t *testing.T) {
	f := &fake{consentBlocked: true}
	c, _ := setup(t, f)
	step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu, Method: "decoupled"})
	if err != nil {
		t.Fatal(err)
	}
	if step.Session != nil {
		t.Fatalf("session before login: %+v", step.Session)
	}
	for i := 0; i < 30 && err == nil; i++ {
		step, err = c.Resume(context.Background(), step.State, obsdk.StepInput{})
	}
	var fe *obsdk.FlowError
	if !errors.As(err, &fe) || fe.Session == nil || fe.Session.AccessToken == "" {
		t.Fatalf("err = %v, want FlowError with a session", err)
	}
	var ae *obsdk.APIError
	if !errors.As(err, &ae) || ae.Code != "SERVICE_BLOCKED" {
		t.Fatalf("bank error lost: %v", err)
	}
}

func TestConnectValidation(t *testing.T) {
	c, _ := setup(t, &fake{})
	if _, err := c.Connect(context.Background(), obsdk.ConnectRequest{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("missing PSU: %v", err)
	}
	if _, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu, Method: "carrier-pigeon"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("bad method: %v", err)
	}
	if _, err := c.Resume(context.Background(), "garbage", obsdk.StepInput{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("bad state: %v", err)
	}
}

func connected(t *testing.T, f *fake) (obsdk.Client, *obsdk.Session) {
	c, _ := setup(t, f)
	f.consentsValid = true
	step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu})
	if err != nil {
		t.Fatal(err)
	}
	done := drive(t, c, step, func(*obsdk.Step) obsdk.StepInput {
		return obsdk.StepInput{Callback: "https://app.example/cb?access_code=CODE1&state=" + f.lastState}
	})
	return c, done.Session
}

func TestAccountsBalancesTransactions(t *testing.T) {
	f := &fake{}
	c, s := connected(t, f)
	ctx := context.Background()

	accs, err := c.Accounts(ctx, s, obsdk.CallOptions{})
	if err != nil || len(accs.Data) != 1 {
		t.Fatalf("accounts: %v %+v", err, accs)
	}
	a := accs.Data[0]
	if a.Identifiers[0] != (obsdk.Identifier{Scheme: "IBAN", Value: "SE0000000000000000000001"}) || a.OwnerName != "Test User" || len(a.Raw) == 0 {
		t.Errorf("account = %+v", a)
	}

	bal, err := c.Balances(ctx, s, "acc1", obsdk.CallOptions{})
	if err != nil || len(bal.Data) != 2 {
		t.Fatalf("balances: %v", err)
	}
	if bal.Data[0].Kind != obsdk.BalanceInterimBooked || bal.Data[0].Amount.Amount != "500.00" || bal.Data[1].Kind != obsdk.BalanceInterimAvailable {
		t.Errorf("balances = %+v", bal.Data)
	}

	tx, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "acc1", From: fixedNow.AddDate(0, 0, -30), Status: []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}})
	if err != nil || tx.Step != nil {
		t.Fatalf("transactions: %v %+v", err, tx)
	}
	if len(tx.Transactions) != 3 || tx.NextCursor != "P2" {
		t.Fatalf("page = %d txs, cursor %q", len(tx.Transactions), tx.NextCursor)
	}
	out, in, pend := tx.Transactions[0], tx.Transactions[1], tx.Transactions[2]
	if out.Direction != obsdk.Debit || out.Counterparty.Name != "Shop" || out.Amount.Amount != "-425.65" || out.Remittance[0] != "ref 1" || out.Status != obsdk.TxBooked {
		t.Errorf("outgoing = %+v", out)
	}
	if in.Direction != obsdk.Credit || in.Counterparty.Name != "Employer" {
		t.Errorf("incoming = %+v", in)
	}
	if pend.Status != obsdk.TxPending {
		t.Errorf("pending = %+v", pend)
	}
	next, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "acc1", From: fixedNow.AddDate(0, 0, -30), Cursor: tx.NextCursor})
	if err != nil || len(next.Transactions) != 1 || next.NextCursor != "" {
		t.Fatalf("next page: %v %+v", err, next)
	}
}

func TestExtendedHistory(t *testing.T) {
	f := &fake{}
	c, s := connected(t, f)
	q := obsdk.TxQuery{AccountID: "acc1", From: fixedNow.AddDate(0, 0, -200), Options: obsdk.CallOptions{PSU: &psu}}
	if _, err := c.Transactions(context.Background(), s, obsdk.TxQuery{AccountID: "acc1", From: q.From}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("without PSU: %v", err)
	}
	res, err := c.Transactions(context.Background(), s, q)
	if err != nil {
		t.Fatal(err)
	}
	// First download attempt answers 428, so the SDK hands back a wait step.
	if res.Step == nil || res.Step.Kind != obsdk.StepWait || res.Step.WaitFor != time.Minute || res.Step.NeedsUser {
		t.Fatalf("expected a wait step, got %+v", res)
	}
	done := drive(t, c, res.Step, func(*obsdk.Step) obsdk.StepInput { return obsdk.StepInput{} })
	if done.Transactions == nil || len(done.Transactions.Transactions) != 2 {
		t.Fatalf("done = %+v", done)
	}
	if done.Transactions.Transactions[0].ID != "a1" || done.Transactions.Transactions[1].ID != "a2" || len(done.Transactions.Raw) == 0 {
		t.Errorf("transactions = %+v", done.Transactions.Transactions)
	}
}

func TestRefreshMergesRefreshToken(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		f := &fake{}
		c, s := connected(t, f)
		f.rotateRefresh = rotate
		ns, err := c.Refresh(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		if ns.AccessToken == s.AccessToken || ns.Generation <= s.Generation {
			t.Errorf("rotate=%t: session not updated: %+v", rotate, ns)
		}
		wantRT := "RT1"
		if rotate {
			wantRT = fmt.Sprintf("RT%d", f.tokenN)
		}
		if ns.RefreshToken != wantRT {
			t.Errorf("rotate=%t: refresh token = %q, want %q", rotate, ns.RefreshToken, wantRT)
		}
		if s.AccessToken != "AT1" {
			t.Error("Refresh mutated its input")
		}
	}
}

func TestRefreshFailures(t *testing.T) {
	f := &fake{}
	c, s := connected(t, f)

	f.tokenStatus = 400
	_, err := c.Refresh(context.Background(), s)
	var re *obsdk.RefreshError
	if !errors.As(err, &re) || re.Temporary || !errors.Is(err, obsdk.ErrRefreshFailed) || !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("permanent failure: %v", err)
	}
	f.tokenStatus = 503
	_, err = c.Refresh(context.Background(), s)
	if !errors.As(err, &re) || !re.Temporary || errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("temporary failure: %v", err)
	}
	s2 := s.Clone()
	s2.RefreshToken = ""
	if _, err := c.Refresh(context.Background(), s2); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("no refresh token: %v", err)
	}
}

func TestExpiryAndErrorClassification(t *testing.T) {
	f := &fake{}
	c, s := connected(t, f)
	ctx := context.Background()

	expired := s.Clone()
	past := fixedNow.Add(-time.Minute)
	expired.AccessExpiresAt = &past
	if _, err := c.Accounts(ctx, expired, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("expired token: %v", err)
	}

	lapsed := s.Clone()
	d := lapsed.Consents["detailed"]
	d.ValidUntil = &past
	lapsed.Consents["detailed"] = d
	err := func() error { _, err := c.Balances(ctx, lapsed, "acc1", obsdk.CallOptions{}); return err }()
	var rae *obsdk.ReauthError
	if !errors.Is(err, obsdk.ErrReauthRequired) || !errors.As(err, &rae) || rae.Reason != "consent_expired" || errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("expired consent: %v", err)
	}

	other := s.Clone()
	other.Bank = "someone-else"
	if _, err := c.Accounts(ctx, other, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("foreign session: %v", err)
	}
}

func TestServerErrorMapping(t *testing.T) {
	status, code := 401, "TOKEN_INVALID"
	var hdr http.Header = http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdr {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"tppMessages":[{"category":"ERROR","code":%q,"text":"t"}]}`, code)
	}))
	defer srv.Close()
	c, err := obsdk.New(obsdk.Target{Bank: "swedbank", Country: "SE"}, obsdk.Config{
		Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "shh", RedirectURL: "x"},
		Extra: map[string]string{"base_url": srv.URL}, Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	until := fixedNow.Add(24 * time.Hour)
	s := &obsdk.Session{Version: 1, Bank: "swedbank", Country: "SE", Env: obsdk.Sandbox, Integration: "swedbank-psd2-v5", AccessToken: "AT",
		Consents: map[string]obsdk.Consent{"detailed": {ID: "C", ValidUntil: &until}, "allAccounts": {ID: "C0"}}}
	ctx := context.Background()

	_, err = c.Balances(ctx, s, "acc1", obsdk.CallOptions{})
	var api *obsdk.APIError
	if !errors.Is(err, obsdk.ErrAccessExpired) || !errors.As(err, &api) || api.Code != "TOKEN_INVALID" || api.Status != 401 {
		t.Errorf("TOKEN_INVALID: %v", err)
	}

	// RESOURCE_NOT_POSTED only means "start the extended export" for transactions; elsewhere it is a plain error.
	code = "RESOURCE_NOT_POSTED"
	_, err = c.Balances(ctx, s, "acc1", obsdk.CallOptions{})
	if errors.Is(err, obsdk.ErrAccessExpired) || !errors.As(err, &api) || api.Code != "RESOURCE_NOT_POSTED" {
		t.Errorf("RESOURCE_NOT_POSTED on balances should stay a plain API error: %v", err)
	}

	status, code = 429, "ACCESS_EXCEEDED"
	hdr.Set("Retry-After", "7")
	_, err = c.Balances(ctx, s, "acc1", obsdk.CallOptions{})
	var rl *obsdk.RateLimitedError
	if !errors.Is(err, obsdk.ErrRateLimited) || !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Errorf("429: %v", err)
	}

	status, code = 400, "CONSENT_EXPIRED"
	_, err = c.Balances(ctx, s, "acc1", obsdk.CallOptions{})
	if !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("CONSENT_EXPIRED: %v", err)
	}
}

func TestDisconnect(t *testing.T) {
	f := &fake{}
	c, s := connected(t, f)
	res, err := c.Disconnect(context.Background(), s)
	if err != nil || len(res.Closed) != 2 || len(res.Failed) != 0 || len(res.Session.Consents) != 0 {
		t.Fatalf("disconnect: %v %+v", err, res)
	}
	if len(s.Consents) != 2 {
		t.Error("Disconnect mutated its input")
	}
}

func TestAuthMethods(t *testing.T) {
	c, _ := setup(t, &fake{})
	l, ok := c.(obsdk.AuthMethodLister)
	if !ok {
		t.Fatal("client should list auth methods")
	}
	ms, err := l.AuthMethods(context.Background())
	if err != nil || len(ms) != 1 || ms[0].ID != "MOBILE_ID" {
		t.Fatalf("methods = %v %v", ms, err)
	}
}
