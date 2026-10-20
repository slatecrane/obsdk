package stet

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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// fakeBank is a minimal STET bank: token endpoint, AIS and PIS under /v1.
type fakeBank struct {
	t        *testing.T
	mu       sync.Mutex
	srv      *httptest.Server
	requests []string
	bodies   map[string][]byte
	headers  map[string]http.Header
	queries  map[string]url.Values

	payStatus  string // status reported after confirmation / on GET
	cancelAuth bool   // the cancellation needs the user's approval
	consentPut bool   // PUT /consents happened
}

func newFakeBank(t *testing.T) *fakeBank {
	f := &fakeBank{t: t, bodies: map[string][]byte{}, headers: map[string]http.Header{}, queries: map[string]url.Values{}, payStatus: "ACSP"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBank) key(r *http.Request) string { return r.Method + " " + r.URL.Path }

func (f *fakeBank) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	k := f.key(r)
	f.requests = append(f.requests, k)
	f.bodies[k], f.headers[k], f.queries[k] = b, r.Header.Clone(), r.URL.Query()
	consented := f.consentPut
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/v1/") && r.Header.Get("X-Request-ID") == "" {
		w.WriteHeader(400)
		io.WriteString(w, `{"status":400,"message":"FORMAT_ERROR","details":[{"name":"X-Request-ID","message":"missing"}]}`)
		return
	}
	switch p := r.URL.Path; {
	case p == "/token":
		form, _ := url.ParseQuery(string(b))
		if form.Get("client_id") != "cid" || form.Get("client_secret") != "sec" {
			w.WriteHeader(401)
			io.WriteString(w, `{"statusCode":401,"error":"Unauthorized","message":"Client not found"}`)
			return
		}
		switch form.Get("grant_type") {
		case "client_credentials":
			io.WriteString(w, `{"access_token":"cc-token","token_type":"Bearer","expires_in":3600}`)
		case "authorization_code":
			if form.Get("code") != "the-code" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant","error_description":"bad code"}`)
				return
			}
			io.WriteString(w, `{"access_token":"user-token","token_type":"Bearer","expires_in":"3600","refresh_token":"rt-1","scope":"aisp"}`)
		case "refresh_token":
			if form.Get("refresh_token") != "rt-1" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			io.WriteString(w, `{"access_token":"user-token-2","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-2"}`)
		default:
			w.WriteHeader(400)
		}
	case p == "/v1/accounts":
		if r.Header.Get("Authorization") != "Bearer user-token" {
			w.WriteHeader(401)
			io.WriteString(w, `{"status":401,"message":"Unauthorized"}`)
			return
		}
		id1, id2 := `"resourceId":"acc-1",`, `"resourceId":"acc-2",`
		if !consented {
			id1, id2 = "", ""
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprintf(w, `{"accounts":[{%s"accountId":{"other":{"identification":"1234XXXX5678","schemeName":"CPAN"},"currency":"EUR"},"name":"Visa","cashAccountType":"CARD","usage":"PRIV","_links":{}}],"_links":{"self":{"href":"/v1/accounts?page=2"}}}`, id2)
			return
		}
		fmt.Fprintf(w, `{"accounts":[{%s"bicFi":"GEBABEBB","accountId":{"iban":"BE68539007547034","currency":"EUR"},"name":"Compte courant","cashAccountType":"CACC","usage":"PRIV","product":"Welcome Pack",
			"balances":[{"name":"Solde","balanceAmount":{"amount":1520.45,"currency":"EUR"},"balanceType":"CLBD","referenceDate":"2026-10-19"}],"_links":{}}],
			"_links":{"self":{"href":"/v1/accounts"},"next":{"href":"v1/accounts?page=2"}}}`, id1)
	case p == "/v1/consents" && r.Method == http.MethodPut:
		f.mu.Lock()
		f.consentPut = true
		f.mu.Unlock()
		w.WriteHeader(201)
	case p == "/v1/accounts/acc-1/balances":
		io.WriteString(w, `{"balances":[{"name":"Solde comptable","balanceAmount":{"amount":"1520.45","currency":"EUR"},"balanceType":"CLBD","referenceDate":"2026-10-19"},
			{"name":"Solde instantané","balanceAmount":{"amount":-12.5,"currency":"EUR"},"balanceType":"XPCD","lastChangeDateTime":"2026-10-20T08:00:00Z"}],"_links":{"self":{"href":"/v1/accounts/acc-1/balances"}}}`)
	case p == "/v1/accounts/acc-1/transactions":
		if r.URL.Query().Get("page") == "2" {
			io.WriteString(w, `{"transactions":[{"resourceId":"t3","transactionAmount":{"amount":5,"currency":"EUR"},"creditDebitIndicator":"DBIT","status":"BOOK","bookingDate":"2026-10-01","remittanceInformation":["old style"]}],"_links":{"self":{"href":"x"}}}`)
			return
		}
		io.WriteString(w, `{"transactions":[
			{"resourceId":"t1","entryReference":"E1","transactionAmount":{"amount":42.10,"currency":"EUR"},"creditDebitIndicator":"DBIT","status":"BOOK",
			 "bookingDate":"2026-10-15","valueDate":"2026-10-15T00:00:00+02:00","endToEndId":"e2e-1",
			 "bankTransactionCode":{"domain":"PMNT","family":"ICDT","subFamily":"ESCT"},
			 "relatedParties":{"creditor":{"name":"Electrabel"},"creditorAccount":{"iban":"BE71096123456769"},"debtor":{"name":"Me"}},
			 "remittanceInformation":{"unstructured":["Facture 42"],"structured":[{"creditorReferenceInformation":{"reference":"RF18539007547034"}}]}},
			{"resourceId":"t2","transactionAmount":{"amount":"1000","currency":"EUR"},"creditDebitIndicator":"CRDT","status":"PDNG","expectedBookingDate":"2026-10-21",
			 "relatedParties":{"debtor":{"name":"Employer"},"debtorAccount":{"iban":"BE62510007547061"}}},
			{"resourceId":"t9","transactionAmount":{"amount":9,"currency":"EUR"},"creditDebitIndicator":"DBIT","status":"INFO"}
		],"_links":{"next":{"href":"/v1/accounts/acc-1/transactions?page=2"}}}`)
	case p == "/v1/payment-requests" && r.Method == http.MethodPost:
		w.Header().Set("Location", "/v1/payment-requests/pr-77")
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"appliedAuthenticationApproach":"REDIRECT","_links":{"consentApproval":{"href":%q}}}`, f.srv.URL+"/approve/pr-77")
	case p == "/v1/payment-requests/pr-77/confirmation":
		f.payment(w)
	case p == "/v1/payment-requests/pr-77" && r.Method == http.MethodGet:
		f.payment(w)
	case p == "/v1/payment-requests/pr-77" && r.Method == http.MethodPut:
		f.mu.Lock()
		f.payStatus = "CANC"
		f.mu.Unlock()
		if f.cancelAuth {
			fmt.Fprintf(w, `{"appliedAuthenticationApproach":"REDIRECT","_links":{"consentApproval":{"href":%q}}}`, f.srv.URL+"/approve-cancel")
			return
		}
		io.WriteString(w, `{"appliedAuthenticationApproach":"NONE"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":404,"message":"RESOURCE_UNKNOWN"}`)
	}
}

func (f *fakeBank) payment(w http.ResponseWriter) {
	f.mu.Lock()
	st := f.payStatus
	f.mu.Unlock()
	reason := ""
	if st == "RJCT" {
		reason = `,"statusReasonInformation":"AM04"`
	}
	fmt.Fprintf(w, `{"paymentRequest":{"resourceId":"pr-77","paymentInformationId":"x","creationDateTime":"2026-10-20T12:00:00Z","numberOfTransactions":1,
		"initiatingParty":{"name":"obsdk test"},"paymentTypeInformation":{"serviceLevel":"SEPA"},"debtorAccount":{"iban":"BE68539007547034"},
		"paymentInformationStatus":%q%s,"creditTransferTransaction":[{"paymentId":{"instructionId":"i"},"instructedAmount":{"amount":12.5,"currency":"EUR"},
		"beneficiary":{"creditor":{"name":"Bob"},"creditorAccount":{"iban":"BE71096123456769"}}}],
		"supplementaryData":{"acceptedAuthenticationApproach":["REDIRECT"]}},"_links":{"request":{"href":"/v1/payment-requests/pr-77"}}}`, st, reason)
}

func (f *fakeBank) seen(k string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if r == k {
			return true
		}
	}
	return false
}

func testProfile(f *fakeBank) Profile {
	return Profile{
		ID: "stet-test",
		Info: obsdk.Info{Bank: "stettest", Name: "STET Test Bank",
			Variants: []obsdk.Variant{{Country: "BE", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}},
			Payments: []obsdk.PaymentSpec{{Type: obsdk.PaymentSEPA, Cancellable: true, Fields: []obsdk.PaymentField{
				{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeIBAN}},
				{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70},
				{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140},
				{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}},
				{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional},
			}}}},
		APIBase:    func(obsdk.Env, obsdk.Target) string { return f.srv.URL + "/v1" },
		AuthURL:    func(obsdk.Env, obsdk.Target) string { return f.srv.URL + "/authorize?brand=x" },
		TokenURL:   func(obsdk.Env, obsdk.Target) string { return f.srv.URL + "/token" },
		ClientAuth: ClientSecretPost,
	}
}

func newTestClient(t *testing.T, p Profile, mut ...func(*obsdk.Config)) obsdk.Client {
	t.Helper()
	n := 0
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "sec", RedirectURL: "https://tpp.example/cb"},
		Extra:       map[string]string{ParamInitiatingParty: "obsdk test"},
		Now:         func() time.Time { return frozen },
		NewID:       func(purpose string) string { n++; return fmt.Sprintf("%s-%d", purpose, n) },
	}
	for _, m := range mut {
		m(&cfg)
	}
	c, err := Integration(p).Factory(cfg, obsdk.Target{Bank: p.Info.Bank, Country: "BE"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func connect(t *testing.T, c obsdk.Client, caps ...obsdk.Capability) (*obsdk.Step, url.Values) {
	t.Helper()
	st, err := c.Connect(context.Background(), obsdk.ConnectRequest{Capabilities: caps, Language: "fr", PSU: obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect {
		t.Fatalf("kind %s", st.Kind)
	}
	u, _ := url.Parse(st.Redirect.URL)
	return st, u.Query()
}

func TestConnectForwardsConsentAndListsAccounts(t *testing.T) {
	f := newFakeBank(t)
	p := testProfile(f)
	p.ForwardConsent, p.PKCE = true, true
	c := newTestClient(t, p)

	st, q := connect(t, c, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapTransactionsHistory)
	want := map[string]string{"response_type": "code", "client_id": "cid", "redirect_uri": "https://tpp.example/cb",
		"scope": "aisp extended_transaction_history", "ui_locales": "fr", "brand": "x", "code_challenge_method": "S256"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("authorize %s = %q, want %q", k, q.Get(k), v)
		}
	}
	// NewID yields state-1 (the OAuth state), then state-2 and state-3 (the verifier).
	sum := sha256.Sum256([]byte("state-2state-3"))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || q.Get("state") != "state-1" {
		t.Fatalf("authorize query %v", q)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://tpp.example/cb?code=the-code&state=wrong"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("wrong state: %v", err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://tpp.example/cb?code=the-code&state=" + q.Get("state")})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := url.ParseQuery(string(f.bodies["POST /token"])); v.Get("code_verifier") != "state-2state-3" {
		t.Errorf("token form %s", f.bodies["POST /token"])
	}
	if done.Kind != obsdk.StepDone || done.Session == nil || done.Session.AccessToken != "user-token" || done.Session.RefreshToken != "rt-1" {
		t.Fatalf("done %+v", done)
	}
	if exp := done.Session.AccessExpiresAt; exp == nil || !exp.Equal(frozen.Add(time.Hour)) {
		t.Errorf("expiry %v", exp)
	}
	if len(done.Accounts) != 2 || done.Accounts[0].ID != "acc-1" || done.Accounts[1].ID != "acc-2" {
		t.Fatalf("accounts %+v", done.Accounts)
	}
	a := done.Accounts[0]
	if a.Identifiers[0] != (obsdk.Identifier{Scheme: "IBAN", Value: "BE68539007547034"}) || a.Currency != "EUR" || a.Type != "CACC" ||
		a.Usage != "PRIV" || a.BIC != "GEBABEBB" || a.Product != "Welcome Pack" || a.StableID == "" {
		t.Errorf("account %+v", a)
	}
	if len(a.Balances) != 1 || a.Balances[0].Amount.Amount != "1520.45" || a.Balances[0].Kind != obsdk.BalanceClosingBooked {
		t.Errorf("inline balances %+v", a.Balances)
	}
	if card := done.Accounts[1]; card.Identifiers[0].Scheme != "CPAN" || card.Type != "CARD" {
		t.Errorf("card %+v", card)
	}
	var access struct {
		Balances     []map[string]any `json:"balances"`
		Transactions []map[string]any `json:"transactions"`
		Owners       []map[string]any `json:"owners"`
		PSUIdentity  *bool            `json:"psuIdentity"`
	}
	if err := json.Unmarshal(f.bodies["PUT /v1/consents"], &access); err != nil {
		t.Fatal(err)
	}
	if len(access.Balances) != 2 || len(access.Transactions) != 2 || access.Owners == nil || access.PSUIdentity == nil ||
		access.Balances[0]["iban"] != "BE68539007547034" {
		t.Errorf("consent body %s", f.bodies["PUT /v1/consents"])
	}
	if got := done.Session.Consents[consentKind].Accounts; len(got) != 2 || got[0] != "BE68539007547034" {
		t.Errorf("consent accounts %v", got)
	}
	if h := f.headers["GET /v1/accounts"]; h.Get("PSU-IP-Address") != "203.0.113.7" || h.Get("Authorization") != "Bearer user-token" {
		t.Errorf("headers %v", h)
	}
}

func TestDataCalls(t *testing.T) {
	f := newFakeBank(t)
	f.consentPut = true
	c := newTestClient(t, testProfile(f))
	st, q := connect(t, c)
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "?code=the-code&state=" + q.Get("state")})
	if err != nil {
		t.Fatal(err)
	}
	if f.seen("PUT /v1/consents") {
		t.Error("consent forwarded without ForwardConsent")
	}
	s := done.Session

	bal, err := c.Balances(context.Background(), s, "acc-1", obsdk.CallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(bal.Data) != 2 || bal.Data[1].Amount.Amount != "-12.5" || bal.Data[1].Kind != obsdk.BalanceOther ||
		bal.Data[1].ReferenceDate != "2026-10-20" || bal.Data[0].ReferenceDate != "2026-10-19" {
		t.Errorf("balances %+v", bal.Data)
	}

	tr, err := c.Transactions(context.Background(), s, obsdk.TxQuery{AccountID: "acc-1", From: time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC),
		To: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), Status: []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}})
	if err != nil {
		t.Fatal(err)
	}
	if q := f.queries["GET /v1/accounts/acc-1/transactions"]; q.Get("dateFrom") != "2026-09-01T00:00:00Z" || q.Get("dateTo") != "2026-10-21T00:00:00Z" {
		t.Errorf("query %v", q)
	}
	if len(tr.Transactions) != 2 {
		t.Fatalf("transactions %+v", tr.Transactions)
	}
	t1, t2 := tr.Transactions[0], tr.Transactions[1]
	if t1.Amount.Amount != "-42.10" || t1.Direction != obsdk.Debit || t1.Status != obsdk.TxBooked || t1.BookingDate != "2026-10-15" ||
		t1.ValueDate != "2026-10-15" || t1.Counterparty.Name != "Electrabel" || t1.Counterparty.Identifiers[0].Value != "BE71096123456769" ||
		t1.Remittance[0] != "Facture 42" || t1.ReferenceNumber != "RF18539007547034" || t1.BankCode != "PMNT-ICDT-ESCT" ||
		t1.EndToEndID != "e2e-1" || t1.EntryReference != "E1" {
		t.Errorf("t1 %+v", t1)
	}
	if t2.Amount.Amount != "1000" || t2.Direction != obsdk.Credit || t2.Status != obsdk.TxPending || t2.Counterparty.Name != "Employer" ||
		t2.Counterparty.Identifiers[0].Value != "BE62510007547061" {
		t.Errorf("t2 %+v", t2)
	}
	if tr.NextCursor != f.srv.URL+"/v1/accounts/acc-1/transactions?page=2" {
		t.Fatalf("cursor %q", tr.NextCursor)
	}
	tr2, err := c.Transactions(context.Background(), s, obsdk.TxQuery{AccountID: "acc-1", Cursor: tr.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr2.Transactions) != 1 || tr2.Transactions[0].Remittance[0] != "old style" || tr2.NextCursor != "" {
		t.Errorf("page 2 %+v", tr2)
	}
	if _, err := c.Transactions(context.Background(), s, obsdk.TxQuery{AccountID: "acc-1", Cursor: "https://evil.example/steal"}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("foreign cursor: %v", err)
	}

	// Refresh rotates the tokens; a dead refresh token asks for a new login.
	ns, err := c.Refresh(context.Background(), s)
	if err != nil || ns.AccessToken != "user-token-2" || ns.RefreshToken != "rt-2" || ns.Generation <= s.Generation {
		t.Fatalf("refresh %+v %v", ns, err)
	}
	if _, err := c.Refresh(context.Background(), ns); !errors.Is(err, obsdk.ErrReauthRequired) || !errors.Is(err, obsdk.ErrRefreshFailed) {
		t.Errorf("refresh with rt-2: %v", err)
	}
	// The new token is unknown to the fake bank: 401 means expired.
	if _, err := c.Accounts(context.Background(), ns, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("accounts with unknown token: %v", err)
	}

	d, err := c.Disconnect(context.Background(), s)
	if err != nil || d.Session.AccessToken != "" || d.Failed[consentKind] == "" || len(d.Session.Consents) != 0 {
		t.Errorf("disconnect %+v %v", d, err)
	}
}

func TestPaymentConfirmedWithClientToken(t *testing.T) {
	f := newFakeBank(t)
	c := newTestClient(t, testProfile(f))
	st, err := c.InitiatePayment(context.Background(), obsdk.PaymentRequest{
		Type: obsdk.PaymentSEPA, ExecutionDate: "2026-10-22", PSU: obsdk.PSUContext{IP: "203.0.113.7"},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "12.50", Currency: "EUR"},
			Creditor:   obsdk.Creditor{Name: "Bob", Account: obsdk.Identifier{Scheme: "IBAN", Value: "BE71096123456769"}},
			Remittance: []string{"Invoice 7"}, Reference: &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect.URL != f.srv.URL+"/approve/pr-77" || st.Payment == nil || st.Payment.ID != "pr-77" {
		t.Fatalf("step %+v", st)
	}
	raw := f.bodies["POST /v1/payment-requests"]
	for _, want := range []string{`"amount":12.50`, `"iban":"BE71096123456769"`, `"initiatingParty":{"name":"obsdk test"}`, `"serviceLevel":"SEPA"`,
		`"categoryPurpose":"CASH"`, `"chargeBearer":"SLEV"`, `"requestedExecutionDate":"2026-10-22T00:00:00.000+00:00"`, `"unstructured":["Invoice 7"]`,
		`"type":{"code":"SCOR","issuer":"ISO"}`, `"acceptedAuthenticationApproach":["REDIRECT"]`, `"numberOfTransactions":1`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("body lacks %s: %s", want, raw)
		}
	}
	var body PaymentRequestBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	su, _ := url.Parse(body.SupplementaryData.SuccessfulReportURL)
	fu, _ := url.Parse(body.SupplementaryData.UnsuccessfulReportURL)
	if su.Query().Get("state") == "" || su.Query().Get("error") != "" || fu.Query().Get("error") != errNotApproved {
		t.Fatalf("report urls %+v", body.SupplementaryData)
	}
	if h := f.headers["POST /v1/payment-requests"]; h.Get("Authorization") != "Bearer cc-token" || h.Get("Idempotency-Key") == "" {
		t.Errorf("headers %v", h)
	}

	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: body.SupplementaryData.SuccessfulReportURL})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Payment.Status != obsdk.PaymentInProgress || done.Payment.BankStatus != "ACSP" ||
		done.Payment.Debtor == nil || done.Payment.Debtor.Value != "BE68539007547034" {
		t.Fatalf("done %+v", done.Payment)
	}
	if !strings.Contains(string(f.bodies["POST /v1/payment-requests/pr-77/confirmation"]), `"nonce"`) {
		t.Errorf("confirmation body %s", f.bodies["POST /v1/payment-requests/pr-77/confirmation"])
	}

	// The user turned it down.
	_, err = c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: body.SupplementaryData.UnsuccessfulReportURL})
	var fe *obsdk.FlowError
	if !errors.Is(err, obsdk.ErrAuthFailed) || !errors.As(err, &fe) || fe.Payment == nil {
		t.Errorf("refused: %v", err)
	}

	// The bank rejected it on confirmation.
	f.payStatus = "RJCT"
	_, err = c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: body.SupplementaryData.SuccessfulReportURL})
	var rej *obsdk.PaymentRejectedError
	if !errors.As(err, &rej) || rej.Reason != "am04" {
		t.Errorf("rejected: %v", err)
	}

	got, err := c.PaymentStatus(context.Background(), done.Payment.Ref, obsdk.PaymentCallOptions{})
	if err != nil || got.Data.Status != obsdk.PaymentRejected || !got.Data.Final {
		t.Errorf("status %+v %v", got, err)
	}
}

func TestPaymentEnforcedRedirect(t *testing.T) {
	f := newFakeBank(t)
	p := testProfile(f)
	p.Confirmation = ConfirmAuthorizationCode
	c := newTestClient(t, p)
	st, err := c.InitiatePayment(context.Background(), obsdk.PaymentRequest{Type: obsdk.PaymentSEPA,
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "1", Currency: "EUR"}, Creditor: obsdk.Creditor{Name: "Bob", Account: obsdk.Identifier{Scheme: "IBAN", Value: "BE71096123456769"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.Redirect.URL)
	q := u.Query()
	if u.Path != "/approve/pr-77" || q.Get("client_id") != "cid" || q.Get("response_type") != "code" || q.Get("scope") != "pisp" ||
		q.Get("redirect_uri") != "https://tpp.example/cb" || q.Get("state") == "" {
		t.Fatalf("approval url %s", st.Redirect.URL)
	}
	if _, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "?state=" + q.Get("state")}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("no code: %v", err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "?code=the-code&state=" + q.Get("state")})
	if err != nil || done.Payment.Status != obsdk.PaymentInProgress {
		t.Fatalf("done %+v %v", done, err)
	}
	if h := f.headers["POST /v1/payment-requests/pr-77/confirmation"]; h.Get("Authorization") != "Bearer user-token" {
		t.Errorf("confirmation token %q", h.Get("Authorization"))
	}
}

func TestCancel(t *testing.T) {
	f := newFakeBank(t)
	c := newTestClient(t, testProfile(f))
	ref, _ := c.(*client).newPayment(&payFlow{Type: obsdk.PaymentSEPA, ID: "pr-77"})

	st, err := c.CancelPayment(context.Background(), ref.Ref, obsdk.PaymentCallOptions{})
	if err != nil || st.Kind != obsdk.StepDone || st.Payment.Status != obsdk.PaymentCancelled {
		t.Fatalf("cancel %+v %v", st, err)
	}
	var put map[string]any
	_ = json.Unmarshal(f.bodies["PUT /v1/payment-requests/pr-77"], &put)
	sd, _ := put["supplementaryData"].(map[string]any)
	if put["paymentInformationStatus"] != "CANC" || put["statusReasonInformation"] != "DS02" || sd["successfulReportUrl"] == nil {
		t.Errorf("cancel body %s", f.bodies["PUT /v1/payment-requests/pr-77"])
	}

	f.payStatus, f.cancelAuth = "ACTC", true
	st, err = c.CancelPayment(context.Background(), ref.Ref, obsdk.PaymentCallOptions{})
	if err != nil || st.Kind != obsdk.StepRedirect || st.Redirect.URL != f.srv.URL+"/approve-cancel" {
		t.Fatalf("cancel with approval %+v %v", st, err)
	}
	done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://tpp.example/cb"})
	if err != nil || done.Payment.Status != obsdk.PaymentCancelled {
		t.Errorf("cancel resumed %+v %v", done, err)
	}
}

func TestSigning(t *testing.T) {
	f := newFakeBank(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := testProfile(f)
	p.Signing = &Signing{Required: true}
	if _, err := Integration(p).Factory(obsdk.Config{Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "sec"}},
		obsdk.Target{Bank: "stettest", Country: "BE"}); !errors.Is(err, obsdk.ErrInvalidConfig) {
		t.Fatalf("missing seal: %v", err)
	}
	c := newTestClient(t, p, func(cfg *obsdk.Config) {
		cfg.Seal = &obsdk.Seal{Key: key, KeyID: "https://tpp.example/qsealc_abc"}
	})
	if _, err := c.InitiatePayment(context.Background(), obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, PSU: obsdk.PSUContext{IP: "203.0.113.7", UserAgent: "ua"},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "1", Currency: "EUR"}, Creditor: obsdk.Creditor{Name: "Bob", Account: obsdk.Identifier{Scheme: "IBAN", Value: "BE71096123456769"}}}}}); err != nil {
		t.Fatal(err)
	}
	h := f.headers["POST /v1/payment-requests"]
	body := f.bodies["POST /v1/payment-requests"]
	if h.Get("Digest") != bodyDigest(body) {
		t.Fatalf("digest %q", h.Get("Digest"))
	}
	m := regexp.MustCompile(`keyId="([^"]*)",algorithm="rsa-sha256",headers="([^"]*)",signature="([^"]*)"`).FindStringSubmatch(h.Get("Signature"))
	if m == nil || m[1] != "https://tpp.example/qsealc_abc" {
		t.Fatalf("signature %q", h.Get("Signature"))
	}
	if m[2] != "(request-target) content-type content-length digest x-request-id psu-ip-address psu-user-agent" {
		t.Errorf("signed headers %q", m[2])
	}
	var lines []string
	for _, n := range strings.Fields(m[2]) {
		switch n {
		case "(request-target)":
			lines = append(lines, n+": post /v1/payment-requests")
		case "content-length":
			lines = append(lines, fmt.Sprintf("%s: %d", n, len(body)))
		default:
			lines = append(lines, n+": "+h.Get(n))
		}
	}
	sig, _ := base64.StdEncoding.DecodeString(m[3])
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
	if f.headers["POST /token"].Get("Signature") != "" {
		t.Error("token request was signed")
	}
}

func TestErrors(t *testing.T) {
	for _, tc := range []struct {
		body       string
		code, text string
	}{
		{`{"status":400,"error":"Bad Request","message":"FORMAT_ERROR","details":[{"path":"$.creditTransferTransaction[0]","message":"invalid iban"}]}`,
			"FORMAT_ERROR", "Bad Request ($.creditTransferTransaction[0]: invalid iban)"},
		{`{"statusCode":401,"error":"Unauthorized","message":"Client not found"}`, "", "Client not found"},
		{`{"error":"invalid_grant","error_description":"expired"}`, "invalid_grant", "expired"},
		{`{"message":"REQUESTED_FORMATS _INVALID"}`, "REQUESTED_FORMATS_INVALID", ""},
		{`oops`, "", "oops"},
	} {
		code, text := parseError([]byte(tc.body))
		if code != tc.code || text != tc.text {
			t.Errorf("%s: got %q %q", tc.body, code, text)
		}
	}
	c := &client{p: &Profile{}}
	h := http.Header{"Retry-After": {"7"}}
	var rl *obsdk.RateLimitedError
	if err := c.apiErr(opAccounts, &resp{status: 429, header: h, body: []byte(`{"message":"ACCESS_EXCEEDED"}`)}); !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Errorf("429: %v", err)
	}
	if err := c.apiErr(opTransactions, &resp{status: 403, header: http.Header{}}); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("403: %v", err)
	}
}

func TestResourceID(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/payment-requests/pr-1":                       "pr-1",
		"https://api.bank/psd2/v2/payment-requests/a%2Fb": "a/b",
		"payment-requests/x/":                             "x",
		"":                                                "",
	} {
		if got := resourceID(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
