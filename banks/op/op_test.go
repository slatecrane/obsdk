package op

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func newTestClient(t *testing.T, srv *httptest.Server, seg obsdk.Segment) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "secret", RedirectURL: "https://example.com/cb"},
		HTTPClient:  srv.Client(),
		Seal:        &obsdk.Seal{Key: testKey, KeyID: "qseal-1"},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{paramAPIKey: "key-1", paramBaseURL: srv.URL},
	}
	c, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "FI", Segment: seg}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

// fakeOP is a minimal OP PSD2 API. Handlers record what they saw.
type fakeOP struct {
	t        *testing.T
	mu       sync.Mutex
	headers  map[string]http.Header // by "METHOD path"
	bodies   map[string][]byte
	statuses map[string]string // paymentId -> status
	created  int
}

func newFake(t *testing.T) (*fakeOP, *httptest.Server) {
	f := &fakeOP{t: t, headers: map[string]http.Header{}, bodies: map[string][]byte{}, statuses: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeOP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	key := r.Method + " " + r.URL.Path
	f.headers[key], f.bodies[key] = r.Header.Clone(), body
	if r.URL.Path != "/oauth/token" && r.Header.Get("x-api-key") != "key-1" {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"SECURITY","message":"Forbidden","id":"e-1"}`))
		return
	}
	switch {
	case key == "POST /oauth/token":
		form, _ := url.ParseQuery(string(body))
		if form.Get("client_id") != "cid" || form.Get("client_secret") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		switch form.Get("grant_type") {
		case "client_credentials":
			_, _ = w.Write([]byte(`{"token_type":"bearer","access_token":"cc-` + form.Get("scope") + `","scope":"` + form.Get("scope") + `","status":"approved","expires_in":"86399"}`))
		case "authorization_code":
			if form.Get("redirect_uri") != "https://example.com/cb" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"redirect_uri"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"user-` + form.Get("code") + `","refresh_token":"rt-1","token_type":"bearer","expires_in":3599,"scope":"openid accounts"}`))
		case "refresh_token":
			if form.Get("refresh_token") != "rt-1" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"user-2","refresh_token":"rt-2","token_type":"bearer","expires_in":3599}`))
		}
	case key == "POST /accounts-psd2/v1/authorizations":
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"authorizationId":"auth-1","created":"2026-10-17T12:00:00Z","status":"Unauthorized","expires":"2027-04-15T12:00:00.000Z"}`))
	case key == "DELETE /accounts-psd2/v1/authorizations/auth-stuck":
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"id":"e-3","type":"TECHNICAL","message":"Authorization auth-stuck not found"}`))
	case key == "GET /accounts-psd2/v1/authorizations/auth-stuck":
		_, _ = w.Write([]byte(`{"authorizationId":"auth-stuck","status":"Authorized"}`))
	case key == "DELETE /accounts-psd2/v1/authorizations/auth-gone":
		w.WriteHeader(http.StatusNotFound)
	case key == "GET /accounts-psd2/v1/authorizations/auth-gone":
		w.WriteHeader(http.StatusNotFound)
	case key == "DELETE /accounts-psd2/v1/authorizations/auth-1":
		_, _ = w.Write([]byte(`{"authorizationId":"auth-1","status":"Revoked"}`))
	case key == "GET /accounts-psd2/v1/accounts":
		_, _ = w.Write([]byte(`[{"accountId":"acc-1","productName":"KÄYTTÖTILI","identifierSchema":"IBAN","identifier":"FI3959986920068848",
			"servicerSchema":"BIC","servicer":"OKOYFIHH","owner":"Matti Meikäläinen","netBalance":"1234.56","grossBalance":"1300.00","currency":"EUR"}]`))
	case key == "GET /accounts-psd2/v1/accounts/acc-1":
		_, _ = w.Write([]byte(`{"accountId":"acc-1","identifier":"FI3959986920068848","netBalance":"10.00","grossBalance":"12.50","currency":"EUR"}`))
	case key == "GET /accounts-psd2/v1/cards":
		_, _ = w.Write([]byte(`[{"cardId":"card-1","productName":"OP-Visa Credit/Debit","cardNumber":"492065******6526","statementBalance":"150.00","authorizedOutstandingAmount":"20.00"}]`))
	case key == "GET /accounts-psd2/v1/accounts/acc-1/transactions":
		if r.URL.Query().Get("continuationToken") == "" {
			_, _ = w.Write([]byte(`{"transactions":[
				{"archiveId":"A1","amount":"-25.00","currency":"EUR","bookingDate":"2026-10-15","valueDate":"2026-10-15","paymentDate":"2026-10-14",
				 "message":"Lasku 12","reference":"1232","recipient":{"name":"Shop Oy","identifier":"FI2112345600000785","servicer":"NDEAFIHH"},
				 "proprietaryTransactionDescription":"TILISIIRTO"},
				{"archiveId":"A2","amount":"1500.00","currency":"EUR","bookingDate":"2026-10-01","payer":{"name":"Employer Oy"},"proprietaryTransactionDescription":"PALKKA"}],
				"continuationToken":"ct-2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"transactions":[{"archiveId":"A3","amount":"-1.00","currency":"EUR","bookingDate":"2026-08-01"}]}`))
	case key == "GET /accounts-psd2/v1/cards/card-1/transactions":
		_, _ = w.Write([]byte(`{"transactions":[{"description":"HBO*NORDIC.COM","amount":"15.00","currency":"EUR","postingDate":"2026-10-03","transactionDate":"2026-10-02"},
			{"description":"REFUND","amount":"-5.00","currency":"EUR","postingDate":"2026-10-04","transactionDate":"2026-10-04"}]}`))
	case r.Method == http.MethodPost && (r.URL.Path == pisBase+"/sepa-payments" || r.URL.Path == pisBase+"/scheduled-sepa-payments" || r.URL.Path == pisBase+"/foreign-payments"):
		if r.Header.Get("Authorization") != "Bearer cc-payments" || r.Header.Get("x-jws-signature") == "" || r.Header.Get("x-idempotency-key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.created++
		id := "pay-" + string(rune('0'+f.created))
		f.statuses[id] = "Unauthorized"
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		auth, _ := in["authorizationId"].(string)
		if auth == "" {
			auth = "bundle-1"
		}
		f.bodies["created "+id] = body
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"authorizationId":"` + auth + `","paymentId":"` + id + `","status":"Unauthorized"}`))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/submit"):
		id := strings.Split(r.URL.Path, "/")[4]
		if r.Header.Get("Authorization") != "Bearer user-pay-code" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("x-sandbox-scenario") == "" && id == "pay-9" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"BUSINESS","message":"Payment failed","id":"e-2","violations":[{"type":"InsufficientFunds","message":"Insufficient funds"}]}`))
			return
		}
		f.statuses[id] = "Debited"
		_, _ = w.Write([]byte(`{"paymentId":"` + id + `","status":"Debited","payer":{"iban":"FI1258410220189833","name":"Matti"}}`))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, pisBase+"/") && !strings.Contains(r.URL.Path, "/authorizations/"):
		id := strings.Split(r.URL.Path, "/")[4]
		st, ok := f.statuses[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"paymentId":"` + id + `","authorizationId":"bundle-1","status":"` + st + `"}`))
	case key == "DELETE "+pisBase+"/authorizations/bundle-1":
		for id := range f.statuses {
			f.statuses[id] = "Revoked"
		}
		_, _ = w.Write([]byte(`{"authorizationId":"bundle-1","status":"Revoked"}`))
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, pisBase+"/scheduled-sepa-payments/"):
		if r.Header.Get("Authorization") != "Bearer user-cancel-code" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		id := strings.Split(r.URL.Path, "/")[4]
		f.statuses[id] = "Cancelled"
		_, _ = w.Write([]byte(`{"paymentId":"` + id + `","status":"Cancelled"}`))
	default:
		f.t.Errorf("unexpected request %s", key)
		w.WriteHeader(http.StatusNotFound)
	}
}

// requestObject decodes the request JWT of an authorisation URL after
// checking its RS256 signature.
func requestObjectOf(t *testing.T, authURL string) (url.Values, map[string]any) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	parts := strings.Split(q.Get("request"), ".")
	if len(parts) != 3 {
		t.Fatalf("request is not a JWS: %q", q.Get("request"))
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("request object signature: %v", err)
	}
	var hdr map[string]any
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(h, &hdr)
	if hdr["alg"] != "RS256" || hdr["kid"] != "qseal-1" {
		t.Errorf("request object header = %v", hdr)
	}
	var claims map[string]any
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(p, &claims)
	return q, claims
}

func TestConnectAndAIS(t *testing.T) {
	fake, srv := newFake(t)
	c := newTestClient(t, srv, obsdk.Personal)
	ctx := context.Background()

	st, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7", UserAgent: "ua"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || !strings.HasPrefix(st.Redirect.URL, sandboxAuth+"?") {
		t.Fatalf("step = %+v", st)
	}
	var cons map[string]string
	_ = json.Unmarshal(fake.bodies["POST /accounts-psd2/v1/authorizations"], &cons)
	if cons["expires"] != "2027-04-15T12:00:00.000Z" {
		t.Errorf("authorization body = %v", cons)
	}
	if h := fake.headers["POST /accounts-psd2/v1/authorizations"]; h.Get("Authorization") != "Bearer cc-accounts" || h.Get("x-fapi-customer-ip-address") != "203.0.113.7" {
		t.Errorf("authorization headers = %v", h)
	}
	q, claims := requestObjectOf(t, st.Redirect.URL)
	if q.Get("scope") != "openid accounts" || q.Get("response_type") != "code id_token" || q.Get("client_id") != "cid" {
		t.Errorf("auth query = %v", q)
	}
	if claims["scope"] != "openid accounts" || claims["state"] != "state-1" || claims["redirect_uri"] != "https://example.com/cb" || claims["aud"] != audience {
		t.Errorf("claims = %v", claims)
	}
	idt := claims["claims"].(map[string]any)["id_token"].(map[string]any)
	if idt["authorizationId"].(map[string]any)["value"] != "auth-1" || idt["acr"].(map[string]any)["values"].([]any)[0] != acrSCA {
		t.Errorf("id_token claims = %v", idt)
	}

	if _, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://example.com/cb#state=other&code=x"}); !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("wrong state: err = %v", err)
	}
	if _, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://example.com/cb?state=state-1&error=access_denied&description=cancelled"}); !errors.Is(err, obsdk.ErrAuthFailed) || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("declined: err = %v", err)
	}
	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://example.com/cb#state=state-1&code=ais-code&id_token=x.y.z"})
	if err != nil {
		t.Fatal(err)
	}
	s := done.Session
	if s.AccessToken != "user-ais-code" || s.RefreshToken != "rt-1" || s.AccessExpiresAt == nil || !s.AccessExpiresAt.Equal(frozen.Add(3599*time.Second)) {
		t.Errorf("session tokens = %+v", s)
	}
	if s.RefreshExpiresAt == nil || !s.RefreshExpiresAt.Equal(frozen.Add(refreshTTL)) || s.Consents[consentKind].ID != "auth-1" {
		t.Errorf("session = %+v", s)
	}
	if len(done.Accounts) != 2 {
		t.Fatalf("accounts = %+v", done.Accounts)
	}
	acc, card := done.Accounts[0], done.Accounts[1]
	if acc.ID != "acc-1" || acc.BIC != "OKOYFIHH" || acc.OwnerName != "Matti Meikäläinen" || acc.Identifiers[0].Value != "FI3959986920068848" ||
		acc.Usage != "PRIV" || len(acc.Balances) != 2 || acc.Balances[0].Kind != obsdk.BalanceInterimAvailable || acc.Balances[0].Amount.Amount != "1234.56" {
		t.Errorf("account = %+v", acc)
	}
	if card.ID != "card~card-1" || card.Type != "CARD" || card.Identifiers[0].Scheme != "MASKED_PAN" || card.Balances[0].Amount.Amount != "-150.00" {
		t.Errorf("card = %+v", card)
	}
	if h := fake.headers["GET /accounts-psd2/v1/accounts"]; h.Get("Authorization") != "Bearer user-ais-code" || h.Get("x-api-key") != "key-1" || h.Get("x-fapi-interaction-id") == "" {
		t.Errorf("accounts headers = %v", h)
	}

	bal, err := c.Balances(ctx, s, "acc-1", obsdk.CallOptions{})
	if err != nil || len(bal.Data) != 2 || bal.Data[1].Amount.Amount != "12.50" || bal.Data[1].Kind != obsdk.BalanceInterimBooked {
		t.Fatalf("balances = %+v, %v", bal, err)
	}
	cbal, err := c.Balances(ctx, s, "card~card-1", obsdk.CallOptions{})
	if err != nil || len(cbal.Data) != 2 || cbal.Data[1].Amount.Amount != "-20.00" {
		t.Fatalf("card balances = %+v, %v", cbal, err)
	}

	// Page 1 holds two transactions; the window keeps the October 15 one, and
	// the October 1 one is older than From, so paging stops (newest first).
	tx, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "acc-1", From: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), To: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Transactions) != 1 || tx.NextCursor != "" {
		t.Fatalf("page 1 = %+v", tx.TxPage)
	}
	t1 := tx.Transactions[0]
	if t1.Direction != obsdk.Debit || t1.Amount.Amount != "-25.00" || t1.Counterparty.Name != "Shop Oy" || t1.Counterparty.Identifiers[0].Scheme != "IBAN" ||
		t1.ReferenceNumber != "1232" || t1.Remittance[0] != "Lasku 12" || t1.TransactionDate != "2026-10-14" || t1.EntryReference != "A1" || t1.BankCodeText != "TILISIIRTO" {
		t.Errorf("transaction = %+v", t1)
	}
	all, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "acc-1", From: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil || len(all.Transactions) != 2 || all.Transactions[1].Counterparty.Name != "Employer Oy" || all.Transactions[1].Direction != obsdk.Credit || all.NextCursor == "" {
		t.Fatalf("unfiltered = %+v, %v", all, err)
	}
	// Page 2 is filtered with the window kept in the cursor.
	tx2, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "acc-1", Cursor: all.NextCursor})
	if err != nil || len(tx2.Transactions) != 0 || tx2.NextCursor != "" {
		t.Fatalf("page 2 = %+v, %v", tx2, err)
	}
	if fake.headers["GET /accounts-psd2/v1/accounts/acc-1/transactions"].Get("Authorization") != "Bearer user-ais-code" {
		t.Fatal("transactions call without the user token")
	}
	ctx2, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "card~card-1"})
	if err != nil || len(ctx2.Transactions) != 2 {
		t.Fatalf("card transactions = %+v, %v", ctx2, err)
	}
	if p := ctx2.Transactions[0]; p.Amount.Amount != "-15.00" || p.Direction != obsdk.Debit || p.Counterparty.Name != "HBO*NORDIC.COM" || p.BookingDate != "2026-10-03" {
		t.Errorf("card purchase = %+v", p)
	}
	if r := ctx2.Transactions[1]; r.Amount.Amount != "5.00" || r.Direction != obsdk.Credit {
		t.Errorf("card refund = %+v", r)
	}
	pend, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "acc-1", Status: []obsdk.TxStatus{obsdk.TxPending}})
	if err != nil || len(pend.Transactions) != 0 {
		t.Fatalf("pending = %+v, %v", pend, err)
	}

	ns, err := c.Refresh(ctx, s)
	if err != nil || ns.AccessToken != "user-2" || ns.RefreshToken != "rt-2" || ns.Generation <= s.Generation {
		t.Fatalf("refresh = %+v, %v", ns, err)
	}
	bad := ns.Clone()
	bad.RefreshToken = "nope"
	if _, err := c.Refresh(ctx, bad); !errors.Is(err, obsdk.ErrReauthRequired) || !errors.Is(err, obsdk.ErrRefreshFailed) {
		t.Fatalf("bad refresh: %v", err)
	}

	dr, err := c.Disconnect(ctx, ns)
	if err != nil || len(dr.Closed) != 1 || len(dr.Session.Consents) != 0 {
		t.Fatalf("disconnect = %+v, %v", dr, err)
	}
	if h := fake.headers["DELETE /accounts-psd2/v1/authorizations/auth-1"]; h.Get("Authorization") != "Bearer cc-accounts" {
		t.Errorf("disconnect headers = %v", h)
	}
}

func TestExpiredAccess(t *testing.T) {
	_, srv := newFake(t)
	c := newTestClient(t, srv, obsdk.Business)
	past := frozen.Add(-time.Minute)
	s := &obsdk.Session{Version: 1, Bank: bankKey, Country: "FI", Segment: obsdk.Business, Env: obsdk.Sandbox, Integration: integrationID,
		AccessToken: "x", AccessExpiresAt: &past}
	if _, err := c.Accounts(context.Background(), s, obsdk.CallOptions{}); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIErrors(t *testing.T) {
	c := &client{cfg: obsdk.Config{}}
	r := &resp{status: 400, header: http.Header{}, body: []byte(`{"type":"BUSINESS","message":"x","id":"e-9","violations":[{"type":"InsufficientFunds","message":"Insufficient funds"}]}`)}
	if err := c.apiErr(opPaySubmit, r); !errors.Is(err, obsdk.ErrPaymentRejected) || !strings.Contains(err.Error(), "insufficient_funds") {
		t.Errorf("submit: %v", err)
	}
	r.body = []byte(`{"type":"VALIDATION","message":"x","id":"e-9","violations":[{"type":"MessageOrReference","path":"message","message":"Must specify either message or reference"}]}`)
	err := c.apiErr(opPayCreate, r)
	var ae *obsdk.APIError
	if !errors.As(err, &ae) || ae.Code != "MessageOrReference" || ae.RequestID != "e-9" || !strings.HasPrefix(ae.Text, "message: ") {
		t.Errorf("validation: %#v", err)
	}
	r = &resp{status: 401, header: http.Header{}, body: []byte(`<html>Unauthorized</html>`)}
	if err := c.apiErr(opTransactions, r); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("401: %v", err)
	}
	r = &resp{status: 429, header: http.Header{"Retry-After": {"7"}}, body: nil}
	var rl *obsdk.RateLimitedError
	if err := c.apiErr(opAccounts, r); !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Errorf("429: %v", err)
	}
}

func sepaRequest(n int) obsdk.PaymentRequest {
	r := obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, PSU: obsdk.PSUContext{IP: "203.0.113.7"},
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI1258410220189833"}}}
	for i := 0; i < n; i++ {
		r.Transfers = append(r.Transfers, obsdk.Transfer{
			Amount:     obsdk.Money{Amount: "1.5", Currency: "EUR"},
			Creditor:   obsdk.Creditor{Name: "Payee", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI2112345600000785"}},
			Remittance: []string{"test"},
		})
	}
	return r
}

func TestPaymentBundle(t *testing.T) {
	fake, srv := newFake(t)
	c := newTestClient(t, srv, obsdk.Personal)
	ctx := context.Background()

	st, err := c.InitiatePayment(ctx, sepaRequest(2))
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Payment == nil || st.Payment.ID != "bundle-1" || st.Payment.Status != obsdk.PaymentReceived {
		t.Fatalf("step = %+v", st)
	}
	var first, second map[string]any
	_ = json.Unmarshal(fake.bodies["created pay-1"], &first)
	_ = json.Unmarshal(fake.bodies["created pay-2"], &second)
	if first["amountEUR"] != "1.50" || first["authorizationId"] != nil || first["message"] != "test" || first["payer"].(map[string]any)["iban"] != "FI1258410220189833" {
		t.Errorf("first body = %v", first)
	}
	if second["authorizationId"] != "bundle-1" {
		t.Errorf("second body = %v", second)
	}
	h := fake.headers["POST "+pisBase+"/sepa-payments"]
	if h.Get("x-idempotency-key") != "request-1-1" {
		t.Errorf("idempotency key = %q", h.Get("x-idempotency-key"))
	}
	// The detached JWS signs the exact body.
	parts := strings.Split(h.Get("x-jws-signature"), ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("x-jws-signature = %q", h.Get("x-jws-signature"))
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString(fake.bodies["created pay-2"])))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Errorf("body signature: %v", err)
	}
	q, claims := requestObjectOf(t, st.Redirect.URL)
	if q.Get("scope") != "openid payments" || claims["claims"].(map[string]any)["userinfo"].(map[string]any)["authorizationId"].(map[string]any)["value"] != "bundle-1" {
		t.Errorf("payment request object = %v %v", q, claims)
	}

	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://example.com/cb#state=state-1&code=pay-code"})
	if err != nil {
		t.Fatal(err)
	}
	p := done.Payment
	if p.Status != obsdk.PaymentCompleted || !p.Final || p.ID != "bundle-1" || p.Debtor == nil || p.Debtor.Value != "FI1258410220189833" {
		t.Fatalf("payment = %+v", p)
	}
	res, err := c.PaymentStatus(ctx, p.Ref, obsdk.PaymentCallOptions{})
	if err != nil || res.Data.Status != obsdk.PaymentCompleted {
		t.Fatalf("status = %+v, %v", res, err)
	}
	if h := fake.headers["GET "+pisBase+"/sepa-payments/pay-2"]; h.Get("Authorization") != "Bearer cc-payments" {
		t.Errorf("status headers = %v", h)
	}
	if _, err := c.CancelPayment(ctx, p.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("cancel executed: %v", err)
	}
}

func TestPaymentValidation(t *testing.T) {
	_, srv := newFake(t)
	c := newTestClient(t, srv, obsdk.Personal)
	r := sepaRequest(1)
	r.Transfers[0].Remittance = nil
	var ve *obsdk.PaymentValidationError
	if _, err := c.InitiatePayment(context.Background(), r); !errors.As(err, &ve) || ve.Issues[0].Path != obsdk.FieldRemittance {
		t.Fatalf("err = %v", err)
	}
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: referenceFI, Value: "12a"}
	if _, err := c.InitiatePayment(context.Background(), r); !errors.As(err, &ve) {
		t.Fatalf("bad reference: err = %v", err)
	}
}

func TestScheduledCancel(t *testing.T) {
	fake, srv := newFake(t)
	c := newTestClient(t, srv, obsdk.Personal)
	ctx := context.Background()
	r := sepaRequest(1)
	r.ExecutionDate = "2026-11-02"
	r.Transfers[0].Remittance = nil
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}
	st, err := c.InitiatePayment(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal(fake.bodies["created pay-1"], &body)
	if body["dueDate"] != "2026-11-02" || body["reference"] != "RF18539007547034" || body["message"] != nil {
		t.Errorf("scheduled body = %v", body)
	}
	if st.Payment.ID != "pay-1" {
		t.Errorf("payment id = %q", st.Payment.ID)
	}

	// Before approval: the bundle is revoked without the user.
	cs, err := c.CancelPayment(ctx, st.Payment.Ref, obsdk.PaymentCallOptions{})
	if err != nil || cs.Kind != obsdk.StepDone || cs.Payment.Status != obsdk.PaymentCancelled {
		t.Fatalf("revoke = %+v, %v", cs, err)
	}

	// After approval, waiting for its date: cancellation needs the user.
	fake.statuses["pay-1"] = "AwaitingDueDate"
	cs, err = c.CancelPayment(ctx, st.Payment.Ref, obsdk.PaymentCallOptions{})
	if err != nil || cs.Kind != obsdk.StepRedirect || cs.Payment.Status != obsdk.PaymentInProgress {
		t.Fatalf("cancel step = %+v, %v", cs, err)
	}
	q, claims := requestObjectOf(t, cs.Redirect.URL)
	idt := claims["claims"].(map[string]any)["id_token"].(map[string]any)
	if q.Get("scope") != "openid payments:delete" || idt["paymentId"].(map[string]any)["value"] != "pay-1" || len(idt["acr"].(map[string]any)["values"].([]any)) != 2 {
		t.Errorf("cancel request object = %v %v", q, idt)
	}
	done, err := c.Resume(ctx, cs.State, obsdk.StepInput{Callback: "https://example.com/cb#state=state-1&code=cancel-code"})
	if err != nil || done.Payment.Status != obsdk.PaymentCancelled || !done.Payment.Final {
		t.Fatalf("cancelled = %+v, %v", done, err)
	}
}

func TestSubmitRejected(t *testing.T) {
	fake, srv := newFake(t)
	c := newTestClient(t, srv, obsdk.Personal)
	ctx := context.Background()
	fake.created = 8 // the next payment is pay-9, which the fake refuses
	st, err := c.InitiatePayment(ctx, sepaRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://example.com/cb#state=state-1&code=pay-code"})
	var fe *obsdk.FlowError
	var rej *obsdk.PaymentRejectedError
	if !errors.As(err, &fe) || fe.Payment == nil || !errors.As(err, &rej) || rej.Reason != "insufficient_funds" {
		t.Fatalf("err = %v", err)
	}
}

func TestES256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &client{cfg: obsdk.Config{Seal: &obsdk.Seal{Key: k, KeyID: "ec-1"}}}
	jws, err := c.signBody([]byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jws, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature length %d", len(sig))
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`))))
	if !ecdsa.Verify(&k.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("ES256 signature does not verify")
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(h), `"alg":"ES256"`) {
		t.Errorf("header = %s", h)
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[obsdk.Decimal]string{"1": "1", "1.5": "1.50", "1.50": "1.50", "10.": "10"} {
		if got := twoDecimals(in); got != want {
			t.Errorf("twoDecimals(%s) = %s, want %s", in, got, want)
		}
	}
	a := &obsdk.PostalAddress{Street: "Teollisuuskatu", BuildingNumber: "1b", PostCode: "00510", Town: "Helsinki", Country: "FI"}
	if got := addressLines(a, 4); len(got) != 2 || got[0] != "Teollisuuskatu 1b" || got[1] != "00510 Helsinki" {
		t.Errorf("addressLines = %q", got)
	}
	if transferKey(strings.Repeat("k", 45), 1) != strings.Repeat("k", 38)+"-1" {
		t.Error("transferKey not cut to 40")
	}
}

// TestDisconnectNotFound: a 404 counts as closed only when OP no longer
// holds a live authorization (the sandbox answers 404 for approved ones).
func TestDisconnectNotFound(t *testing.T) {
	_, srv := newFake(t)
	c := newTestClient(t, srv, obsdk.Personal)
	s := &obsdk.Session{Version: 1, Bank: bankKey, Country: "FI", Segment: obsdk.Personal, Env: obsdk.Sandbox, Integration: integrationID,
		Consents: map[string]obsdk.Consent{"accounts": {ID: "auth-stuck", Kind: "accounts"}}}
	dr, err := c.Disconnect(context.Background(), s)
	if err != nil || len(dr.Closed) != 0 || dr.Failed["accounts"] == "" || len(dr.Session.Consents) != 1 {
		t.Fatalf("stuck = %+v, %v", dr, err)
	}
	s.Consents["accounts"] = obsdk.Consent{ID: "auth-gone", Kind: "accounts"}
	dr, err = c.Disconnect(context.Background(), s)
	if err != nil || len(dr.Closed) != 1 || len(dr.Session.Consents) != 0 {
		t.Fatalf("gone = %+v, %v", dr, err)
	}
}
