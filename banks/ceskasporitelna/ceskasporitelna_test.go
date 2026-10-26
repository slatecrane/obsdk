package ceskasporitelna

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"github.com/slatecrane/obsdk/obsdktest"
)

func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

var frozen = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

const (
	testIBAN  = "CZ1208000000000259459101"
	payeeIBAN = "CZ6508000000192000145399"
)

func testConfig(srv *httptest.Server) obsdk.Config {
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "csecret", RedirectURL: "https://www.example.com/cb"},
		HTTPClient:  http.DefaultClient,
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{paramAPIKey: "key-1"},
	}
	if srv != nil {
		cfg.HTTPClient = srv.Client()
		cfg.Extra[paramBaseURL] = srv.URL
		cfg.Extra[paramIDPURL] = srv.URL + "/idp"
	}
	return cfg
}

func newTestClient(t *testing.T, srv *httptest.Server) *client {
	t.Helper()
	c, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "CZ"}, testConfig(srv))
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func pisSession() *obsdk.Session {
	exp := frozen.Add(5 * time.Minute)
	return &obsdk.Session{Version: 1, Bank: bankKey, Country: "CZ", Segment: obsdk.Personal, Env: obsdk.Sandbox,
		Integration: integrationID, AccessToken: "pt", RefreshToken: "prt", AccessExpiresAt: &exp, Scope: "PISP",
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{}}
}

// fake records the requests it gets and answers from a handler.
type fake struct {
	reqs   []*http.Request
	bodies []string
	h      func(w http.ResponseWriter, r *http.Request)
}

func (f *fake) server(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.reqs = append(f.reqs, r)
		f.bodies = append(f.bodies, string(b))
		f.h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConfig(t *testing.T) {
	cfg := testConfig(nil)
	delete(cfg.Extra, paramAPIKey)
	_, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "CZ"}, cfg)
	if !errors.Is(err, obsdk.ErrInvalidConfig) || !strings.Contains(err.Error(), "api_key") {
		t.Fatalf("missing api_key: got %v", err)
	}
	cfg = testConfig(nil)
	cfg.Env = obsdk.Production
	_, err = obsdk.New(obsdk.Target{Bank: bankKey, Country: "CZ"}, cfg)
	if !errors.Is(err, obsdk.ErrInvalidConfig) || !strings.Contains(err.Error(), "seal") {
		t.Fatalf("production without seal: got %v", err)
	}
}

func TestAuthorizeURL(t *testing.T) {
	c := newTestClient(t, nil)
	u, err := url.Parse(c.authorizeURL(scopeAIS, "https://www.example.com/cb", "st"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "webapi.developers.erstegroup.com" || u.Path != "/api/csas/sandbox/v1/sandbox-idp/auth" ||
		q.Get("scope") != "AISP" || q.Get("access_type") != "offline" || q.Get("client_id") != "cid" || q.Get("state") != "st" {
		t.Fatalf("got %s", u)
	}
}

func TestConnectCallbackErrors(t *testing.T) {
	c := newTestClient(t, nil)
	step, err := c.Connect(context.Background(), obsdk.ConnectRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Resume(context.Background(), step.State, obsdk.StepInput{Callback: "https://www.example.com/cb#error=access_denied&error_description=USER_CANCELLED_ACCESS"})
	if !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("cancelled: got %v", err)
	}
	_, err = c.Resume(context.Background(), step.State, obsdk.StepInput{Callback: "?code=x&state=other"})
	if !errors.Is(err, obsdk.ErrAuthFailed) {
		t.Fatalf("state mismatch: got %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	c := newTestClient(t, nil)
	r := func(status int, body string) *resp {
		return &resp{status: status, header: http.Header{"Web-Api-Correlation-Id": {"corr"}}, body: []byte(body)}
	}
	if err := c.apiErr(opAccounts, r(403, `{"status":403,"errors":[{"error":"TOKEN_INVALID"}]}`)); !errors.Is(err, obsdk.ErrAccessExpired) {
		t.Errorf("TOKEN_INVALID: got %v", err)
	}
	if err := c.apiErr(opPayment, r(403, `{"status":403,"errors":[{"error":"KEY_UNAUTHORIZED"}]}`)); !errors.Is(err, obsdk.ErrInvalidConfig) {
		t.Errorf("KEY_UNAUTHORIZED: got %v", err)
	}
	if err := c.apiErr(opAccounts, r(429, `{"errors":[{"error":"REQUEST_QUOTA_EXCEEDED"}]}`)); !errors.Is(err, obsdk.ErrRateLimited) {
		t.Errorf("quota: got %v", err)
	}
	if err := c.apiErr(opRefresh, r(400, `{"error":"request_error","error_code":"7109","error_description":"Parameter 'refresh_token' is invalid."}`)); !errors.Is(err, obsdk.ErrReauthRequired) {
		t.Errorf("refresh: got %v", err)
	}
	ae := c.apiErr(opPayment, r(400, `{"errors":[{"error":"FIELD_INVALID","scope":"amount.instructedAmount.value","message":"bad"}]}`)).(*obsdk.APIError)
	if ae.Code != "FIELD_INVALID" || ae.RequestID != "corr" || !strings.Contains(ae.Text, "amount.instructedAmount.value") {
		t.Errorf("got %+v", ae)
	}
}

func payRequest() obsdk.PaymentRequest {
	return obsdk.PaymentRequest{
		Type:   obsdk.PaymentDomestic,
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: testIBAN}},
		Transfers: []obsdk.Transfer{{
			Amount:     obsdk.Money{Amount: "12.50", Currency: "CZK"},
			Creditor:   obsdk.Creditor{Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: payeeIBAN}},
			Remittance: []string{"obsdk test"},
			Reference:  &obsdk.Reference{Scheme: obsdk.ReferenceCZ, Value: "1234567890"},
		}},
		IdempotencyKey: "3987b4fa-a057-44d8",
	}
}

func TestBuildBody(t *testing.T) {
	c := newTestClient(t, nil)
	b, err := c.buildBody(payRequest())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"paymentIdentification":{"instructionIdentification":"3987B4FAA05744D8"},"paymentTypeInformation":{"instructionPriority":"NORM"},` +
		`"amount":{"instructedAmount":{"value":12.50,"currency":"CZK"}},"debtorAccount":{"identification":{"iban":"` + testIBAN + `"}},` +
		`"creditorAccount":{"identification":{"iban":"` + payeeIBAN + `"}},` +
		`"remittanceInformation":{"structured":{"creditorReferenceInformation":{"reference":["VS:1234567890"]}},"unstructured":"obsdk test"}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}

	r := payRequest()
	r.Type, r.ExecutionDate = obsdk.PaymentSEPA, "2026-10-27"
	r.Transfers[0].Amount.Currency, r.Transfers[0].Reference, r.Transfers[0].EndToEndID = "EUR", nil, "E2E1"
	r.Transfers[0].Creditor = obsdk.Creditor{Name: "Max Mustermann", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE89370400440532013000"},
		Address: &obsdk.PostalAddress{Country: "DE"}}
	spec, _ := c.Info().PaymentSpec("CZ", "", obsdk.PaymentSEPA)
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatalf("SEPA: %v", err)
	}
	b, err = c.buildBody(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`"endToEndIdentification":"E2E1"`, `"requestedExecutionDate":"2026-10-27"`, `"chargeBearer":"SHA"`,
		`"creditor":{"name":"Max Mustermann","postalAddress":{"country":"DE"}}`} {
		if !strings.Contains(string(b), part) {
			t.Errorf("SEPA body has no %s: %s", part, b)
		}
	}
	r.Transfers[0].Creditor.Address = nil
	if err := spec.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("SEPA without the payee's country: got %v", err)
	}
}

func standingRequest() obsdk.PaymentRequest {
	r := payRequest()
	r.Schedule = &obsdk.Schedule{Frequency: obsdk.FrequencyMonthly, StartDate: "2026-11-05", EndDate: "2027-10-05"}
	return r
}

func TestBuildStandingBody(t *testing.T) {
	c := newTestClient(t, nil)
	spec, ok := c.Info().StandingOrderSpec("CZ", "", obsdk.PaymentDomestic)
	if !ok {
		t.Fatal("no standing-order spec")
	}
	r := standingRequest()
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatal(err)
	}
	b, err := c.buildStandingBody(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"standingOrderIdentification":{"instructionIdentification":"3987B4FAA05744D8"},` +
		`"standingOrder":{"execution":{"mode":"UNTIL_DATE","modeDue":"DUE_DAY_OF_MONTH","interval":"MONTHLY"},"validity":{"lastExecutionDate":"2027-10-05"}},` +
		`"amount":{"instructedAmount":{"value":12.50,"currency":"CZK"}},"requestedExecutionDate":"2026-11-05",` +
		`"debtorAccount":{"identification":{"iban":"` + testIBAN + `"}},"creditorAccount":{"identification":{"iban":"` + payeeIBAN + `"}},` +
		`"remittanceInformation":{"structured":{"creditorReferenceInformation":{"reference":["VS:1234567890"]}},"unstructured":"obsdk test"}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}

	r.Schedule = &obsdk.Schedule{Frequency: obsdk.FrequencyAnnual, StartDate: "2026-11-30", EndOfMonth: true}
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatal(err)
	}
	if b, err = c.buildStandingBody(r); err != nil || !strings.Contains(string(b),
		`"execution":{"mode":"UNTIL_CANCELLATION","modeDue":"DUE_LAST_DAY_OF_MONTH","interval":"YEARLY"}}`) {
		t.Fatalf("until cancelled, month end: %s %v", b, err)
	}
	r.Schedule.StartDate = "2026-11-28"
	if _, err := c.buildStandingBody(r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("month end on the 28th: %v", err)
	}

	for name, mod := range map[string]func(*obsdk.Schedule){
		"weekly":       func(s *obsdk.Schedule) { s.Frequency = obsdk.FrequencyWeekly },
		"today":        func(s *obsdk.Schedule) { s.StartDate = "2026-10-23" },
		"day 30":       func(s *obsdk.Schedule) { s.StartDate = "2026-11-30" },
		"count":        func(s *obsdk.Schedule) { s.EndDate, s.Count = "", 12 },
		"business day": func(s *obsdk.Schedule) { s.NonBusinessDay = obsdk.ScheduleFollowing },
	} {
		r := standingRequest()
		mod(r.Schedule)
		if err := spec.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	r = standingRequest()
	r.ExecutionDate = "2026-11-05"
	if err := spec.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("execution date on a standing order: got %v", err)
	}
}

// TestStandingOrderFlow creates and signs a standing order on a saved
// payment login: its own resources, no status call after the poll.
func TestStandingOrderFlow(t *testing.T) {
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/payment-initiation/my/standingorders":
			_, _ = io.WriteString(w, `{"standingOrderIdentification":{"instructionIdentification":"3987B4FAA05744D8"},
"debtorAccount":{"identification":{"iban":"`+testIBAN+`"}},"signInfo":{"signId":"S2","hash":"h2","state":"OPEN"},"instructionStatus":"ACTC"}`)
		case r.URL.Path == "/payment-initiation/my/standingorders/federate/sign/S2/hash/h2":
			_, _ = io.WriteString(w, `{"signingUrl":"https://sign.example/so","poll":{"id":"P2","interval":3000}}`)
		case r.URL.Path == "/payment-initiation/my/standingorders/sign/poll/P2":
			_, _ = io.WriteString(w, `{"state":"DONE","pollInterval":3000}`)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
		}
	}}
	c := newTestClient(t, f.server(t))
	ctx := context.Background()
	r := standingRequest()
	r.Session = pisSession()
	step, err := c.InitiatePayment(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if step.Redirect == nil || step.Redirect.URL != "https://sign.example/so" || step.Payment.ID != "S2" || step.Payment.Status != obsdk.PaymentReceived {
		t.Fatalf("sign step: %+v", step)
	}
	if !strings.Contains(f.bodies[0], `"interval":"MONTHLY"`) {
		t.Fatalf("body: %s", f.bodies[0])
	}
	step, err = c.Resume(ctx, step.State, obsdk.StepInput{Callback: "https://www.example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	p := step.Payment
	if step.Kind != obsdk.StepDone || p.Status != obsdk.PaymentAccepted || !p.Final || p.Schedule == nil || p.Schedule.Frequency != obsdk.FrequencyMonthly {
		t.Fatalf("done: %+v", p)
	}
	if len(f.reqs) != 3 {
		t.Fatalf("%d requests, want 3 (no status call)", len(f.reqs))
	}
	if _, err := c.PaymentStatus(ctx, p.Ref, obsdk.PaymentCallOptions{Session: step.Session}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("status: %v", err)
	}
	if _, err := c.CancelPayment(ctx, p.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("cancel: %v", err)
	}
}

// TestPaymentFlow drives login, creation, signing, a poll that is still
// processing, and the status against a fake ČS.
func TestPaymentFlow(t *testing.T) {
	poll := []string{"PROCESSING", "DONE"}
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/idp/token":
			_, _ = io.WriteString(w, `{"access_token":"pt","refresh_token":"prt","token_type":"bearer","expires_in":300,"scope":"PISP"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/payment-initiation/my/payments":
			_, _ = io.WriteString(w, `{"paymentIdentification":{"instructionIdentification":"X","transactionIdentification":"TPP1"},
"debtorAccount":{"identification":{"iban":"`+testIBAN+`"}},"signInfo":{"signId":"S1","hash":"h/1","state":"OPEN"},"instructionStatus":"ACTC"}`)
		case strings.HasPrefix(r.URL.Path, "/payment-initiation/my/payments/federate/sign/"):
			_, _ = io.WriteString(w, `{"validTo":"2026-10-24T12:10:00Z","signingUrl":"https://sign.example/x","poll":{"id":"P1","interval":2000},"signInfo":{"state":"OPEN","signId":"S1"}}`)
		case r.URL.Path == "/payment-initiation/my/payments/sign/poll/P1":
			_, _ = io.WriteString(w, `{"state":"`+poll[0]+`","pollInterval":2000}`)
			poll = poll[1:]
		case r.URL.Path == "/payment-initiation/my/payments/S1/status":
			_, _ = io.WriteString(w, `{"instructionStatus":"ACSP"}`)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
		}
	}}
	c := newTestClient(t, f.server(t))
	ctx := context.Background()
	step, err := c.InitiatePayment(ctx, payRequest())
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != obsdk.StepRedirect || !strings.Contains(step.Redirect.URL, "scope=PISP") {
		t.Fatalf("login step: %+v", step)
	}
	step, err = c.Resume(ctx, step.State, obsdk.StepInput{Callback: "?code=c1&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	if step.Redirect.URL != "https://sign.example/x" || step.Payment.ID != "TPP1" || step.Session == nil {
		t.Fatalf("sign step: %+v", step)
	}
	sign := f.reqs[2]
	if sign.URL.EscapedPath() != "/payment-initiation/my/payments/federate/sign/S1/hash/h%2F1" || sign.Header.Get("Callback-Uri") != "https://www.example.com/cb" ||
		sign.Header.Get("Web-Api-Key") != "key-1" || sign.Header.Get("Authorization") != "Bearer pt" {
		t.Fatalf("signing request %s %v", sign.URL, sign.Header)
	}
	if f.reqs[0].Header.Get("Web-Api-Key") != "" || !strings.Contains(f.bodies[0], "client_secret=csecret") {
		t.Fatalf("token request: %v %s", f.reqs[0].Header, f.bodies[0])
	}
	step, err = c.Resume(ctx, step.State, obsdk.StepInput{Callback: "https://www.example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != obsdk.StepWait || step.WaitFor != 2*time.Second {
		t.Fatalf("processing: %+v", step)
	}
	step, err = c.Resume(ctx, step.State, obsdk.StepInput{})
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != obsdk.StepDone || step.Payment.Status != obsdk.PaymentInProgress || step.Payment.ID != "TPP1" {
		t.Fatalf("done: %+v", step)
	}

	res, err := c.PaymentStatus(ctx, step.Payment.Ref, obsdk.PaymentCallOptions{Session: step.Session})
	if err != nil || res.Data.BankStatus != "ACSP" {
		t.Fatalf("status: %+v %v", res, err)
	}
	if _, err := c.PaymentStatus(ctx, step.Payment.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("status without session: %v", err)
	}
	if _, err := c.CancelPayment(ctx, step.Payment.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestPaymentRejectedAtSigning(t *testing.T) {
	f := &fake{h: func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			_, _ = io.WriteString(w, `{"paymentIdentification":{"transactionIdentification":"TPP1"},"signInfo":{"signId":"S1","hash":"h","state":"OPEN"},"instructionStatus":"ACTC"}`)
		case strings.Contains(r.URL.Path, "/federate/"):
			_, _ = io.WriteString(w, `{"signingUrl":"https://sign.example/x","poll":{"id":"P1","interval":5000}}`)
		default:
			_, _ = io.WriteString(w, `{"state":"REJECTED"}`)
		}
	}}
	c := newTestClient(t, f.server(t))
	r := payRequest()
	r.Session = pisSession()
	step, err := c.InitiatePayment(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Resume(context.Background(), step.State, obsdk.StepInput{Callback: "https://www.example.com/cb"})
	var fe *obsdk.FlowError
	if !errors.Is(err, obsdk.ErrAuthFailed) || !errors.As(err, &fe) || fe.Session == nil || fe.Payment == nil {
		t.Fatalf("rejected: got %v", err)
	}
}

// TestSign checks the payment signature: the Digest of ČS's worked example,
// the signed headers and a signature that verifies with the QSealC.
func TestSign(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Self-signed, so the issuer is the subject.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0x99C11D), Subject: pkix.Name{CommonName: "I.CA Test Qualified 2 CA/RSA 02/2016", Country: []string{"CZ"}},
		NotBefore: frozen.Add(-time.Hour), NotAfter: frozen.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	cfg := testConfig(nil)
	cfg.Seal = &obsdk.Seal{Key: key, Certificate: cert}
	cl, err := obsdk.New(obsdk.Target{Bank: bankKey, Country: "CZ"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := cl.(*client)

	body := `{"paymentIdentification":{"instructionIdentification":"TPP1234567890"},"paymentTypeInformation":{"instructionPriority":"NORM"},"amount":{"instructedAmount":{"value":1.0,"currency":"CZK"}},"debtorAccount":{"identification":{"iban":"CZ6108000000000189501043"}},"creditorAccount":{"identification":{"iban":"CZ5108000000000102902339"}},"remittanceInformation":{"structured":{"creditorReferenceInformation":{"reference":["VS:1234","KS:9","SS:5678"]}},"unstructured":"Test"}}`
	hr, _ := http.NewRequest(http.MethodPost, "https://x/my/payments", strings.NewReader(body))
	hr.Header.Set("Authorization", "Bearer tok")
	hr.Header.Set("Web-Api-Key", "bb5d5379")
	if err := c.sign(hr, []byte(body)); err != nil {
		t.Fatal(err)
	}
	if got := hr.Header.Get("Digest"); got != "SHA-256=+S7SDWZX754e789wyLlhkS/1USCFvs+xIGyyNlMbAk4=" {
		t.Fatalf("digest %s", got)
	}
	m := regexp.MustCompile(`^keyId="(.*)",algorithm="SHA256withRSA",headers="([^"]*)",signature="([^"]*)"$`).FindStringSubmatch(hr.Header.Get("Signature"))
	if m == nil || m[1] != "SN=99c11d,CA=CN=I.CA Test Qualified 2 CA/RSA 02/2016,C=CZ" || m[2] != "authorization date digest web-api-key" {
		t.Fatalf("signature header %q", hr.Header.Get("Signature"))
	}
	signing := "authorization: Bearer tok\ndate: " + frozen.Format(http.TimeFormat) + "\ndigest: " + hr.Header.Get("Digest") + "\nweb-api-key: bb5d5379"
	sig, _ := base64.StdEncoding.DecodeString(m[3])
	sum := sha256.Sum256([]byte(signing))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if hr.Header.Get("TPP-Signature-Certificate") != base64.StdEncoding.EncodeToString(der) {
		t.Fatal("TPP-Signature-Certificate is not the QSealC")
	}
}
