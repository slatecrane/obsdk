package sibs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/obsdktest"
)

var frozen = time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

// TestScenarios replays the scenarios recorded against the SIBS sandbox.
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

func TestASPSPCode(t *testing.T) {
	for in, want := range map[string]string{"BST": "BST", " bbpi ": "BBPI", "CCAML": "CCAML", "bnki": "BNKI",
		"TOTAPTPL": "BST", "TOTAPTPLXXX": "BST", "CGDIPTPLXXX": "CGDPT", "BKBKPTPL": "BNKI", "NEWBANK": "NEWBANK",
		"PT45 0035 0123 1234 5678 9015 4": "CGDPT"} {
		if got, err := ASPSPCode(in); err != nil || got != want {
			t.Errorf("ASPSPCode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "B", "BS-T", "BST/../x", "VERYLONGCODE123", "PT50003501231234567890155", "PT05999901231234567890154"} {
		if got, err := ASPSPCode(in); err == nil {
			t.Errorf("ASPSPCode(%q) = %q, want an error", in, got)
		}
	}
}

func TestKeyID(t *testing.T) {
	// The serial of the QSealC in the guide's signing example.
	serial, _ := new(big.Int).SetString("44ba0c31580926fcda18ddee8d1ac0a9", 16)
	if got := KeyID(&x509.Certificate{SerialNumber: serial}); got != "44ba0c31580926fcda18ddee8d1ac0a9" {
		t.Errorf("KeyID = %s", got)
	}
}

func TestPaymentCharset(t *testing.T) {
	spec, ok := Profile.Info.PaymentSpec("PT", obsdk.Personal, obsdk.PaymentSEPA)
	if !ok {
		t.Fatal("no SEPA spec")
	}
	r := obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, Transfers: []obsdk.Transfer{{
		Amount:     obsdk.Money{Amount: "10.00", Currency: "EUR"},
		Creditor:   obsdk.Creditor{Name: "João Conceição", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "PT50000201231234567890154"}},
		Remittance: []string{"Fatura 12/2026"},
	}}}
	var v *obsdk.PaymentValidationError
	if err := spec.Validate(r, frozen); err == nil || !asValidation(err, &v) || v.Issues[0].Path != obsdk.FieldCreditorName {
		t.Fatalf("accented payee name: err = %v", err)
	}
	r.Transfers[0].Creditor.Name = "Joao Conceicao"
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatalf("plain payee name: %v", err)
	}
}

func asValidation(err error, v **obsdk.PaymentValidationError) bool {
	e, ok := err.(*obsdk.PaymentValidationError)
	*v = e
	return ok
}

// fakeSIBS answers like the SIBS gateway for one ASPSP and records requests.
type fakeSIBS struct {
	mu   sync.Mutex
	reqs []*http.Request
	body map[string][]byte
}

func (f *fakeSIBS) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.body[r.Method+" "+r.URL.Path] = b
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method + " " + r.URL.Path {
	case "POST /BST/v1-0-4/consents":
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"consentStatus":"received","consentId":"c1","_links":{"scaRedirect":"https://bank.example/sca?id=c1","status":"BST/v1-0-4/consents/c1/status","self":"BST/v1-0-4/consents/c1"}}`)
	case "GET /BST/v1-0-4/consents/c1/status":
		io.WriteString(w, `{"consentStatus":"valid"}`)
	case "GET /BST/v1-0-4/consents/c1":
		io.WriteString(w, `{"access":{"allPsd2":"all-accounts"},"recurringIndicator":true,"validUntil":"2027-04-17T10:00:00","frequencyPerDay":4,"lastActionDate":"2026-10-19","consentStatus":"valid","_links":{}}`)
	case "GET /BST/v1-0-4/accounts":
		io.WriteString(w, `{"accounts":[{"resourceId":"a1","iban":"PT50000201231234567890154","currency":"EUR","name":"Conta Ordenado","_links":{"balances":"BST/v1-0-4/accounts/a1/balances","transactions":"BST/v1-0-4/accounts/a1/transactions"}}]}`)
	case "GET /BST/v1-0-4/accounts/a1/transactions":
		if r.URL.Query().Get("pageId") == "" {
			io.WriteString(w, `{"account":{"iban":"PT50000201231234567890154"},"transactions":{"booked":[{"entryReference":"e1","bookingDate":"2026-10-18","transactionAmount":{"currency":"EUR","amount":"-12.50"},"creditorName":"Loja"}],"_links":{"viewAccount":"BST/v1-0-4/accounts/a1","next":"BST/v1-0-4/accounts/a1/transactions?pageId=2&sig=x"}}}`)
			return
		}
		io.WriteString(w, `{"transactions":{"booked":[],"_links":{"viewAccount":"BST/v1-0-4/accounts/a1"}}}`)
	case "POST /BST/v1-0-4/payments/sepa-credit-transfers":
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"transactionStatus":"RCVD","paymentId":"p1","_links":{"redirect":"https://bank.example/pay?id=p1","status":"BST/v1-0-4/payments/sepa-credit-transfers/p1/status"}}`)
	case "GET /BST/v1-0-4/payments/sepa-credit-transfers/p1/status":
		io.WriteString(w, `{"transactionStatus":"ACSP"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"tppMessages":[{"category":"ERROR","code":"RESOURCE_UNIKNOWN","text":"`+r.Method+" "+r.URL.Path+`"}]}`)
	}
}

func TestRequestShape(t *testing.T) {
	f := &fakeSIBS{body: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	defer srv.Close()
	c, err := obsdk.New(obsdk.Target{Bank: Bank, Country: "PT"}, obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "the-client-id", RedirectURL: "https://app.example/cb"},
		HTTPClient:  srv.Client(),
		Extra:       map[string]string{ParamASPSP: "bst", "base_url": srv.URL + "/BST"},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect.URL != "https://bank.example/sca?id=c1" {
		t.Fatalf("step = %+v", st)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepDone || len(st.Accounts) != 1 || st.Session.Meta["institution"] != "BST" {
		t.Fatalf("step = %+v", st)
	}
	if v := st.Session.Consents["ais"].ValidUntil; v == nil || v.Format("2006-01-02") != "2027-04-17" {
		t.Errorf("consent valid until %v", v)
	}

	var body struct {
		Access     map[string]string `json:"access"`
		ValidUntil string            `json:"validUntil"`
	}
	if err := json.Unmarshal(f.body["POST /BST/v1-0-4/consents"], &body); err != nil {
		t.Fatal(err)
	}
	if body.Access["allPsd2"] != "all-accounts" || body.ValidUntil != "2027-04-17T10:00:00" {
		t.Errorf("consent body = %+v", body)
	}
	for _, r := range f.reqs {
		if r.Header.Get("X-IBM-Client-Id") != "the-client-id" || r.Header.Get("Date") != "2026-10-19T10:00:00.000Z" ||
			r.Header.Get("Signature") != "sandbox" || r.Header.Get("X-Request-ID") == "" {
			t.Errorf("%s %s: headers %v", r.Method, r.URL.Path, r.Header)
		}
		if r.URL.Path == "/BST/v1-0-4/accounts" && r.URL.Query().Has("withBalance") {
			t.Error("withBalance sent; SIBS does not support it")
		}
	}

	res, err := c.Transactions(ctx, st.Session, obsdk.TxQuery{AccountID: "a1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transactions) != 1 || res.Transactions[0].EntryReference != "e1" || res.NextCursor == "" {
		t.Fatalf("page 1 = %+v", res.TxPage)
	}
	if !strings.Contains(res.NextCursor, "pageId=2&sig=x") {
		t.Errorf("cursor %q lost the bank's query", res.NextCursor)
	}
	res, err = c.Transactions(ctx, st.Session, obsdk.TxQuery{AccountID: "a1", Cursor: res.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if res.NextCursor != "" {
		t.Errorf("page 2 cursor = %q", res.NextCursor)
	}
	last := f.reqs[len(f.reqs)-1]
	if last.URL.RawQuery != "pageId=2&sig=x" {
		t.Errorf("next link sent as %q; SIBS wants it unchanged", last.URL.RawQuery)
	}
}

// TestPaymentRedirect: SIBS names the approval link "redirect" (not
// scaRedirect); a Digest goes with the body only.
func TestPaymentRedirect(t *testing.T) {
	f := &fakeSIBS{body: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	defer srv.Close()
	c, err := obsdk.New(obsdk.Target{Bank: Bank, Country: "PT"}, obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "the-client-id", RedirectURL: "https://app.example/cb"},
		HTTPClient:  srv.Client(),
		Extra:       map[string]string{ParamASPSP: "BST", "base_url": srv.URL + "/BST"},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, err := c.InitiatePayment(ctx, obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, PSU: obsdk.PSUContext{IP: "203.0.113.7"},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "10.00", Currency: "EUR"},
			Creditor: obsdk.Creditor{Name: "Joao", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "PT50000201231234567890154"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepRedirect || st.Redirect.URL != "https://bank.example/pay?id=p1" {
		t.Fatalf("step = %+v", st)
	}
	st, err = c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != obsdk.StepDone || st.Payment.BankStatus != "ACSP" {
		t.Fatalf("step = %+v", st)
	}
	for _, r := range f.reqs {
		if hasBody := r.Method == http.MethodPost; (r.Header.Get("Digest") != "") != hasBody {
			t.Errorf("%s %s: Digest %q", r.Method, r.URL.Path, r.Header.Get("Digest"))
		}
	}
}
