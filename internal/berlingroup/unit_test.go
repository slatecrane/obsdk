package berlingroup

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

func TestAPIPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://bank.example/xs2a/v1/consents/abc/status": "/v1/consents/abc/status",
		"/v1/accounts/1/transactions?page=2":               "/v1/accounts/1/transactions?page=2",
		"http://localhost:8089/v1/payments/sepa/x=_=_y":    "/v1/payments/sepa/x=_=_y",
	} {
		if got, err := apiPath(in, ""); err != nil || got != want {
			t.Errorf("apiPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := apiPath("https://bank.example/login?x=1", ""); err == nil {
		t.Error("a link outside the XS2A API was accepted")
	}
	// A bank with its own version segment (SIBS) returns links with it, or
	// sometimes with plain v1; both become the canonical form.
	for in, want := range map[string]string{
		"https://site1.sibsapimarket.com/sibs/apimarket/BST/v1-0-4/consents/c1/status": "/v1/consents/c1/status",
		"BST/v1-0-4/accounts/a1/transactions?pageId=2":                                 "/v1/accounts/a1/transactions?pageId=2",
		"BST/v1/consents/c1": "/v1/consents/c1",
	} {
		if got, err := apiPath(in, "v1-0-4"); err != nil || got != want {
			t.Errorf("apiPath(%q, v1-0-4) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// A bank serving account information on v2 (Samlink) returns v2 links for
// consents and accounts and v1 links for payments; requests go back out on
// the version their path belongs to.
func TestAISPathVersion(t *testing.T) {
	p := &Profile{AISPathVersion: "v2"}
	for in, want := range map[string]string{
		"/psd2/v2/consents/c1/status":                       "/v1/consents/c1/status",
		"/psd2/v2/accounts/a1/transactions?x=1":             "/v1/accounts/a1/transactions?x=1",
		"/psd2/v1/payments/sepa-credit-transfers/p1/status": "/v1/payments/sepa-credit-transfers/p1/status",
	} {
		if got, err := apiPath(in, p.linkVersions()...); err != nil || got != want {
			t.Errorf("apiPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for path, want := range map[string]string{
		"/v1/consents": "v2", "/v1/consents/c1/status": "v2", "/v1/accounts?withBalance=true": "v2",
		"/v1/card-accounts/x": "v2", "/v1/funds-confirmations": "v2",
		"/v1/payments/sepa-credit-transfers": "v1", "/v1/consentsx": "v1",
	} {
		if got := p.versionFor(path); got != want {
			t.Errorf("versionFor(%q) = %q, want %q", path, got, want)
		}
	}
	if got := (&Profile{PathVersion: "v1-0-4"}).versionFor("/v1/consents"); got != "v1-0-4" {
		t.Errorf("without AISPathVersion: %q", got)
	}
}

func TestReferenceInEndToEnd(t *testing.T) {
	c := &client{p: &Profile{ReferenceInEndToEnd: true}}
	r := obsdk.PaymentRequest{Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "1.00", Currency: "EUR"},
		Creditor:  obsdk.Creditor{Name: "N", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI1445760010038426"}},
		Reference: &obsdk.Reference{Scheme: obsdk.ReferenceFI, Value: "1232"}}}}
	b, err := c.buildBody(r)
	if err != nil || b.EndToEndIdentification != "1232" || b.Structured != nil {
		t.Fatalf("body %+v, %v", b, err)
	}
	r.Transfers[0].EndToEndID = "other"
	if _, err := c.buildBody(r); err == nil {
		t.Error("a reference and a different end-to-end id: want an error")
	}
}

func TestNokURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://app.example/cb":         "https://app.example/cb?error=access_denied",
		"https://app.example/cb?s=1":     "https://app.example/cb?s=1&error=access_denied",
		"https://app.example/cb?s=1#tab": "https://app.example/cb?s=1&error=access_denied#tab",
	} {
		if got := nokURL(in); got != want {
			t.Errorf("nokURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseError(t *testing.T) {
	cases := []struct{ body, code, text string }{
		{`{"tppMessages":[{"category":"WARNING","code":"WARNING","text":"w"},{"category":"ERROR","code":"CONSENT_EXPIRED","text":"gone"}]}`, "CONSENT_EXPIRED", "gone"},
		{`{"tppMessages":{"category":"ERROR","code":"FORMAT_ERROR","text":"bad"}}`, "FORMAT_ERROR", "bad"},
		{`{"type":"https://berlin-group.org/v1/codes/x","title":"t","detail":"d","code":"TOKEN_INVALID"}`, "TOKEN_INVALID", "d"},
		{`{"additionalErrors":[{"title":"t","code":"PSU_CREDENTIALS_INVALID"}]}`, "PSU_CREDENTIALS_INVALID", "t"},
		{`not json`, "", "not json"},
	}
	for _, c := range cases {
		if code, text := parseError([]byte(c.body)); code != c.code || text != c.text {
			t.Errorf("parseError(%s) = %q, %q; want %q, %q", c.body, code, text, c.code, c.text)
		}
	}
}

func testClient(p Profile) *client {
	if p.Info.Name == "" {
		p.Info.Name = "Test Bank"
	}
	return &client{p: &p, cfg: obsdk.Config{Env: obsdk.Sandbox}}
}

func TestBookingStatus(t *testing.T) {
	booked := testClient(Profile{})
	both := testClient(Profile{BookingStatuses: []string{"booked", "pending", "both"}})
	separate := testClient(Profile{BookingStatuses: []string{"booked", "pending"}})
	type tc struct {
		c       *client
		st      []obsdk.TxStatus
		want    string
		errKind error
	}
	for i, x := range []tc{
		{booked, nil, "booked", nil},
		{booked, []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}, "booked", nil},
		{booked, []obsdk.TxStatus{obsdk.TxPending}, "", obsdk.ErrUnsupported},
		{both, []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}, "both", nil},
		{separate, []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}, "", obsdk.ErrUnsupported},
		{separate, []obsdk.TxStatus{obsdk.TxPending}, "pending", nil},
	} {
		got, err := x.c.bookingStatus(x.st)
		if got != x.want || !errors.Is(err, x.errKind) && (err != nil || x.errKind != nil) {
			t.Errorf("case %d: got %q, %v; want %q, %v", i, got, err, x.want, x.errKind)
		}
	}
}

func TestAccess(t *testing.T) {
	enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	global := testClient(Profile{})
	if got := enc(global.access(nil, nil)); got != `{"allPsd2":"allAccounts"}` {
		t.Errorf("global: %s", got)
	}
	offered := testClient(Profile{Consent: ConsentBankOffered})
	if got := enc(offered.access(nil, nil)); got != `{"accounts":[],"balances":[],"transactions":[]}` {
		t.Errorf("bank offered: %s", got)
	}
	got := enc(global.access([]obsdk.Capability{obsdk.CapBalances}, []string{"DE89370400440532013000"}))
	if got != `{"accounts":[{"iban":"DE89370400440532013000"}],"balances":[{"iban":"DE89370400440532013000"}]}` {
		t.Errorf("dedicated: %s", got)
	}
}

func TestConsentDays(t *testing.T) {
	p := Profile{MaxConsentDays: 180, DefaultConsentDays: 90}
	for in, want := range map[int]int{0: 90, 30: 30, 365: 180} {
		if got := p.consentDays(in); got != want {
			t.Errorf("consentDays(%d) = %d, want %d", in, got, want)
		}
	}
	if got := (&Profile{}).consentDays(0); got != 90 {
		t.Errorf("default consentDays = %d", got)
	}
}

func TestBuildBodyShapes(t *testing.T) {
	r := obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, Transfers: []obsdk.Transfer{{
		Amount:    obsdk.Money{Amount: "1.50", Currency: "EUR"},
		Creditor:  obsdk.Creditor{Name: "A", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE89370400440532013000"}, Address: &obsdk.PostalAddress{Street: "Main", Town: "Berlin", Country: "DE"}},
		Reference: &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"},
	}}}
	enc := func(c *client) string {
		b, err := c.buildBody(r)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal(b)
		return string(out)
	}
	v138 := enc(testClient(Profile{}))
	for _, want := range []string{`"streetName":"Main"`, `"townName":"Berlin"`, `"remittanceInformationStructured":{"reference":"RF18539007547034","referenceType":"SCOR","referenceIssuer":"ISO"}`} {
		if !strings.Contains(v138, want) {
			t.Errorf("1.3.8 body %s lacks %s", v138, want)
		}
	}
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceBE, Value: "123456789002"}
	if be := enc(testClient(Profile{})); !strings.Contains(be, `"remittanceInformationStructured":{"reference":"123456789002","referenceType":"SCOR","referenceIssuer":"BBA"}`) {
		t.Errorf("Belgian reference body %s", be)
	}
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}
	old := enc(testClient(Profile{LegacyAddress: true, StructuredRemittanceString: true}))
	for _, want := range []string{`"street":"Main"`, `"city":"Berlin"`, `"remittanceInformationStructured":"RF18539007547034"`} {
		if !strings.Contains(old, want) {
			t.Errorf("legacy body %s lacks %s", old, want)
		}
	}
}

func TestToTransactionDirection(t *testing.T) {
	tx, err := toTransaction([]byte(`{"transactionAmount":{"currency":"EUR","amount":"5.00"},"creditDebitIndicator":"DBIT","creditorName":"Shop","debtorName":"Me"}`), obsdk.TxBooked, "")
	if err != nil || tx.Direction != obsdk.Debit || tx.Amount.Amount != "-5.00" || tx.Counterparty.Name != "Shop" {
		t.Errorf("unsigned debit: %+v, %v", tx, err)
	}
	tx, _ = toTransaction([]byte(`{"transactionAmount":{"currency":"EUR","amount":"5.00"},"creditorName":"Me","debtorName":"Payer","remittanceInformationUnstructured":"x","remittanceInformationUnstructuredArray":["x","y"]}`), obsdk.TxPending, "")
	if tx.Direction != obsdk.Credit || tx.Counterparty.Name != "Payer" || strings.Join(tx.Remittance, "|") != "x|y" || tx.Status != obsdk.TxPending {
		t.Errorf("credit: %+v", tx)
	}
	// Samlink's pending payments: unsigned, no indicator, sent from the
	// queried account.
	own := "FI3745760010038400"
	tx, _ = toTransaction([]byte(`{"transactionAmount":{"currency":"EUR","amount":"12.34"},"creditorName":"Payee","creditorAccount":{"iban":"FI1445760010038426"},"debtorAccount":{"iban":"FI3745760010038400"}}`), obsdk.TxPending, own)
	if tx.Direction != obsdk.Debit || tx.Amount.Amount != "-12.34" || tx.Counterparty.Name != "Payee" {
		t.Errorf("unsigned outgoing: %+v", tx)
	}
	tx, _ = toTransaction([]byte(`{"transactionAmount":{"currency":"EUR","amount":"3.00"},"creditorAccount":{"iban":"FI3745760010038400"},"debtorAccount":{"iban":"FI3745760010038400"}}`), obsdk.TxPending, own)
	if tx.Direction != obsdk.Credit || tx.Amount.Amount != "3.00" {
		t.Errorf("transfer to itself: %+v", tx)
	}
}

// testSeal is a throwaway RSA key and self-signed certificate.
func testSeal(t *testing.T) *obsdk.Seal {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(0x9FA1), Subject: pkix.Name{CommonName: "TPP"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &obsdk.Seal{Key: key, Certificate: cert}
}

func TestSign(t *testing.T) {
	seal := testSeal(t)
	body := []byte(`{"a":1}`)
	hr, _ := http.NewRequest(http.MethodPost, "https://bank.example/v1/consents", nil)
	hr.Header.Set("X-Request-ID", "req-1")
	hr.Header.Set("PSU-ID", "user")
	hr.Header.Set("TPP-Redirect-URI", "https://app.example/cb")
	s := &Signing{Date: true}
	if err := s.sign(hr, body, seal, "Sun, 18 Oct 2026 09:00:00 GMT"); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if got := hr.Header.Get("Digest"); got != "SHA-256="+base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("Digest = %q", got)
	}
	if got := hr.Header.Get("TPP-Signature-Certificate"); got != base64.StdEncoding.EncodeToString(seal.Certificate.Raw) {
		t.Error("TPP-Signature-Certificate is not the certificate's DER")
	}
	m := regexp.MustCompile(`^keyId="([^"]+)",algorithm="SHA-256",headers="([^"]+)",signature="([^"]+)"$`).FindStringSubmatch(hr.Header.Get("Signature"))
	if m == nil {
		t.Fatalf("Signature = %q", hr.Header.Get("Signature"))
	}
	if m[1] != "SN=9FA1,CA=CN=TPP" { // self-signed: the issuer is the subject
		t.Errorf("keyId = %q", m[1])
	}
	if m[2] != "date digest x-request-id psu-id tpp-redirect-uri" {
		t.Errorf("headers = %q", m[2])
	}
	var lines []string
	for _, n := range strings.Fields(m[2]) {
		lines = append(lines, n+": "+hr.Header.Get(n))
	}
	sig, _ := base64.StdEncoding.DecodeString(m[3])
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	if err := rsa.VerifyPKCS1v15(seal.Key.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestIntegrationChecksProducts(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a payment spec without a payment product was accepted")
		}
	}()
	Integration(Profile{ID: "x", BaseURL: func(obsdk.Env, obsdk.Target, string) string { return "https://x" },
		Info: obsdk.Info{Bank: "x", Payments: []obsdk.PaymentSpec{{Type: obsdk.PaymentSEPA}}}})
}

func TestPeriodicBody(t *testing.T) {
	r := obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, Transfers: []obsdk.Transfer{{
		Amount:   obsdk.Money{Amount: "25.00", Currency: "EUR"},
		Creditor: obsdk.Creditor{Name: "A", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE89370400440532013000"}},
	}}}
	c := testClient(Profile{})
	for _, tc := range []struct {
		sc   obsdk.Schedule
		want string
	}{
		{obsdk.Schedule{Frequency: obsdk.FrequencyMonthly, StartDate: "2026-11-05", EndDate: "2027-10-05", NonBusinessDay: obsdk.ScheduleFollowing},
			`"startDate":"2026-11-05","endDate":"2027-10-05","executionRule":"following","frequency":"Monthly","dayOfExecution":"5"`},
		{obsdk.Schedule{Frequency: obsdk.FrequencySemiannual, StartDate: "2026-11-30", EndOfMonth: true},
			`"startDate":"2026-11-30","frequency":"SemiAnnual","dayOfExecution":"31"`},
		{obsdk.Schedule{Frequency: obsdk.FrequencyEveryTwoWeeks, StartDate: "2026-11-06"},
			`"startDate":"2026-11-06","frequency":"EveryTwoWeeks"}`},
	} {
		sc := tc.sc
		r.Schedule = &sc
		b, err := c.buildBody(r)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal(b)
		if !strings.Contains(string(out), tc.want) {
			t.Errorf("%+v: body %s lacks %s", sc, out, tc.want)
		}
	}

	p := &payState{Type: obsdk.PaymentSEPA, Product: "sepa-credit-transfers", ID: "P1", Periodic: true}
	if got := c.paymentPath(p); got != "/v1/periodic-payments/sepa-credit-transfers/P1" {
		t.Errorf("path %s", got)
	}
	c.p.ID = "test-bg"
	pay, err := c.paymentOf(p, "ACSP", nil)
	if err != nil || pay.Status != obsdk.PaymentAccepted {
		t.Fatalf("ACSP on a standing order: %+v %v", pay, err)
	}
	_, back, err := c.decodeRef(pay.Ref)
	if err != nil || !back.Periodic || c.paymentPath(back) != c.paymentPath(p) {
		t.Fatalf("ref round trip: %+v %v", back, err)
	}
}

func TestPeriodicSpec(t *testing.T) {
	single := CreditTransferSpec(obsdk.PaymentSEPA, SpecOptions{ExecutionDate: true, Cancellable: true})
	s := PeriodicSpec(single, PeriodicOptions{EndOfMonth: true, Frequencies: []obsdk.Frequency{obsdk.FrequencyMonthly}})
	if s.Schedule == nil || !s.Cancellable || len(s.FinalStatuses) != 1 || s.FinalStatuses[0] != obsdk.PaymentAccepted {
		t.Fatalf("spec %+v", s)
	}
	if _, ok := s.Field(obsdk.FieldExecutionDate); ok {
		t.Error("execution_date must go")
	}
	if f, ok := s.Field(obsdk.FieldScheduleFrequency); !ok || len(f.Options) != 1 {
		t.Errorf("frequency field %+v", f)
	}
	for path, want := range map[string]bool{obsdk.FieldScheduleEndOfMonth: true, obsdk.FieldScheduleNonBusinessDay: false, obsdk.FieldScheduleCount: false} {
		if _, ok := s.Field(path); ok != want {
			t.Errorf("%s offered = %v", path, ok)
		}
	}
	if _, ok := single.Field(obsdk.FieldExecutionDate); !ok {
		t.Error("PeriodicSpec changed the single spec's fields")
	}
}

func TestIntegrationRefusesPeriodicPain001(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a pain.001 profile with a standing-order spec was accepted")
		}
	}()
	single := obsdk.PaymentSpec{Type: obsdk.PaymentSEPA}
	Integration(Profile{ID: "x", BaseURL: func(obsdk.Env, obsdk.Target, string) string { return "https://x" }, PaymentXML: true,
		Products: map[obsdk.PaymentType]string{obsdk.PaymentSEPA: "pain.001-sepa-credit-transfers"},
		Info:     obsdk.Info{Bank: "x", Payments: []obsdk.PaymentSpec{single, PeriodicSpec(single, PeriodicOptions{})}}})
}
