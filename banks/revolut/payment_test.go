package revolut

import (
	"context"
	"crypto"
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
	"testing"

	obsdk "github.com/slatecrane/obsdk"
)

// verifyDetached checks an x-jws-signature over body and returns its header.
func verifyDetached(t *testing.T, key *rsa.PublicKey, sig string, body []byte) map[string]any {
	t.Helper()
	parts := strings.Split(sig, ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("not a detached JWS: %q", sig)
	}
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(input))
	raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPSS(key, crypto.SHA256, sum[:], raw, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("JWS does not verify over the sent body: %v", err)
	}
	var h map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &h)
	return h
}

type payBank struct {
	consent, payment []byte // bodies received
	keys             []string
}

func fakePayBank(t *testing.T, key *rsa.PrivateKey, pb *payBank) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/token":
			_ = r.ParseForm()
			q, _ := url.ParseQuery(string(body))
			switch q.Get("grant_type") {
			case "client_credentials":
				if q.Get("scope") != "payments" {
					t.Errorf("client token scope %q", q.Get("scope"))
				}
				fmt.Fprint(w, `{"access_token":"cc","token_type":"Bearer","expires_in":2399}`)
			case "authorization_code":
				fmt.Fprint(w, `{"access_token":"pay-at","token_type":"Bearer","expires_in":86376}`)
			}
		case strings.HasSuffix(r.URL.Path, "-payment-consents") && r.Method == http.MethodPost:
			h := verifyDetached(t, &key.PublicKey, r.Header.Get("x-jws-signature"), body)
			if h[tanClaim] != "example.org" || h["kid"] != "kid-1" || h["typ"] != "JOSE" {
				t.Errorf("JWS header %v", h)
			}
			if r.Header.Get("Authorization") != "Bearer cc" {
				t.Errorf("consent auth %q", r.Header.Get("Authorization"))
			}
			pb.consent = body
			pb.keys = append(pb.keys, r.Header.Get("x-idempotency-key"))
			w.WriteHeader(201)
			fmt.Fprint(w, `{"Data":{"ConsentId":"pc-1","Status":"AwaitingAuthorisation"}}`)
		case r.URL.Path == "/domestic-payments" && r.Method == http.MethodPost:
			verifyDetached(t, &key.PublicKey, r.Header.Get("x-jws-signature"), body)
			if r.Header.Get("Authorization") != "Bearer pay-at" {
				t.Errorf("payment auth %q", r.Header.Get("Authorization"))
			}
			pb.payment = body
			pb.keys = append(pb.keys, r.Header.Get("x-idempotency-key"))
			w.WriteHeader(201)
			fmt.Fprint(w, `{"Data":{"DomesticPaymentId":"dp-1","Status":"Pending","ConsentId":"pc-1",
				"Initiation":{"DebtorAccount":{"SchemeName":"UK.OBIE.SortCodeAccountNumber","Identification":"80200110203345"}}}}`)
		case r.URL.Path == "/domestic-payments/dp-1" && r.Method == http.MethodGet:
			if r.Header.Get("Authorization") != "Bearer cc" {
				t.Errorf("status auth %q", r.Header.Get("Authorization"))
			}
			fmt.Fprint(w, `{"Data":{"DomesticPaymentId":"dp-1","Status":"AcceptedSettlementCompleted"}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
}

func gbPayment() obsdk.PaymentRequest {
	return obsdk.PaymentRequest{Type: obsdk.PaymentDomestic, Context: obsdk.PaymentContextPartyToParty, Transfers: []obsdk.Transfer{{
		Amount:     obsdk.Money{Amount: "55", Currency: "GBP"},
		Creditor:   obsdk.Creditor{Name: "Receiver Co.", Account: obsdk.Identifier{Scheme: obsdk.SchemeSortCodeAccount, Value: "11223321325698"}},
		Remittance: []string{"Shipment fee"},
	}}}
}

func TestDomesticPaymentFlow(t *testing.T) {
	key := testKey(t)
	pb := &payBank{}
	srv := fakePayBank(t, key, pb)
	defer srv.Close()
	c := newTestClient(t, srv, key)
	c.cfg.Extra[paramJWSTan] = "example.org"
	ctx := context.Background()

	step, err := c.InitiatePayment(ctx, gbPayment())
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != obsdk.StepRedirect || step.Payment != nil {
		t.Fatalf("step %+v", step)
	}
	u, _ := url.Parse(step.Redirect.URL)
	if u.Query().Get("scope") != "payments" || u.Query().Get("state") != "state-1" {
		t.Fatalf("redirect %s", step.Redirect.URL)
	}
	var consent struct {
		Data struct{ Initiation initiation }
		Risk map[string]string
	}
	_ = json.Unmarshal(pb.consent, &consent)
	ini := consent.Data.Initiation
	if ini.InstructedAmount.Amount != "55.00" || ini.CreditorAccount.SchemeName != "UK.OBIE.SortCodeAccountNumber" ||
		ini.CreditorAccount.Name != "Receiver Co." || ini.RemittanceInformation["Reference"] != "Shipment fee" ||
		ini.EndToEndIdentification != "request1" || consent.Risk["PaymentContextCode"] != "PartyToParty" {
		t.Fatalf("consent body %s", pb.consent)
	}

	done, err := c.Resume(ctx, step.State, obsdk.StepInput{Callback: "https://app.example/cb?code=c1&state=state-1"})
	if err != nil {
		t.Fatal(err)
	}
	if done.Kind != obsdk.StepDone || done.Payment == nil || done.Payment.ID != "dp-1" ||
		done.Payment.Status != obsdk.PaymentAccepted || done.Payment.Final || done.Payment.Debtor == nil ||
		done.Payment.Debtor.Scheme != obsdk.SchemeSortCodeAccount {
		t.Fatalf("done %+v / %+v", done, done.Payment)
	}
	// The submission repeats the consent's Initiation and Risk exactly.
	var sub struct {
		Data struct {
			ConsentID  string          `json:"ConsentId"`
			Initiation json.RawMessage `json:"Initiation"`
		}
	}
	var con struct {
		Data struct {
			Initiation json.RawMessage `json:"Initiation"`
		}
	}
	_ = json.Unmarshal(pb.payment, &sub)
	_ = json.Unmarshal(pb.consent, &con)
	if sub.Data.ConsentID != "pc-1" || string(sub.Data.Initiation) != string(con.Data.Initiation) {
		t.Fatalf("submission %s", pb.payment)
	}
	if len(pb.keys) != 2 || pb.keys[0] == "" || pb.keys[1] == "" {
		t.Fatalf("idempotency keys %v", pb.keys)
	}

	res, err := c.PaymentStatus(ctx, done.Payment.Ref, obsdk.PaymentCallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Data.Status != obsdk.PaymentCompleted || !res.Data.Final {
		t.Fatalf("status %+v", res.Data)
	}
}

func TestPaymentValidationAndConfig(t *testing.T) {
	key := testKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected, got %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, key)
	ctx := context.Background()

	if _, err := c.InitiatePayment(ctx, gbPayment()); !errors.Is(err, obsdk.ErrInvalidConfig) {
		t.Errorf("missing jws_tan: %v", err)
	}
	c.cfg.Extra[paramJWSTan] = "example.org"
	r := gbPayment()
	r.Transfers[0].Remittance = []string{strings.Repeat("x", 19)} // Faster Payments: 18
	r.Transfers[0].Creditor.Account.Scheme = obsdk.SchemeIBAN
	var ve *obsdk.PaymentValidationError
	if _, err := c.InitiatePayment(ctx, r); !errors.As(err, &ve) || len(ve.Issues) != 2 {
		t.Errorf("want 2 issues, got %v", err)
	}
	r = gbPayment()
	r.Type = obsdk.PaymentSEPA
	if _, err := c.InitiatePayment(ctx, r); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Errorf("SEPA in GB: %v", err)
	}
	if _, err := c.CancelPayment(ctx, "x", obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Errorf("cancel: %v", err)
	}
	if _, err := c.PaymentStatus(ctx, "garbage", obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("bad ref: %v", err)
	}
}

func TestInternationalInitiation(t *testing.T) {
	c := &client{cfg: obsdk.Config{NewID: func(string) string { return "11111111-2222-3333-4444-555555555555" }}, target: obsdk.Target{Country: "DE"}}
	r := obsdk.PaymentRequest{Type: obsdk.PaymentCrossBorder, ChargeBearer: obsdk.ChargeBearerDebtor, ExecutionDate: "2026-11-02",
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "12.5", Currency: "USD"},
			Creditor: obsdk.Creditor{Name: "Acme Inc", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "GB33BUKB20201555555555"},
				Agent: &obsdk.Agent{BIC: "BUKBGB22"}, Address: &obsdk.PostalAddress{Town: "Austin", Country: "US"}}}}}
	spec, err := c.paymentSpec(obsdk.PaymentCrossBorder)
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatal(err)
	}
	family, ini, _ := c.buildInitiation(r, spec)
	if family != familyIntlScheduled || ini.CurrencyOfTransfer != "USD" || ini.ChargeBearer != "BorneByDebtor" ||
		ini.CreditorAgent.Identification != "BUKBGB22" || ini.Creditor.PostalAddress.Country != "US" ||
		ini.RequestedExecutionDateTime != "2026-11-02T12:00:00+00:00" || ini.EndToEndIdentification != "11111111222233334444555555555555"[:32] {
		t.Fatalf("family %s, initiation %+v", family, ini)
	}
	if len(ini.InstructionIdentification) > 35 || strings.Contains(ini.InstructionIdentification, "-") {
		t.Fatalf("instruction id %q", ini.InstructionIdentification)
	}
}

func TestPaymentSpecsByCountry(t *testing.T) {
	info, _ := obsdk.Lookup("revolut")
	if got := info.PaymentTypes("GB", obsdk.Personal); len(got) != 2 || got[0] != obsdk.PaymentDomestic || got[1] != obsdk.PaymentCrossBorder {
		t.Errorf("GB: %v", got)
	}
	if got := info.PaymentTypes("LT", obsdk.Business); len(got) != 2 || got[0] != obsdk.PaymentSEPA {
		t.Errorf("LT: %v", got)
	}
	if !info.Has(obsdk.CapPayments) {
		t.Error("CapPayments missing")
	}
}
