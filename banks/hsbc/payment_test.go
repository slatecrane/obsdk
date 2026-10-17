package hsbc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	obsdk "github.com/slatecrane/obsdk"
)

func domesticRequest() obsdk.PaymentRequest {
	return obsdk.PaymentRequest{Type: obsdk.PaymentDomestic, Context: obsdk.PaymentContextPartyToParty, Transfers: []obsdk.Transfer{{
		Amount:     obsdk.Money{Amount: "10.5", Currency: "GBP"},
		Creditor:   obsdk.Creditor{Name: "Payee Ltd", Account: obsdk.Identifier{Scheme: obsdk.SchemeSortCodeAccount, Value: "40053024615859"}},
		Remittance: []string{"INV-1234"},
	}}}
}

func TestBuildInitiation(t *testing.T) {
	c := newTestClient(t, nil, testKey(t), obsdk.Target{})
	r := domesticRequest()
	family, ini, risk := c.buildInitiation(r)
	b, _ := json.Marshal(ini)
	if family != familyDomestic || ini.LocalInstrument != "UK.OBIE.FPS" || ini.InstructedAmount.Amount != "10.5" ||
		!strings.Contains(string(b), `"RemittanceInformation":{"Structured":[{"CreditorReferenceInformation":{"Reference":"INV-1234"}}]}`) ||
		risk["PaymentContextCode"] != "TransferToThirdParty" || len(ini.EndToEndIdentification) > 31 {
		t.Errorf("initiation %s risk %v", b, risk)
	}
	r.ExecutionDate = "2026-11-02"
	family, ini, _ = c.buildInitiation(r)
	if family != familyDomesticScheduled || ini.RequestedExecutionDateTime != "2026-11-02T12:00:00+00:00" {
		t.Errorf("scheduled: %s %+v", family, ini)
	}
}

func TestPaymentValidation(t *testing.T) {
	c := newTestClient(t, nil, testKey(t), obsdk.Target{})
	spec, err := c.paymentSpec(obsdk.PaymentDomestic)
	if err != nil {
		t.Fatal(err)
	}
	r := domesticRequest()
	if err := spec.Validate(r, frozen); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	r.Transfers[0].Remittance = []string{"INV 1234"} // HSBC refuses spaces in the reference
	if err := spec.Validate(r, frozen); err == nil {
		t.Error("a reference with a space must be rejected")
	}
	r.Transfers[0].Remittance = nil
	if err := spec.Validate(r, frozen); err == nil {
		t.Error("the reference is required")
	}
	mt := newTestClient(t, nil, testKey(t), obsdk.Target{Bank: "hsbc", Country: "MT"})
	if _, err := mt.paymentSpec(obsdk.PaymentDomestic); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Errorf("Malta payments: want ErrUnsupported, got %v", err)
	}
}

func TestPaymentStatusCodes(t *testing.T) {
	cases := map[string]struct {
		s     obsdk.PaymentStatus
		final bool
	}{
		"ACSP": {obsdk.PaymentInProgress, false}, "ACCC": {obsdk.PaymentCompleted, true}, "RJCT": {obsdk.PaymentRejected, true},
		"PDNG": {obsdk.PaymentAccepted, false}, "INCO": {obsdk.PaymentInProgress, true}, "INFA": {obsdk.PaymentRejected, true},
		"CANC": {obsdk.PaymentCancelled, true}, "AcceptedSettlementCompleted": {obsdk.PaymentCompleted, true},
	}
	for code, want := range cases {
		if s, f := mapPaymentStatus(code); s != want.s || f != want.final {
			t.Errorf("%s: %s %v, want %s %v", code, s, f, want.s, want.final)
		}
	}
}

func TestPaymentFlow(t *testing.T) {
	var consentBody, paymentBody []byte
	var sigs []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case tokenPath:
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":300}`))
		case "/obie/open-banking/v4.0/pisp/domestic-payment-consents":
			consentBody = body
			sigs = append(sigs, r.Header.Get("x-jws-signature"))
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Data":{"ConsentId":"pc-1","Status":"AWAU"},"Risk":{}}`))
		case "/obie/open-banking/v4.0/pisp/domestic-payments":
			paymentBody = body
			sigs = append(sigs, r.Header.Get("x-jws-signature"))
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Data":{"DomesticPaymentId":"p-1","ConsentId":"pc-1","Status":"ACSP",
				"Initiation":{"DebtorAccount":{"SchemeName":"UK.OBIE.SortCodeAccountNumber","Identification":"40400411111111"}}}}`))
		case "/obie/open-banking/v4.0/pisp/domestic-payments/p-1":
			_, _ = w.Write([]byte(`{"Data":{"DomesticPaymentId":"p-1","Status":"ACCC"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testKey(t), obsdk.Target{})
	ctx := context.Background()
	st, err := c.InitiatePayment(ctx, domesticRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st.Redirect.URL, "scope=openid+payments") {
		t.Errorf("redirect: %s", st.Redirect.URL)
	}
	done, err := c.Resume(ctx, st.State, obsdk.StepInput{Callback: "https://app.example/cb#code=abc&state=state-1&id_token=x"})
	if err != nil {
		t.Fatal(err)
	}
	var cb, pb map[string]map[string]json.RawMessage
	_ = json.Unmarshal(consentBody, &cb)
	_ = json.Unmarshal(paymentBody, &pb)
	if string(cb["Data"]["Initiation"]) != string(pb["Data"]["Initiation"]) || string(pb["Data"]["ConsentId"]) != `"pc-1"` {
		t.Errorf("payment must resubmit the consent's Initiation:\n%s\n%s", consentBody, paymentBody)
	}
	for _, s := range sigs {
		if parts := strings.Split(s, "."); len(parts) != 3 || parts[1] != "" {
			t.Errorf("want a detached JWS, got %q", s)
		}
	}
	p := done.Payment
	if p.ID != "p-1" || p.Status != obsdk.PaymentInProgress || p.Debtor == nil || p.Debtor.Value != "40400411111111" {
		t.Fatalf("payment: %+v", p)
	}
	res, err := c.PaymentStatus(ctx, p.Ref, obsdk.PaymentCallOptions{})
	if err != nil || res.Data.Status != obsdk.PaymentCompleted || !res.Data.Final {
		t.Fatalf("status: %v %+v", err, res)
	}
	if _, err := c.CancelPayment(ctx, p.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Errorf("cancel: %v", err)
	}
}
