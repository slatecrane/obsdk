package swedbank

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

func bodyJSON(t *testing.T, b map[string]any) string {
	t.Helper()
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestPaymentBodies(t *testing.T) {
	ids := func(string) string { return "11111111-2222-3333-4444-555555555555" }
	se := &client{cfg: obsdk.Config{NewID: ids}, target: obsdk.Target{Country: "SE"}}
	ee := &client{cfg: obsdk.Config{NewID: ids}, target: obsdk.Target{Country: "EE"}}
	tr := func(acc obsdk.Identifier) obsdk.Transfer {
		return obsdk.Transfer{Amount: obsdk.Money{Amount: "10.00", Currency: "SEK"}, Creditor: obsdk.Creditor{Name: "Anna", Account: acc}}
	}

	giro := tr(obsdk.Identifier{Scheme: obsdk.SchemeBankgiro, Value: "5051-6905"})
	giro.Reference = &obsdk.Reference{Scheme: obsdk.ReferenceOCR, Value: "1234567890"}
	got := bodyJSON(t, se.paymentBody(obsdk.PaymentRequest{Type: obsdk.PaymentDomesticGiro, ExecutionDate: "2026-10-20", Transfers: []obsdk.Transfer{giro}}, productSEDomestic))
	want := `{"creditorAccount":{"bban":"BG 5051-6905"},"creditorFriendlyName":"Anna","executionDate":"2026-10-20","instructedAmount":{"amount":"10.00","currency":"SEK"},"remittanceInformationStructured":{"reference":"1234567890","referenceType":"OCR"}}`
	if got != want {
		t.Errorf("giro:\n got %s\nwant %s", got, want)
	}

	sepa := tr(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "EE382200221020145685"})
	sepa.Amount.Currency, sepa.Remittance = "EUR", []string{"inv 1"}
	debtor := obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "EE471000001020145685"}
	got = bodyJSON(t, ee.paymentBody(obsdk.PaymentRequest{Type: obsdk.PaymentSEPA, Debtor: &obsdk.PaymentDebtor{Account: &debtor}, Transfers: []obsdk.Transfer{sepa}}, productSEPA))
	want = `{"creditorAccount":{"iban":"EE382200221020145685"},"creditorName":"Anna","debtorAccount":{"iban":"EE471000001020145685"},"endToEndIdentification":"11111111222233334444555555555555","instructedAmount":{"amount":"10.00","currency":"EUR"},"remittanceInformationUnstructured":"inv 1"}`
	if got != want {
		t.Errorf("sepa:\n got %s\nwant %s", got, want)
	}

	intl := tr(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE89370400440532013000"})
	intl.Amount.Currency, intl.Remittance = "EUR", []string{"rent"}
	intl.Creditor.Agent = &obsdk.Agent{BIC: "COBADEFFXXX"}
	intl.Creditor.Address = &obsdk.PostalAddress{Town: "Berlin", Country: "DE"}
	got = bodyJSON(t, se.paymentBody(obsdk.PaymentRequest{Type: obsdk.PaymentCrossBorder, ChargeBearer: obsdk.ChargeBearerShared, Transfers: []obsdk.Transfer{intl}}, productSEIntl))
	want = `{"bic":"COBADEFFXXX","chargeBearer":"SHA","creditorAccount":{"iban":"DE89370400440532013000"},"creditorAddress":"Berlin, DE","creditorName":"Anna","instructedAmount":{"amount":"10.00","currency":"EUR"},"priority":"NORMAL","remittanceInformationUnstructured":"rent"}`
	if got != want {
		t.Errorf("international:\n got %s\nwant %s", got, want)
	}
}

func TestPaymentSpecsPerCountry(t *testing.T) {
	info, _ := obsdk.Lookup("swedbank")
	if got := info.PaymentTypes("SE", obsdk.Personal); len(got) != 3 {
		t.Errorf("SE: %v", got)
	}
	if got := info.PaymentTypes("LT", obsdk.Personal); len(got) != 3 || got[0] != obsdk.PaymentSEPA {
		t.Errorf("LT: %v", got)
	}
	se := &client{target: obsdk.Target{Country: "SE"}}
	if _, _, err := se.paymentSpec(obsdk.PaymentSEPA); !errors.Is(err, obsdk.ErrUnsupported) {
		t.Errorf("SEPA in SE: %v", err)
	}
	spec, product, err := se.paymentSpec(obsdk.PaymentCrossBorder)
	if err != nil || product != productSEIntl {
		t.Fatalf("%v %s", err, product)
	}
	// International from Sweden needs the debtor account, unlike domestic.
	r := obsdk.PaymentRequest{Type: obsdk.PaymentCrossBorder, ChargeBearer: obsdk.ChargeBearerShared, Transfers: []obsdk.Transfer{{
		Amount:     obsdk.Money{Amount: "1", Currency: "EUR"},
		Creditor:   obsdk.Creditor{Name: "A", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE89370400440532013000"}, Address: &obsdk.PostalAddress{Country: "DE"}},
		Remittance: []string{"x"},
	}}}
	var ve *obsdk.PaymentValidationError
	if err := spec.Validate(r, time.Now()); !errors.As(err, &ve) || len(ve.Issues) != 1 || ve.Issues[0].Path != obsdk.FieldDebtorAccount {
		t.Errorf("want debtor.account required, got %v", err)
	}
}
