package obsdk

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

var payNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func sepaSpec() PaymentSpec {
	return PaymentSpec{
		Type: PaymentSEPA, Currencies: []string{"EUR"}, ExecutionDateMaxDays: 30,
		Fields: []PaymentField{
			{Path: FieldDebtorAccount, Use: FieldRequired, Ask: true, Schemes: []string{SchemeIBAN}},
			{Path: FieldCreditorAccount, Use: FieldRequired, Schemes: []string{SchemeIBAN}, Pattern: `^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$`},
			{Path: FieldCreditorName, Use: FieldRequired, MaxLength: 70},
			{Path: FieldRemittance, Use: FieldOptional, MaxItems: 1, MaxLength: 140},
			{Path: FieldReference, Use: FieldOptional, Schemes: []string{ReferenceRF}},
			{Path: FieldEndToEndID, Use: FieldRequired, MaxLength: 35},
			{Path: FieldExecutionDate, Use: FieldOptional},
			{Path: FieldChargeBearer, Use: FieldOptional, Options: []Option{{Value: ChargeBearerService}}},
		},
	}
}

func goodSEPA() PaymentRequest {
	return PaymentRequest{Type: PaymentSEPA, Transfers: []Transfer{{
		Amount:     Money{Amount: "10.50", Currency: "EUR"},
		Creditor:   Creditor{Name: "Jane Doe", Account: Identifier{Scheme: SchemeIBAN, Value: "EE382200221020145685"}},
		Remittance: []string{"invoice 42"}, EndToEndID: "e2e-1",
	}}}
}

func issues(err error) []string {
	var ve *PaymentValidationError
	if !errors.As(err, &ve) {
		return nil
	}
	var out []string
	for _, i := range ve.Issues {
		out = append(out, i.Path+"="+i.Code)
	}
	sort.Strings(out)
	return out
}

func TestValidatePaymentAcceptsGoodRequest(t *testing.T) {
	if err := sepaSpec().Validate(goodSEPA(), payNow); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePaymentIssues(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*PaymentRequest)
		want []string
	}{
		{"wrong type", func(r *PaymentRequest) { r.Type = PaymentDomestic }, []string{"type=type"}},
		{"no transfers", func(r *PaymentRequest) { r.Transfers = nil }, []string{"transfers=required"}},
		{"bulk on single-only", func(r *PaymentRequest) { r.Transfers = append(r.Transfers, r.Transfers[0]) }, []string{"transfers=too_many"}},
		{"required missing", func(r *PaymentRequest) { r.Transfers[0].Creditor.Name, r.Transfers[0].EndToEndID = "", "" },
			[]string{FieldEndToEndID + "=required", FieldCreditorName + "=required"}},
		{"creditor account missing", func(r *PaymentRequest) { r.Transfers[0].Creditor.Account = Identifier{} }, []string{FieldCreditorAccount + "=required"}},
		{"too long", func(r *PaymentRequest) { r.Transfers[0].Creditor.Name = strings.Repeat("ä", 71) }, []string{FieldCreditorName + "=too_long"}},
		{"too many lines", func(r *PaymentRequest) { r.Transfers[0].Remittance = []string{"a", "b"} }, []string{FieldRemittance + "=too_many"}},
		{"pattern", func(r *PaymentRequest) { r.Transfers[0].Creditor.Account.Value = "ee38 2200" }, []string{FieldCreditorAccount + "=invalid", FieldCreditorAccount + "=pattern"}},
		{"check digits", func(r *PaymentRequest) { r.Transfers[0].Creditor.Account.Value = "EE382200221020145686" }, []string{FieldCreditorAccount + "=invalid"}},
		{"scheme", func(r *PaymentRequest) { r.Transfers[0].Creditor.Account.Scheme = SchemeBBAN }, []string{FieldCreditorAccount + "=scheme"}},
		{"reference scheme", func(r *PaymentRequest) {
			r.Transfers[0].Reference = &Reference{Scheme: ReferenceOCR, Value: "1234567897"}
		}, []string{FieldReference + "=scheme"}},
		{"option", func(r *PaymentRequest) { r.ChargeBearer = ChargeBearerDebtor }, []string{FieldChargeBearer + "=option"}},
		{"unsupported", func(r *PaymentRequest) {
			r.Context = PaymentContextOther
			r.Transfers[0].Creditor.Address = &PostalAddress{Country: "EE"}
		}, []string{FieldContext + "=unsupported", FieldCreditorAddress + "=unsupported", FieldCreditorCountry + "=unsupported"}},
		{"payee bank unsupported", func(r *PaymentRequest) {
			r.Transfers[0].Creditor.Agent = &Agent{Name: "NatWest", Address: &PostalAddress{Town: "London", Country: "GB"}}
		}, []string{FieldCreditorBankAddress + "=unsupported", FieldCreditorBankName + "=unsupported"}},
		{"currency not accepted", func(r *PaymentRequest) { r.Transfers[0].Amount.Currency = "SEK" }, []string{FieldAmount + "=currency"}},
		{"currency malformed", func(r *PaymentRequest) { r.Transfers[0].Amount.Currency = "eur" }, []string{FieldAmount + "=currency"}},
		{"amount zero", func(r *PaymentRequest) { r.Transfers[0].Amount.Amount = "0.00" }, []string{FieldAmount + "=amount"}},
		{"amount comma", func(r *PaymentRequest) { r.Transfers[0].Amount.Amount = "1,50" }, []string{FieldAmount + "=amount"}},
		{"date past", func(r *PaymentRequest) { r.ExecutionDate = "2026-10-01" }, []string{FieldExecutionDate + "=date"}},
		{"date too far", func(r *PaymentRequest) { r.ExecutionDate = "2026-12-01" }, []string{FieldExecutionDate + "=date"}},
		{"date malformed", func(r *PaymentRequest) { r.ExecutionDate = "14.10.2026" }, []string{FieldExecutionDate + "=date"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := goodSEPA()
			tt.mod(&r)
			err := sepaSpec().Validate(r, payNow)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			}
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if got := issues(err); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("issues = %v, want %v", got, want)
			}
		})
	}
}

func TestValidatePaymentAskedFieldMayBeEmpty(t *testing.T) {
	s := sepaSpec()
	r := goodSEPA()
	r.ExecutionDate = "2026-10-14" // today is fine
	if err := s.Validate(r, payNow); err != nil {
		t.Fatalf("debtor account is Ask, so it may be empty: %v", err)
	}
	s.Fields[0].Ask = false
	if got := issues(s.Validate(r, payNow)); len(got) != 1 || got[0] != FieldDebtorAccount+"=required" {
		t.Errorf("issues = %v", got)
	}
}

func TestValidatePaymentIndexesTransfers(t *testing.T) {
	s := sepaSpec()
	s.MaxTransfers = 5
	r := goodSEPA()
	bad := r.Transfers[0]
	bad.Creditor.Name = ""
	r.Transfers = append(r.Transfers, bad)
	err := s.Validate(r, payNow)
	var ve *PaymentValidationError
	if !errors.As(err, &ve) || len(ve.Issues) != 1 || ve.Issues[0].Index != 1 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "transfers[1].creditor.name") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestInfoPaymentSpec(t *testing.T) {
	i := Info{Payments: []PaymentSpec{
		{Type: PaymentDomestic, Countries: []Country{"SE"}},
		{Type: PaymentSEPA, Countries: []Country{"EE", "LV"}, Segments: []Segment{Business}},
		{Type: PaymentCrossBorder},
	}}
	if _, ok := i.PaymentSpec("se", Personal, PaymentDomestic); !ok {
		t.Error("domestic SE not found")
	}
	if _, ok := i.PaymentSpec("EE", Personal, PaymentSEPA); ok {
		t.Error("SEPA is business only")
	}
	if _, ok := i.PaymentSpec("EE", "", PaymentSEPA); !ok {
		t.Error("empty segment matches any")
	}
	if got := i.PaymentTypes("LV", Business); len(got) != 2 || got[0] != PaymentSEPA || got[1] != PaymentCrossBorder {
		t.Errorf("types = %v", got)
	}
}
