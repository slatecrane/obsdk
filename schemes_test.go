package obsdk

import (
	"strings"
	"testing"
)

func TestValidateIdentifier(t *testing.T) {
	tests := []struct {
		id Identifier
		ok bool
	}{
		{Identifier{SchemeIBAN, "EE382200221020145685"}, true},
		{Identifier{SchemeIBAN, "GB33BUKB20201555555555"}, true},
		{Identifier{SchemeIBAN, "EE382200221020145686"}, false}, // check digits
		{Identifier{SchemeIBAN, "EE38 2200 2210 2014 5685"}, false},
		{Identifier{SchemeIBAN, "ee382200221020145685"}, false},
		{Identifier{SchemeBankgiro, "5051-6905"}, true},
		{Identifier{SchemeBankgiro, "50516905"}, true},
		{Identifier{SchemeBankgiro, "5051-6904"}, false},
		{Identifier{SchemeBankgiro, "51-6905"}, false}, // too short
		{Identifier{SchemePlusgiro, "1234-4"}, true},
		{Identifier{SchemePlusgiro, "1234-5"}, false},
		{Identifier{SchemePlusgiro, "4"}, false}, // too short
		{Identifier{SchemeSortCodeAccount, "11223321325698"}, true},
		{Identifier{SchemeSortCodeAccount, "112233-21325698"}, false},
		{Identifier{SchemeBBAN, "8327-9,123456789"}, true}, // no common format
		{Identifier{"BANK_SPECIFIC", "anything"}, true},
	}
	for _, tt := range tests {
		if err := ValidateIdentifier(tt.id); (err == nil) != tt.ok {
			t.Errorf("%s %q: err = %v, want ok=%v", tt.id.Scheme, tt.id.Value, err, tt.ok)
		}
	}
}

func TestValidateReference(t *testing.T) {
	tests := []struct {
		r  Reference
		ok bool
	}{
		{Reference{ReferenceOCR, "1234567897"}, true},
		{Reference{ReferenceFI, "1232"}, true},
		{Reference{ReferenceFI, "1009"}, true},
		{Reference{ReferenceFI, "1233"}, false},
		{Reference{ReferenceFI, "0001232"}, false},
		{Reference{ReferenceFI, "123"}, false},
		{Reference{ReferenceOCR, "1234567890"}, false},
		{Reference{ReferenceOCR, "12 34"}, false},
		{Reference{ReferenceRF, "RF18539007547034"}, true},
		{Reference{ReferenceRF, "RF19539007547034"}, false},
		{Reference{ReferenceRF, "rf18539007547034"}, false},
		{Reference{ReferenceBE, "012345678939"}, true},
		{Reference{ReferenceBE, "123456789002"}, true},
		{Reference{ReferenceBE, "000000009797"}, true}, // remainder 0 gives 97
		{Reference{ReferenceBE, "000000009700"}, false},
		{Reference{ReferenceBE, "123456789003"}, false},
		{Reference{ReferenceBE, "+++123/4567/89002+++"}, false},
		{Reference{ReferenceBE, "12345678900"}, false},
	}
	for _, tt := range tests {
		if err := ValidateReference(tt.r); (err == nil) != tt.ok {
			t.Errorf("%s %q: err = %v, want ok=%v", tt.r.Scheme, tt.r.Value, err, tt.ok)
		}
	}
}

// A Swedish-style domestic spec: one type, payee by account or giro number,
// OCR only for giro payees.
func giroSpec() PaymentSpec {
	return PaymentSpec{Type: PaymentDomestic, Currencies: []string{"SEK"}, Fields: []PaymentField{
		{Path: FieldCreditorAccount, Use: FieldRequired, Schemes: []string{SchemeBBAN, SchemeBankgiro},
			SchemeRules: []SchemeRule{{Scheme: SchemeBBAN, MaxLength: 16, Pattern: `^[0-9,-]+$`}}},
		{Path: FieldReference, Use: FieldOptional, Schemes: []string{ReferenceOCR},
			OnlyWith: &FieldCondition{Path: FieldCreditorAccount, Schemes: []string{SchemeBankgiro}}},
	}}
}

func TestValidateSchemeRulesAndConditions(t *testing.T) {
	req := func(acc Identifier, ref *Reference) PaymentRequest {
		return PaymentRequest{Type: PaymentDomestic, Transfers: []Transfer{{
			Amount: Money{Amount: "10.00", Currency: "SEK"}, Creditor: Creditor{Account: acc}, Reference: ref}}}
	}
	ocr := &Reference{Scheme: ReferenceOCR, Value: "1234567897"}
	tests := []struct {
		name string
		r    PaymentRequest
		want string
	}{
		{"giro with OCR", req(Identifier{SchemeBankgiro, "5051-6905"}, ocr), ""},
		{"account without OCR", req(Identifier{SchemeBBAN, "8327-9,123456789"}, nil), ""},
		{"giro check digit", req(Identifier{SchemeBankgiro, "5051-6904"}, nil), FieldCreditorAccount + "=invalid"},
		{"BBAN rule length", req(Identifier{SchemeBBAN, "8327-9,1234567890"}, nil), FieldCreditorAccount + "=too_long"},
		{"BBAN rule pattern", req(Identifier{SchemeBBAN, "8327 9"}, nil), FieldCreditorAccount + "=pattern"},
		{"BBAN rule not applied to giro", req(Identifier{SchemeBankgiro, "5051-6905"}, nil), ""},
		{"OCR for account payee", req(Identifier{SchemeBBAN, "8327-9,123456789"}, ocr), FieldReference + "=unsupported"},
		{"OCR check digit", req(Identifier{SchemeBankgiro, "5051-6905"}, &Reference{ReferenceOCR, "1234567890"}), FieldReference + "=invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(issues(giroSpec().Validate(tt.r, payNow)), ",")
			if got != tt.want {
				t.Errorf("issues = %q, want %q", got, tt.want)
			}
		})
	}
}
