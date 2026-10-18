package berlingroup

import obsdk "github.com/slatecrane/obsdk"

// BICPattern matches a BIC8 or BIC11.
const BICPattern = `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`

// SpecOptions tunes CreditTransferSpec to a bank.
type SpecOptions struct {
	Countries  []obsdk.Country
	Currencies []string // default EUR

	// DebtorOptional: the user may pick the account at the bank (redirect).
	// By default the debtor account is required, as most banks want it.
	DebtorOptional bool

	ExecutionDate        bool // requestedExecutionDate accepted
	ExecutionDateMaxDays int
	Cancellable          bool
	ChargeBearer         bool // chargeBearer accepted (cross-border)
	Address              bool // creditorAddress accepted
	EndToEndRequired     bool // endToEndIdentification must be set
	NoReference          bool // no structured creditor reference

	Approaches []string
	Notes      []string
}

// CreditTransferSpec is the PaymentSpec of a Berlin Group single credit
// transfer with the field limits of the standard (names 70 characters, one
// remittance line of 140, references and identifications of 35).
func CreditTransferSpec(t obsdk.PaymentType, o SpecOptions) obsdk.PaymentSpec {
	debtor := obsdk.PaymentField{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Pay from"}
	if o.DebtorOptional {
		debtor.Use, debtor.Ask = obsdk.FieldOptional, true
		debtor.Note = "Leave empty to let the user pick the account at the bank."
	}
	fields := []obsdk.PaymentField{
		{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,15}(\.\d{1,2})?$`, Label: "Amount"},
		debtor,
		{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, MaxLength: 34, Label: "Payee account"},
		{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
		{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: BICPattern, Label: "Payee bank BIC"},
		{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Description"},
		{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}, MaxLength: 35, Label: "Payment reference"},
		{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35},
	}
	kept := fields[:0]
	for _, f := range fields {
		switch {
		case f.Path == obsdk.FieldReference && o.NoReference:
			continue
		case f.Path == obsdk.FieldEndToEndID && o.EndToEndRequired:
			f.Use = obsdk.FieldRequired
		}
		kept = append(kept, f)
	}
	fields = kept
	if o.ExecutionDate {
		fields = append(fields, obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
			Note: "Empty means as soon as possible."})
	}
	if o.Address {
		fields = append(fields,
			obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address"},
			obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country"})
	}
	if o.ChargeBearer {
		fields = append(fields, obsdk.PaymentField{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldOptional, Options: []obsdk.Option{
			{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees"},
			{Value: obsdk.ChargeBearerCreditor, Label: "Payee pays all fees"},
			{Value: obsdk.ChargeBearerShared, Label: "Each pays their own bank"},
			{Value: obsdk.ChargeBearerService, Label: "As the scheme defines"},
		}})
	}
	cur := o.Currencies
	if len(cur) == 0 {
		cur = []string{"EUR"}
	}
	return obsdk.PaymentSpec{
		Type: t, Countries: o.Countries, Currencies: cur, MaxTransfers: 1,
		ExecutionDateMaxDays: o.ExecutionDateMaxDays, AuthApproaches: o.Approaches,
		FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted}, Cancellable: o.Cancellable,
		Fields: fields, Notes: o.Notes,
	}
}
