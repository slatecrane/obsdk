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

// PeriodicOptions tunes PeriodicSpec to a bank.
type PeriodicOptions struct {
	// Frequencies offered; default all eight of the standard.
	Frequencies []obsdk.Frequency
	// EndOfMonth: dayOfExecution "31" (the month's last day) is accepted.
	EndOfMonth bool
	// ExecutionRule: executionRule (following / preceding) is accepted.
	ExecutionRule bool
	// StartDateMinDays is the earliest first execution, in days from today.
	StartDateMinDays int
	Notes            []string
}

var frequencyLabels = map[obsdk.Frequency]string{
	obsdk.FrequencyDaily: "Daily", obsdk.FrequencyWeekly: "Weekly", obsdk.FrequencyEveryTwoWeeks: "Every two weeks",
	obsdk.FrequencyMonthly: "Monthly", obsdk.FrequencyEveryTwoMonths: "Every two months", obsdk.FrequencyQuarterly: "Quarterly",
	obsdk.FrequencySemiannual: "Every six months", obsdk.FrequencyAnnual: "Yearly",
}

// PeriodicSpec is the standing-order spec (periodic-payments) of a single
// payment spec: the same transfer fields without the execution date, plus
// the schedule. The standard has no execution count, so Count is not
// offered. The payment is cancellable when the single payment is.
func PeriodicSpec(single obsdk.PaymentSpec, o PeriodicOptions) obsdk.PaymentSpec {
	s := single
	s.ExecutionDateMaxDays = 0
	s.FinalStatuses = []obsdk.PaymentStatus{obsdk.PaymentAccepted}
	s.Schedule = &obsdk.ScheduleSpec{StartDateMinDays: o.StartDateMinDays}
	s.Fields = nil
	for _, f := range single.Fields {
		if f.Path != obsdk.FieldExecutionDate {
			s.Fields = append(s.Fields, f)
		}
	}
	freqs := o.Frequencies
	if len(freqs) == 0 {
		freqs = []obsdk.Frequency{obsdk.FrequencyDaily, obsdk.FrequencyWeekly, obsdk.FrequencyEveryTwoWeeks, obsdk.FrequencyMonthly,
			obsdk.FrequencyEveryTwoMonths, obsdk.FrequencyQuarterly, obsdk.FrequencySemiannual, obsdk.FrequencyAnnual}
	}
	opts := make([]obsdk.Option, len(freqs))
	for i, f := range freqs {
		opts[i] = obsdk.Option{Value: string(f), Label: frequencyLabels[f]}
	}
	s.Fields = append(s.Fields,
		obsdk.PaymentField{Path: obsdk.FieldScheduleFrequency, Use: obsdk.FieldRequired, Label: "Frequency", Options: opts},
		obsdk.PaymentField{Path: obsdk.FieldScheduleStartDate, Use: obsdk.FieldRequired, Label: "First payment",
			Note: "Sets the day of the later payments."},
		obsdk.PaymentField{Path: obsdk.FieldScheduleEndDate, Use: obsdk.FieldOptional, Label: "Last payment",
			Note: "Empty: until it is cancelled."},
	)
	if o.EndOfMonth {
		s.Fields = append(s.Fields, obsdk.PaymentField{Path: obsdk.FieldScheduleEndOfMonth, Use: obsdk.FieldOptional, Label: "On the last day of the month"})
	}
	if o.ExecutionRule {
		s.Fields = append(s.Fields, obsdk.PaymentField{Path: obsdk.FieldScheduleNonBusinessDay, Use: obsdk.FieldOptional, Label: "On a non-business day",
			Options: []obsdk.Option{{Value: obsdk.ScheduleFollowing, Label: "Next business day"}, {Value: obsdk.SchedulePreceding, Label: "Business day before"}}})
	}
	s.Notes = append(append([]string{}, single.Notes...), o.Notes...)
	return s
}
