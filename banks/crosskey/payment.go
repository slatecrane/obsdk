package crosskey

import (
	"fmt"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/obie"
)

// Payments differ by bank (rules from each bank's Payment Initiation API
// page on crosskey.io):
//
//   - Finnish banks (S-Pankki, Aktia, POP, Ålandsbanken FI) take SEPA and SEPA
//     Instant credit transfers through the *international* payment API, single
//     or scheduled; scheduled ones can be deleted before they run.
//   - Ålandsbanken SE takes Swedish domestic payments: account transfers
//     (Dataclearing, BBAN), Bankgiro and Plusgiro, single or scheduled.
//   - Morrow Bank takes domestic credit transfers in FI (EUR, IBAN), NO (NOK,
//     BBAN) and SE (SEK, BBAN), single only.

const bicPattern = `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`

var amountField = obsdk.PaymentField{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,13}(\.\d{1,2})?$`, Label: "Amount"}

func debtorField(schemes ...string) obsdk.PaymentField {
	return obsdk.PaymentField{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: schemes, Label: "Pay from",
		Note: "Leave empty to let the user pick the account on the bank's page."}
}

var idFields = []obsdk.PaymentField{
	{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35, Note: "Generated when empty."},
	{Path: obsdk.FieldInstructionID, Use: obsdk.FieldOptional, MaxLength: 35, Note: "Generated when empty."},
}

// ---- Finland: SEPA through the international payment API ----

func sepaSpecs() []obsdk.PaymentSpec {
	fields := func(instant bool) []obsdk.PaymentField {
		f := []obsdk.PaymentField{
			amountField,
			debtorField(obsdk.SchemeIBAN),
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
			{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address",
				Note: "Structured only: town and country are required when an address is given; unstructured lines are refused."},
			{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message"},
			{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}, MaxLength: 35, Label: "Reference"},
		}
		if !instant {
			f = append(f, obsdk.PaymentField{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: bicPattern, Label: "Payee bank BIC"})
		}
		f = append(f, idFields...)
		return append(f, obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
			Note: "Makes a scheduled payment, which can be cancelled before it runs. Its status then only says whether it was scheduled."})
	}
	return []obsdk.PaymentSpec{
		{Type: obsdk.PaymentSEPA, Countries: []obsdk.Country{"FI"}, Currencies: []string{"EUR"}, MaxTransfers: 1,
			AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted}, Cancellable: true,
			Fields: fields(false),
			Notes:  []string{"AcceptedSettlementCompleted means settled on the payer's account, not yet at the payee's bank."}},
		{Type: obsdk.PaymentSEPAInstant, Countries: []obsdk.Country{"FI"}, Currencies: []string{"EUR"}, MaxTransfers: 1,
			AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted}, Cancellable: true,
			Fields: fields(true),
			Notes:  []string{"The final status usually comes with the submission; Pending means the payee's bank has not confirmed yet."}},
	}
}

type intlInitiation struct {
	InstructionIdentification  string        `json:"InstructionIdentification"`
	EndToEndIdentification     string        `json:"EndToEndIdentification"`
	LocalInstrument            string        `json:"LocalInstrument"`
	RequestedExecutionDateTime string        `json:"RequestedExecutionDateTime,omitempty"`
	CurrencyOfTransfer         string        `json:"CurrencyOfTransfer"`
	InstructedAmount           obie.Amount   `json:"InstructedAmount"`
	DebtorAccount              *obie.Account `json:"DebtorAccount,omitempty"`
	Creditor                   *party        `json:"Creditor,omitempty"`
	CreditorAgent              *agent        `json:"CreditorAgent,omitempty"`
	CreditorAccount            obie.Account  `json:"CreditorAccount"`
	RemittanceInformation      *remittance   `json:"RemittanceInformation,omitempty"`
}

type party struct {
	Name          string   `json:"Name,omitempty"`
	PostalAddress *address `json:"PostalAddress,omitempty"`
}

type address struct {
	StreetName     string `json:"StreetName,omitempty"`
	BuildingNumber string `json:"BuildingNumber,omitempty"`
	PostCode       string `json:"PostCode,omitempty"`
	TownName       string `json:"TownName"`
	Country        string `json:"Country"`
}

type agent struct {
	SchemeName     string `json:"SchemeName"`
	Identification string `json:"Identification"`
}

type remittance struct {
	Unstructured string `json:"Unstructured,omitempty"`
	Reference    string `json:"Reference,omitempty"`
}

// ids returns the transfer's instruction and end-to-end ids, generated when empty.
func ids(t obsdk.Transfer, newID func() string) (instr, e2e string) {
	instr, e2e = t.InstructionID, t.EndToEndID
	if instr == "" {
		instr = obie.ShortID(newID(), 35)
	}
	if e2e == "" {
		e2e = obie.ShortID(newID(), 35)
	}
	return instr, e2e
}

func remittanceOf(t obsdk.Transfer) *remittance {
	var r remittance
	if len(t.Remittance) > 0 {
		r.Unstructured = t.Remittance[0]
	}
	if t.Reference != nil {
		r.Reference = t.Reference.Value
	}
	if r == (remittance{}) {
		return nil
	}
	return &r
}

// executionDateTime puts a payment date at midday UTC, which keeps the date
// in every Nordic time zone.
func executionDateTime(date string) string { return date + "T12:00:00+00:00" }

func debtorAccount(r obsdk.PaymentRequest, scheme string) *obie.Account {
	if r.Debtor == nil || r.Debtor.Account == nil || r.Debtor.Account.Value == "" {
		return nil
	}
	return &obie.Account{SchemeName: scheme, Identification: r.Debtor.Account.Value}
}

func buildSEPA(r obsdk.PaymentRequest, _ obsdk.Target, newID func() string) (string, any, any, error) {
	t := r.Transfers[0]
	ini := intlInitiation{
		LocalInstrument: "UK.OBIE.SEPACreditTransfer", CurrencyOfTransfer: "EUR",
		InstructedAmount:      obie.Amount{Amount: obie.Decimal(t.Amount.Amount), Currency: t.Amount.Currency},
		DebtorAccount:         debtorAccount(r, "UK.OBIE.IBAN"),
		CreditorAccount:       obie.Account{SchemeName: "UK.OBIE.IBAN", Identification: t.Creditor.Account.Value, Name: t.Creditor.Name},
		RemittanceInformation: remittanceOf(t),
	}
	ini.InstructionIdentification, ini.EndToEndIdentification = ids(t, newID)
	if r.Type == obsdk.PaymentSEPAInstant {
		ini.LocalInstrument = "UK.OBIE.SEPAInstantCreditTransfer"
	} else if a := t.Creditor.Agent; a != nil && a.BIC != "" {
		ini.CreditorAgent = &agent{SchemeName: "UK.OBIE.BICFI", Identification: a.BIC}
	}
	if a := t.Creditor.Address; a != nil {
		if len(a.Lines) > 0 || a.Town == "" || a.Country == "" {
			return "", nil, nil, fmt.Errorf("%w: the payee address needs a town and a country, and no unstructured lines (EPC rules from November 2026)", obsdk.ErrInvalidRequest)
		}
		ini.Creditor = &party{Name: t.Creditor.Name, PostalAddress: &address{StreetName: a.Street, BuildingNumber: a.BuildingNumber,
			PostCode: a.PostCode, TownName: a.Town, Country: a.Country}}
	}
	family := "international"
	if r.ExecutionDate != "" {
		family = "international-scheduled"
		ini.RequestedExecutionDateTime = executionDateTime(r.ExecutionDate)
	}
	return family, ini, nil, nil
}

// ---- Sweden (Ålandsbanken SE): domestic payments ----

type domInitiation struct {
	InstructionIdentification  string        `json:"InstructionIdentification"`
	EndToEndIdentification     string        `json:"EndToEndIdentification"`
	LocalInstrument            string        `json:"LocalInstrument,omitempty"`
	RequestedExecutionDateTime string        `json:"RequestedExecutionDateTime,omitempty"`
	InstructedAmount           obie.Amount   `json:"InstructedAmount"`
	DebtorAccount              *obie.Account `json:"DebtorAccount,omitempty"`
	CreditorAccount            obie.Account  `json:"CreditorAccount"`
	RemittanceInformation      *remittance   `json:"RemittanceInformation,omitempty"`
}

func swedishSpecs() []obsdk.PaymentSpec {
	f := []obsdk.PaymentField{
		amountField,
		debtorField(obsdk.SchemeIBAN),
		{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Label: "Payee account",
			Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeBankgiro, obsdk.SchemePlusgiro},
			SchemeRules: []obsdk.SchemeRule{{Scheme: obsdk.SchemeBBAN, Pattern: `^[0-9]{6,16}$`, Label: "Clearing and account number",
				Note: "Clearing number followed by the account number, digits only."}}},
		{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 35, Label: "Payee name"},
		{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 12, Label: "Message",
			Note: "Some Bankgiro and Plusgiro payees require a message or an OCR number."},
		{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceOCR}, Label: "OCR number",
			OnlyWith: &obsdk.FieldCondition{Path: obsdk.FieldCreditorAccount, Schemes: []string{obsdk.SchemeBankgiro, obsdk.SchemePlusgiro}}},
	}
	f = append(f, idFields...)
	f = append(f, obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
		Note: "Makes a scheduled payment, which can be cancelled before it runs."})
	return []obsdk.PaymentSpec{{
		Type: obsdk.PaymentDomestic, Countries: []obsdk.Country{"SE"}, Currencies: []string{"SEK"}, MaxTransfers: 1,
		AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted}, Cancellable: true,
		Fields: f,
	}}
}

var swedishSchemes = map[string][2]string{ // SDK scheme -> OBIE scheme, local instrument
	obsdk.SchemeBBAN:     {"UK.OBIE.BBAN", "SE.Dataclearing"},
	obsdk.SchemeBankgiro: {"SE.BGNR", "SE.Bankgiro"},
	obsdk.SchemePlusgiro: {"SE.PGNR", "SE.Plusgiro"},
}

func buildSwedish(r obsdk.PaymentRequest, _ obsdk.Target, newID func() string) (string, any, any, error) {
	t := r.Transfers[0]
	sch, ok := swedishSchemes[t.Creditor.Account.Scheme]
	if !ok {
		return "", nil, nil, fmt.Errorf("%w: payee account scheme %q", obsdk.ErrInvalidRequest, t.Creditor.Account.Scheme)
	}
	ini := domInitiation{
		LocalInstrument:       sch[1],
		InstructedAmount:      obie.Amount{Amount: obie.Decimal(t.Amount.Amount), Currency: t.Amount.Currency},
		DebtorAccount:         debtorAccount(r, "UK.OBIE.IBAN"),
		CreditorAccount:       obie.Account{SchemeName: sch[0], Identification: t.Creditor.Account.Value, Name: t.Creditor.Name},
		RemittanceInformation: remittanceOf(t),
	}
	ini.InstructionIdentification, ini.EndToEndIdentification = ids(t, newID)
	family := "domestic"
	if r.ExecutionDate != "" {
		family = "domestic-scheduled"
		ini.RequestedExecutionDateTime = executionDateTime(r.ExecutionDate)
	}
	return family, ini, nil, nil
}

// ---- Morrow Bank: domestic credit transfers in FI, NO and SE ----

// morrowMarkets: country -> currency and account scheme (payee and payer).
var morrowMarkets = map[obsdk.Country]struct{ currency, scheme, obie string }{
	"FI": {"EUR", obsdk.SchemeIBAN, "UK.OBIE.IBAN"},
	"NO": {"NOK", obsdk.SchemeBBAN, "UK.OBIE.BBAN"},
	"SE": {"SEK", obsdk.SchemeBBAN, "UK.OBIE.BBAN"},
}

func morrowSpecs() []obsdk.PaymentSpec {
	var specs []obsdk.PaymentSpec
	for _, c := range []obsdk.Country{"FI", "NO", "SE"} {
		m := morrowMarkets[c]
		f := []obsdk.PaymentField{
			amountField,
			debtorField(m.scheme),
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{m.scheme}, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 35, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message"},
			{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, MaxLength: 35, Label: "Reference",
				Note: "The national creditor reference (Finnish viitenumero, Norwegian KID) or RF."},
		}
		specs = append(specs, obsdk.PaymentSpec{
			Type: obsdk.PaymentDomestic, Countries: []obsdk.Country{c}, Currencies: []string{m.currency}, MaxTransfers: 1,
			AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
			Fields: append(f, idFields...),
			Notes:  []string{"Domestic only: the market follows the currency and account scheme; cross-border settlement is not supported."},
		})
	}
	return specs
}

func buildMorrow(r obsdk.PaymentRequest, tg obsdk.Target, newID func() string) (string, any, any, error) {
	t := r.Transfers[0]
	m, ok := morrowMarkets[tg.Country]
	if !ok {
		return "", nil, nil, fmt.Errorf("%w: Morrow Bank payments in %s", obsdk.ErrUnsupported, tg.Country)
	}
	ini := domInitiation{
		InstructedAmount:      obie.Amount{Amount: obie.Decimal(t.Amount.Amount), Currency: t.Amount.Currency},
		DebtorAccount:         debtorAccount(r, m.obie),
		CreditorAccount:       obie.Account{SchemeName: m.obie, Identification: t.Creditor.Account.Value, Name: t.Creditor.Name},
		RemittanceInformation: remittanceOf(t),
	}
	ini.InstructionIdentification, ini.EndToEndIdentification = ids(t, newID)
	return "domestic", ini, nil, nil
}
