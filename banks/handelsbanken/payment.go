package handelsbanken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/bgstatus"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payments: the TPP creates the payment with a client credentials token
// (scope PIS), the user approves it (scope "PIS:<id>", redirect or Mobile
// BankID, as for consents), and the token from that approval executes it
// with a PUT. Status is read with the client token.
//
// Sweden has its own API (v2, per segment). Domestic SEK payments go through
// a signing basket of sek-credit-transfers: one approval for up to 30 (100
// for business) transfers. GB, NL and LU each have a country API.

const purposePayment = "payment"

const (
	opPayment   = "payment"
	opPayExec   = "payment_execute"
	opPayStatus = "payment_status"
	opPayCancel = "payment_cancel"
)

// Payment products (path segments).
const (
	prodSEK      = "sek-credit-transfer" // only inside a signing basket
	prodInternal = "handelsbanken-domestic-credit-transfer"
	prodSEPA     = "sepa-credit-transfer"
	prodBritish  = "british-domestic-credit-transfer"
)

// payState is a payment's part of the flow.
type payState struct {
	Type    obsdk.PaymentType `json:"type"`
	Product string            `json:"product"`
	ID      string            `json:"id"`            // payment id, or the signing basket id
	IDs     []string          `json:"ids,omitempty"` // a basket's payment ids
	Body    json.RawMessage   `json:"body,omitempty"`
	Cancel  string            `json:"cancel,omitempty"` // cancellation id, when the flow approves a cancellation
	Create  json.RawMessage   `json:"create,omitempty"` // the request body, while waiting for the company id
}

// paymentRef is what Payment.Ref holds: enough to read the status, and for a
// Swedish single transfer the original payload, which a cancellation repeats.
type paymentRef struct {
	Integration string            `json:"i"`
	Type        obsdk.PaymentType `json:"t"`
	Product     string            `json:"p"`
	ID          string            `json:"id"`
	IDs         []string          `json:"ids,omitempty"`
	Body        json.RawMessage   `json:"b,omitempty"`
}

// ---- specs ----

const amountPattern = `^\d{1,10}(\.\d{1,2})?$`

func paymentSpecs() []obsdk.PaymentSpec {
	amount := obsdk.PaymentField{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: amountPattern, Label: "Amount"}
	date := obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
		Note: "Up to a year ahead. A future-dated Swedish payment can be cancelled until it is executed."}
	final := []obsdk.PaymentStatus{obsdk.PaymentCompleted}
	both := []string{"redirect", "decoupled"}
	redirect := []string{"redirect"}

	var out []obsdk.PaymentSpec

	// Sweden: domestic SEK through a signing basket.
	for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
		max := 30
		if seg == obsdk.Business {
			max = 100
		}
		fields := []obsdk.PaymentField{amount, date,
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeIBAN}, Label: "Pay from",
				Note: "A Handelsbanken SEK account: clearing number + account number, or the IBAN."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Label: "Payee account",
				Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeIBAN, obsdk.SchemeBankgiro, obsdk.SchemePlusgiro},
				SchemeRules: []obsdk.SchemeRule{
					{Scheme: obsdk.SchemeBBAN, Pattern: `^[0-9][0-9 ,.-]{6,20}$`, Label: "Clearing and account number", Note: "Clearing number + account number, e.g. 8327-9,123456789."},
					{Scheme: obsdk.SchemeIBAN, Pattern: `^SE`, Note: "Swedish IBANs only."},
				}},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldOptional, MaxLength: 70, Label: "Payee name", Note: "Required for account (IBAN, BBAN) payees."},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message",
				Note: "A message or an OCR reference is required, not both."},
			{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceOCR}, Label: "OCR reference",
				OnlyWith: &obsdk.FieldCondition{Path: obsdk.FieldCreditorAccount, Schemes: []string{obsdk.SchemeBankgiro, obsdk.SchemePlusgiro}}},
		}
		if seg == obsdk.Business {
			fields = append(fields, obsdk.PaymentField{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35,
				Note: "Shown on the company's own account statement (debtorAccount.text)."})
		}
		out = append(out, obsdk.PaymentSpec{Type: obsdk.PaymentDomestic, Countries: []obsdk.Country{"SE"}, Segments: []obsdk.Segment{seg},
			Currencies: []string{"SEK"}, MaxTransfers: max, ExecutionDateMaxDays: 365, AuthApproaches: both, FinalStatuses: final,
			Cancellable: true, Fields: fields,
			Notes: []string{fmt.Sprintf("Sent as a signing basket of sek-credit-transfers: up to %d transfers with one approval.", max),
				"Cancelling works for a payment with one transfer."}})
	}

	// Sweden: between Handelsbanken accounts, any currency.
	out = append(out, obsdk.PaymentSpec{Type: obsdk.PaymentInternal, Countries: []obsdk.Country{"SE"}, MaxTransfers: 1,
		ExecutionDateMaxDays: 365, AuthApproaches: both, FinalStatuses: final, Cancellable: true,
		Fields: []obsdk.PaymentField{amount, date,
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeIBAN}, Label: "Pay from"},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeIBAN}, Label: "To account",
				SchemeRules: []obsdk.SchemeRule{{Scheme: obsdk.SchemeBBAN, Pattern: `^6[0-9]{3}[0-9 -]{8,11}$`, Label: "Clearing and account number",
					Note: "A Handelsbanken account: clearing number 6xxx + account number."}}},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldOptional, MaxLength: 35, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldRequired, MaxItems: 1, MaxLength: 14, Label: "Message",
				Note: "Shown on both accounts."},
		}})

	// SEPA: Swedish business accounts, NL (both segments) and LU.
	sepaFields := func(e2e, dated, address bool) []obsdk.PaymentField {
		fs := []obsdk.PaymentField{amount,
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Pay from"},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Payee IBAN"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 35, Pattern: `^.{3,35}$`, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message"},
		}
		if address {
			fs = append(fs, obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldRequired, Label: "Payee address",
				Note: "Town and country are required."},
				obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldRequired, Pattern: `^[A-Z]{2}$`, Label: "Payee country"})
		} else {
			fs = append(fs, obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address"},
				obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country"})
		}
		if e2e {
			fs = append(fs, obsdk.PaymentField{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35})
		}
		if dated {
			fs = append(fs, date)
		}
		return fs
	}
	out = append(out,
		obsdk.PaymentSpec{Type: obsdk.PaymentSEPA, Countries: []obsdk.Country{"SE"}, Segments: []obsdk.Segment{obsdk.Business}, Currencies: []string{"EUR"},
			MaxTransfers: 1, ExecutionDateMaxDays: 365, AuthApproaches: both, FinalStatuses: final, Cancellable: true,
			Fields: append(sepaFields(true, true, true), obsdk.PaymentField{Path: obsdk.FieldDebtorCurrency, Use: obsdk.FieldOptional, Options: []obsdk.Option{{Value: "EUR", Label: "EUR"}, {Value: "SEK", Label: "SEK"}},
				Note: "The pay-from account's currency, when it is SEK."})},
		obsdk.PaymentSpec{Type: obsdk.PaymentSEPA, Countries: []obsdk.Country{"NL"}, Segments: []obsdk.Segment{obsdk.Personal}, Currencies: []string{"EUR"},
			MaxTransfers: 1, AuthApproaches: redirect, FinalStatuses: final, Fields: sepaFields(false, false, false)},
		obsdk.PaymentSpec{Type: obsdk.PaymentSEPA, Countries: []obsdk.Country{"NL"}, Segments: []obsdk.Segment{obsdk.Business}, Currencies: []string{"EUR"},
			MaxTransfers: 1, AuthApproaches: redirect, FinalStatuses: final, Fields: sepaFields(true, false, false)},
		obsdk.PaymentSpec{Type: obsdk.PaymentSEPA, Countries: []obsdk.Country{"LU"}, Currencies: []string{"EUR"},
			MaxTransfers: 1, ExecutionDateMaxDays: 365, AuthApproaches: redirect, FinalStatuses: final, Fields: sepaFields(false, true, false)},
	)

	// GB: Faster Payments to a sort code and account number.
	gbText := `^[A-Za-z0-9 ./-]+$`
	out = append(out, obsdk.PaymentSpec{Type: obsdk.PaymentDomestic, Countries: []obsdk.Country{"GB"}, Currencies: []string{"GBP"},
		MaxTransfers: 1, ExecutionDateMaxDays: 365, AuthApproaches: redirect, FinalStatuses: final,
		Fields: []obsdk.PaymentField{amount, date,
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeIBAN}, Label: "Pay from",
				SchemeRules: []obsdk.SchemeRule{{Scheme: obsdk.SchemeBBAN, Pattern: `^[0-9]{8}$`, Label: "Account number", Note: "The 8-digit account number."}}},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeSortCodeAccount}, Label: "Sort code and account number"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 35, Pattern: gbText, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 18, Pattern: gbText, Label: "Reference"},
			{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address"},
			{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country", Note: "Defaults to GB."},
		}})
	return out
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: Handelsbanken payments of type %q are not available for %s %s customers", obsdk.ErrUnsupported, t, c.target.Country, c.target.Segment)
}

// ---- paths ----

func (c *client) seSegment() string {
	if c.business() {
		return "corporate"
	}
	return "private"
}

// payBase is the payments root of the client's country (and Swedish segment).
func (c *client) payBase() string {
	switch c.target.Country {
	case "SE":
		return "/psd2/se/v2/payments/" + c.seSegment()
	case "GB", "NL", "LU":
		return "/psd2/" + strings.ToLower(string(c.target.Country)) + "/v1/payments"
	}
	return "/psd2/v1/payments"
}

func (c *client) createPath(product string) string {
	switch {
	case product == prodSEK:
		return c.payBase() + "/signing-basket"
	case c.target.Country == "SE":
		return c.payBase() + "/single/" + product
	}
	return c.payBase() + "/" + product
}

func (c *client) executePath(p *payState) string {
	switch {
	case p.Product == prodSEK:
		return c.payBase() + "/signing-basket/" + url.PathEscape(p.ID)
	case c.target.Country == "SE":
		return c.payBase() + "/single/" + p.Product + "/" + url.PathEscape(p.ID)
	}
	return c.payBase() + "/" + p.Product + "/" + url.PathEscape(p.ID)
}

func (c *client) statusPath(product, id string) string {
	return c.payBase() + "/" + product + "/" + url.PathEscape(id) + "/status"
}

func (c *client) cancelPath(product, id string) string {
	return c.payBase() + "/" + product + "/" + url.PathEscape(id) + "/cancellation-authorizations"
}

// ---- request bodies ----

type accountRef struct {
	Value       string `json:"value"`
	AccountType string `json:"accountType"`
	Currency    string `json:"currency,omitempty"`
	Country     string `json:"country,omitempty"`
	Text        string `json:"text,omitempty"`
}

type amountRef struct {
	Amount   json.Number `json:"amount"`
	Currency string      `json:"currency"`
}

type agentRef struct {
	Identification *struct {
		Code string `json:"code"`
		Type string `json:"type,omitempty"`
	} `json:"identification,omitempty"`
}

func agent(code, typ string) *agentRef {
	a := &agentRef{}
	a.Identification = &struct {
		Code string `json:"code"`
		Type string `json:"type,omitempty"`
	}{code, typ}
	return a
}

type postal struct {
	StreetName     string `json:"streetName,omitempty"`
	BuildingNumber string `json:"buildingNumber,omitempty"`
	AddressLine    string `json:"addressLine,omitempty"`
	PostCode       string `json:"postCode,omitempty"`
	TownName       string `json:"townName,omitempty"`
	Country        string `json:"country,omitempty"`
}

type party struct {
	Name          string  `json:"name,omitempty"`
	PostalAddress *postal `json:"postalAddress,omitempty"`
}

type textRef struct {
	Text string `json:"text"`
}

type codeRef struct {
	Code string `json:"code"`
}

// payment is the body of one transfer; each product uses a subset.
type payment struct {
	TPPPaymentReference string     `json:"tppPaymentReference,omitempty"`
	DebtorAccount       accountRef `json:"debtorAccount"`
	InstructedAmount    amountRef  `json:"instructedAmount"`
	PaymentID           *struct {
		EndToEnd string `json:"endToEndIdentification"`
	} `json:"paymentIdentification,omitempty"`
	PaymentTypeInfo *struct {
		ServiceLevel    codeRef `json:"serviceLevel"`
		CategoryPurpose codeRef `json:"categoryPurpose"`
	} `json:"paymentTypeInformation,omitempty"`
	ChargeBearer    string     `json:"chargeBearer,omitempty"`
	CreditorAccount accountRef `json:"creditorAccount"`
	Creditor        *party     `json:"creditor,omitempty"`
	CreditorAgent   *agentRef  `json:"creditorAgent,omitempty"`
	ExecutionDate   string     `json:"requestedExecutionDate,omitempty"`
	Remittance      *textRef   `json:"remittanceInformation,omitempty"`
}

func issue(path string, i int, code, msg string) error {
	return &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: path, Index: i, Code: code, Message: msg}}}
}

var nonDigits = regexp.MustCompile(`[^0-9]`)

// splitClearing splits a Swedish clearing + account number. Clearing numbers
// have four digits, five for Swedbank's 8xxx-x.
func splitClearing(v string) (clearing, account string) {
	d := nonDigits.ReplaceAllString(v, "")
	n := 4
	if strings.HasPrefix(d, "8") {
		n = 5
	}
	if len(d) <= n {
		return "", d
	}
	return d[:n], d[n:]
}

// shbAccount turns a Handelsbanken account (clearing + number, the bare
// number, or a Swedish IBAN) into the 8-9 digit number the API wants.
func shbAccount(id obsdk.Identifier) (string, error) {
	d := nonDigits.ReplaceAllString(id.Value, "")
	if id.Scheme == obsdk.SchemeIBAN {
		v := strings.ToUpper(strings.ReplaceAll(id.Value, " ", ""))
		if !strings.HasPrefix(v, "SE") || len(v) != 24 || v[4:7] != "600" {
			return "", fmt.Errorf("not a Handelsbanken IBAN")
		}
		return strings.TrimLeft(v[7:], "0"), nil // SEkk 600 + 17 digits, zero-padded
	}
	if len(d) >= 12 && d[0] == '6' {
		d = d[4:] // drop the clearing number
	}
	if len(d) < 8 || len(d) > 9 {
		return "", fmt.Errorf("a Handelsbanken account number has 8 or 9 digits after the clearing number")
	}
	return d, nil
}

func remittanceText(t obsdk.Transfer) string {
	if t.Reference != nil && t.Reference.Value != "" {
		return t.Reference.Value
	}
	if len(t.Remittance) > 0 {
		return t.Remittance[0]
	}
	return ""
}

func toPostal(a *obsdk.PostalAddress) *postal {
	if a == nil {
		return nil
	}
	p := &postal{StreetName: a.Street, BuildingNumber: a.BuildingNumber, PostCode: a.PostCode, TownName: a.Town, Country: a.Country}
	if len(a.Lines) > 0 {
		p.AddressLine = a.Lines[0]
	}
	return p
}

func ibanCountry(v string) string {
	if len(v) >= 2 {
		return strings.ToUpper(v[:2])
	}
	return ""
}

// buildSEK makes one sek-credit-transfer of a signing basket.
func (c *client) buildSEK(r obsdk.PaymentRequest, i int, t obsdk.Transfer) (payment, error) {
	var p payment
	debtor, err := shbAccount(*r.Debtor.Account)
	if err != nil {
		return p, issue(obsdk.FieldDebtorAccount, -1, obsdk.IssueInvalid, err.Error())
	}
	p.TPPPaymentReference = t.InstructionID
	if p.TPPPaymentReference == "" {
		p.TPPPaymentReference = c.cfg.ID(obsdk.IDRequest)
	}
	p.DebtorAccount = accountRef{Value: debtor, AccountType: "BBAN"}
	if c.business() && t.EndToEndID != "" {
		p.DebtorAccount.Text = t.EndToEndID
	}
	p.InstructedAmount = amountRef{Amount: json.Number(t.Amount.Amount), Currency: t.Amount.Currency}
	cr := t.Creditor.Account
	switch cr.Scheme {
	case obsdk.SchemeBankgiro:
		p.CreditorAccount = accountRef{Value: cr.Value, AccountType: "BG"}
	case obsdk.SchemePlusgiro:
		p.CreditorAccount = accountRef{Value: cr.Value, AccountType: "PG"}
	case obsdk.SchemeIBAN:
		p.CreditorAccount = accountRef{Value: strings.ReplaceAll(cr.Value, " ", ""), AccountType: "IBAN"}
	default: // BBAN: clearing + account
		clearing, acct := splitClearing(cr.Value)
		if t.Creditor.Agent != nil && t.Creditor.Agent.MemberID != "" {
			clearing, acct = t.Creditor.Agent.MemberID, nonDigits.ReplaceAllString(cr.Value, "")
		}
		if clearing == "" {
			return p, issue(obsdk.FieldCreditorAccount, i, obsdk.IssueInvalid, "needs the clearing number in front of the account number")
		}
		p.CreditorAccount = accountRef{Value: acct, AccountType: "BBAN"}
		p.CreditorAgent = agent(clearing, "")
	}
	if cr.Scheme == obsdk.SchemeIBAN || cr.Scheme == obsdk.SchemeBBAN {
		if t.Creditor.Name == "" {
			return p, issue(obsdk.FieldCreditorName, i, obsdk.IssueRequired, "is required for account payees")
		}
	}
	if t.Creditor.Name != "" {
		p.Creditor = &party{Name: t.Creditor.Name}
	}
	if t.Reference != nil && t.Reference.Value != "" && len(t.Remittance) > 0 {
		return p, issue(obsdk.FieldReference, i, obsdk.IssueUnsupported, "Handelsbanken takes either a message or an OCR reference, not both")
	}
	text := remittanceText(t)
	if text == "" {
		return p, issue(obsdk.FieldRemittance, i, obsdk.IssueRequired, "a message or an OCR reference is required")
	}
	p.Remittance = &textRef{Text: text}
	p.ExecutionDate = r.ExecutionDate
	return p, nil
}

// buildInternal makes a handelsbanken-domestic-credit-transfer.
func (c *client) buildInternal(r obsdk.PaymentRequest, t obsdk.Transfer) (payment, error) {
	var p payment
	debtor, err := shbAccount(*r.Debtor.Account)
	if err != nil {
		return p, issue(obsdk.FieldDebtorAccount, -1, obsdk.IssueInvalid, err.Error())
	}
	creditor, err := shbAccount(t.Creditor.Account)
	if err != nil {
		return p, issue(obsdk.FieldCreditorAccount, 0, obsdk.IssueInvalid, err.Error())
	}
	clearing := "6000" // any Handelsbanken clearing number (6000-6999) routes the transfer
	if t.Creditor.Account.Scheme == obsdk.SchemeBBAN {
		if cl, _ := splitClearing(t.Creditor.Account.Value); strings.HasPrefix(cl, "6") && len(nonDigits.ReplaceAllString(t.Creditor.Account.Value, "")) >= 12 {
			clearing = cl
		}
	}
	text := remittanceText(t)
	p.DebtorAccount = accountRef{Value: debtor, AccountType: "BBAN", Text: text}
	p.InstructedAmount = amountRef{Amount: json.Number(t.Amount.Amount), Currency: t.Amount.Currency}
	p.CreditorAccount = accountRef{Value: creditor, AccountType: "BBAN"}
	p.CreditorAgent = agent(clearing, "SESBA")
	if t.Creditor.Name != "" {
		p.Creditor = &party{Name: t.Creditor.Name}
	}
	p.Remittance = &textRef{Text: text}
	p.ExecutionDate = r.ExecutionDate
	return p, nil
}

func sepaTypeInfo(p *payment, level, purpose, bearer string) {
	p.PaymentTypeInfo = &struct {
		ServiceLevel    codeRef `json:"serviceLevel"`
		CategoryPurpose codeRef `json:"categoryPurpose"`
	}{codeRef{level}, codeRef{purpose}}
	p.ChargeBearer = bearer
}

// buildSEPA makes a sepa-credit-transfer (SE business, NL, LU).
func (c *client) buildSEPA(r obsdk.PaymentRequest, t obsdk.Transfer) (payment, error) {
	var p payment
	d := *r.Debtor.Account
	dv := strings.ReplaceAll(d.Value, " ", "")
	p.DebtorAccount = accountRef{Value: dv, AccountType: "IBAN", Currency: "EUR"}
	if r.Debtor.Currency != "" {
		p.DebtorAccount.Currency = r.Debtor.Currency
	}
	if c.target.Country == "NL" {
		p.DebtorAccount.Country = "NL"
	}
	p.InstructedAmount = amountRef{Amount: json.Number(t.Amount.Amount), Currency: t.Amount.Currency}
	if t.EndToEndID != "" {
		p.PaymentID = &struct {
			EndToEnd string `json:"endToEndIdentification"`
		}{t.EndToEndID}
	}
	// Sweden's corporate API takes only SHAR for SEPA; NL and LU want SLEV.
	bearer := "SLEV"
	if c.target.Country == "SE" {
		bearer = "SHAR"
	}
	sepaTypeInfo(&p, "SEPA", "SUPP", bearer)
	cv := strings.ReplaceAll(t.Creditor.Account.Value, " ", "")
	p.CreditorAccount = accountRef{Value: cv, AccountType: "IBAN", Country: ibanCountry(cv)}
	p.Creditor = &party{Name: t.Creditor.Name, PostalAddress: toPostal(t.Creditor.Address)}
	if c.target.Country == "SE" {
		if a := p.Creditor.PostalAddress; a == nil || a.TownName == "" || a.Country == "" {
			return p, issue(obsdk.FieldCreditorAddress, 0, obsdk.IssueRequired, "town and country are required")
		}
	}
	if text := remittanceText(t); text != "" {
		p.Remittance = &textRef{Text: text}
	}
	p.ExecutionDate = r.ExecutionDate
	return p, nil
}

// buildBritish makes a british-domestic-credit-transfer (Faster Payments).
func (c *client) buildBritish(r obsdk.PaymentRequest, t obsdk.Transfer) (payment, error) {
	var p payment
	d := *r.Debtor.Account
	p.DebtorAccount = accountRef{Value: strings.ReplaceAll(d.Value, " ", ""), AccountType: d.Scheme}
	p.InstructedAmount = amountRef{Amount: json.Number(t.Amount.Amount), Currency: t.Amount.Currency}
	sepaTypeInfo(&p, "NURG", "SUPP", "SHAR")
	sc := nonDigits.ReplaceAllString(t.Creditor.Account.Value, "") // sort code (6) + account number (8)
	p.CreditorAccount = accountRef{Value: sc[6:], AccountType: "BBAN"}
	p.CreditorAgent = agent(sc[:6], "GBDSC")
	addr := toPostal(t.Creditor.Address)
	if addr == nil {
		addr = &postal{}
	}
	if addr.Country == "" {
		addr.Country = "GB" // required by the bank
	}
	p.Creditor = &party{Name: t.Creditor.Name, PostalAddress: addr}
	if text := remittanceText(t); text != "" {
		p.Remittance = &textRef{Text: text}
	}
	p.ExecutionDate = r.ExecutionDate
	return p, nil
}

// product picks the payment product for a request.
func (c *client) product(t obsdk.PaymentType) string {
	switch {
	case t == obsdk.PaymentDomestic && c.target.Country == "SE":
		return prodSEK
	case t == obsdk.PaymentDomestic:
		return prodBritish
	case t == obsdk.PaymentInternal:
		return prodInternal
	}
	return prodSEPA
}

// ---- initiate ----

// InitiatePayment creates the payment and starts the user's approval.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	m, err := c.method(r.Method)
	if err != nil {
		return nil, err
	}
	f := &flow{Purpose: purposePayment, Method: m, PSU: r.PSU, RedirectURL: c.redirectURL(r.RedirectURL)}
	if m == methodRedirect && f.RedirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or PaymentRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	fill(&f.PSU, r.Values)
	ps := &payState{Type: r.Type, Product: c.product(r.Type)}
	var body any
	if ps.Product == prodSEK {
		var basket struct {
			Transfers []payment `json:"sekCreditTransfers"`
		}
		for i, t := range r.Transfers {
			p, err := c.buildSEK(r, i, t)
			if err != nil {
				return nil, err
			}
			basket.Transfers = append(basket.Transfers, p)
		}
		body = basket
		if len(basket.Transfers) == 1 {
			// A cancellation repeats the payment's own payload.
			one := basket.Transfers[0]
			one.TPPPaymentReference = ""
			ps.Body, _ = json.Marshal(one)
		}
	} else {
		var p payment
		t := r.Transfers[0]
		switch ps.Product {
		case prodInternal:
			p, err = c.buildInternal(r, t)
		case prodBritish:
			p, err = c.buildBritish(r, t)
		default:
			p, err = c.buildSEPA(r, t)
		}
		if err != nil {
			return nil, err
		}
		body = p
		if c.target.Country == "SE" {
			ps.Body, _ = json.Marshal(p)
		}
	}
	if ps.Create, err = json.Marshal(body); err != nil {
		return nil, err
	}
	f.Pay = ps
	if c.business() && c.corporateID(f.PSU) == "" {
		f.Phase = phInput
		return c.pause(f, &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true,
			Message: "Handelsbanken needs the company's id for a business payment.", Fields: []obsdk.Field{corporateField()}})
	}
	return c.createPayment(ctx, f)
}

// createPayment sends the prepared body and starts the user's approval.
func (c *client) createPayment(ctx context.Context, f *flow) (*obsdk.Step, error) {
	ps := f.Pay
	body := ps.Create
	ps.Create = nil
	cct, err := c.clientToken(ctx, scopePIS)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, url: c.apiURL(c.createPath(ps.Product)), api: true, bearer: cct,
		header: c.psuHeaders(f.PSU), psu: psuOrNil(f.PSU), body: body})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		e := c.apiErr(opPayment, res)
		if res.status == http.StatusBadRequest || res.status == http.StatusForbidden {
			reason := "rejected"
			var ae *obsdk.APIError
			if errors.As(e, &ae) && ae.Code != "" {
				reason = ae.Code
			}
			return nil, &obsdk.PaymentRejectedError{Reason: reason, Err: e}
		}
		return nil, e
	}
	var cr struct {
		PaymentID       string      `json:"paymentId"`
		SigningBasketID string      `json:"signingBasketId"`
		Status          string      `json:"transactionStatus"`
		SCAMethods      []scaMethod `json:"scaMethods"`
		Payments        []struct {
			PaymentID string `json:"paymentId"`
		} `json:"payments"`
	}
	if err := json.Unmarshal(res.body, &cr); err != nil {
		return nil, fmt.Errorf("handelsbanken: unreadable payment response (HTTP %d)", res.status)
	}
	ps.ID = cr.PaymentID
	if ps.Product == prodSEK {
		ps.ID = cr.SigningBasketID
		for _, p := range cr.Payments {
			ps.IDs = append(ps.IDs, p.PaymentID)
		}
	}
	if ps.ID == "" {
		return nil, fmt.Errorf("handelsbanken: payment response has no id")
	}
	status := cr.Status
	if status == "" {
		status = "ACTC" // a basket reports no status before it is signed
	}
	pay, err := c.toPayment(ps, status, "", res.body)
	if err != nil {
		return nil, err
	}
	f.Pay, f.Scope = ps, scopePIS+":"+ps.ID
	st, err := c.authorize(ctx, f, cr.SCAMethods)
	if err != nil {
		return nil, &obsdk.FlowError{Payment: pay, Err: err}
	}
	st.Payment = pay
	return st, nil
}

// ---- approve and execute ----

func (c *client) resumePayment(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	ps := f.Pay
	if ps == nil {
		return nil, fmt.Errorf("%w: payment state missing", obsdk.ErrInvalidRequest)
	}
	if f.Phase == phInput {
		fill(&f.PSU, in.Values)
		if c.corporateID(f.PSU) == "" {
			return c.pause(f, &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "The company id is required.", Fields: []obsdk.Field{corporateField()}})
		}
		if len(ps.Create) > 0 {
			return c.createPayment(ctx, f)
		}
		return c.startCancel(ctx, f)
	}
	pending := func() *obsdk.Payment {
		p, _ := c.toPayment(ps, "ACTC", "", nil)
		return p
	}
	var tr *tokenResponse
	switch f.Phase {
	case phRedirect:
		code, err := c.callbackCode(f, in)
		if err != nil {
			return nil, &obsdk.FlowError{Payment: pending(), Err: err}
		}
		if code == "" {
			st, err := c.pause(f, c.redirectStep(f))
			if st != nil {
				st.Payment = pending()
			}
			return st, err
		}
		if tr, err = c.exchange(ctx, f, code); err != nil {
			return nil, &obsdk.FlowError{Payment: pending(), Err: err}
		}
	case phDecoupled:
		var err error
		if tr, err = c.pollDecoupled(ctx, f); err != nil {
			return nil, &obsdk.FlowError{Payment: pending(), Err: err}
		}
		if tr == nil {
			st, err := c.pause(f, c.waitStep(f))
			if st != nil {
				st.Payment = pending()
			}
			return st, err
		}
	default:
		return nil, fmt.Errorf("%w: unknown flow phase %q", obsdk.ErrInvalidRequest, f.Phase)
	}
	if ps.Cancel != "" {
		return c.executeCancel(ctx, f, tr.AccessToken)
	}
	return c.execute(ctx, f, tr.AccessToken)
}

// execute runs the approved payment (PUT) and reads where it stands.
func (c *client) execute(ctx context.Context, f *flow, token string) (*obsdk.Step, error) {
	ps := f.Pay
	res, err := c.do(ctx, req{op: opPayExec, method: http.MethodPut, url: c.apiURL(c.executePath(ps)), api: true, bearer: token, psu: psuOrNil(f.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK && res.status != http.StatusCreated {
		p, _ := c.toPayment(ps, "ACTC", "", nil)
		return nil, &obsdk.FlowError{Payment: p, Err: c.apiErr(opPayExec, res)}
	}
	var er struct {
		Status string `json:"transactionStatus"`
	}
	_ = json.Unmarshal(res.body, &er)
	var pay *obsdk.Payment
	if ps.Product == prodSEK {
		// The basket answers SUCCEEDED, FAILED or PARTIAL_FAILURE; each payment
		// has its own status.
		if pay, err = c.readStatus(ctx, ps, psuOrNil(f.PSU)); err != nil {
			return nil, err
		}
		pay.Raw = res.body
		if er.Status == "FAILED" {
			pay.Status, pay.Final = obsdk.PaymentRejected, true
		}
	} else if pay, err = c.toPayment(ps, er.Status, "", res.body); err != nil {
		return nil, err
	}
	if pay.Status == obsdk.PaymentRejected {
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: strings.ToLower(pay.BankStatus), Payment: pay}}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: res.body}, nil
}

// ---- status ----

// hbStatus maps Handelsbanken's statuses. ACTC is a created payment that
// still waits for the user's approval; the rest are Berlin Group codes.
func hbStatus(code string) (obsdk.PaymentStatus, bool) {
	if code == "ACTC" {
		return obsdk.PaymentReceived, false
	}
	return bgstatus.Payment(code)
}

func (c *client) toPayment(ps *payState, status, reason string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, Type: ps.Type, Product: ps.Product, ID: ps.ID, IDs: ps.IDs, Body: ps.Body})
	if err != nil {
		return nil, err
	}
	st, final := hbStatus(status)
	return &obsdk.Payment{ID: ps.ID, Type: ps.Type, Status: st, BankStatus: status, Final: final, Reason: reason, Ref: ref, Raw: raw}, nil
}

type statusJSON struct {
	PaymentID  string `json:"paymentId"`
	Status     string `json:"transactionStatus"`
	ReasonCode string `json:"reasonCode"`
	Reason     string `json:"reason"`
}

// rank orders statuses for a basket summary: the least advanced wins.
var rank = map[obsdk.PaymentStatus]int{
	obsdk.PaymentReceived: 0, obsdk.PaymentAccepted: 1, obsdk.PaymentInProgress: 2, obsdk.PaymentPartiallyAccepted: 3,
	obsdk.PaymentCompleted: 4, obsdk.PaymentCancelled: 5, obsdk.PaymentRejected: 6,
}

// readStatus reads a payment's status; a basket's is summed up from its
// payments (the raw response lists each).
func (c *client) readStatus(ctx context.Context, ps *payState, psu *obsdk.PSUContext) (*obsdk.Payment, error) {
	cct, err := c.clientToken(ctx, scopePIS)
	if err != nil {
		return nil, err
	}
	ids := []string{ps.ID}
	if ps.Product == prodSEK {
		ids = ps.IDs
	}
	var all []statusJSON
	for _, id := range ids {
		res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, url: c.apiURL(c.statusPath(ps.Product, id)), api: true, bearer: cct, psu: psu})
		if err != nil {
			return nil, err
		}
		if res.status != http.StatusOK {
			return nil, c.apiErr(opPayStatus, res)
		}
		var s statusJSON
		if err := json.Unmarshal(res.body, &s); err != nil || s.Status == "" {
			// NL documents a list of statuses; take the first.
			var l []statusJSON
			if json.Unmarshal(res.body, &l) != nil || len(l) == 0 {
				return nil, fmt.Errorf("handelsbanken: unreadable payment status (HTTP %d)", res.status)
			}
			s = l[0]
		}
		all = append(all, s)
	}
	raw, _ := json.Marshal(all)
	if len(all) == 1 {
		s := all[0]
		reason := s.ReasonCode
		if reason == "" {
			reason = s.Reason
		}
		return c.toPayment(ps, s.Status, reason, raw)
	}
	// Several transfers: the summary is the least advanced status, or
	// partially accepted when some were rejected and some not.
	worst, rejected, final := all[0].Status, 0, true
	for _, s := range all {
		st, fin := hbStatus(s.Status)
		w, _ := hbStatus(worst)
		if rank[st] < rank[w] {
			worst = s.Status
		}
		if st == obsdk.PaymentRejected {
			rejected++
		}
		final = final && fin
	}
	pay, err := c.toPayment(ps, worst, "", raw)
	if err != nil {
		return nil, err
	}
	if rejected > 0 && rejected < len(all) {
		pay.Status, pay.BankStatus = obsdk.PaymentPartiallyAccepted, "PARTIAL"
	}
	pay.Final = final
	return pay, nil
}

func decodeRef(ref string) (*payState, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.ID == "" || strings.ContainsAny(r.ID, "/?#") {
		return nil, fmt.Errorf("%w: not a Handelsbanken payment reference", obsdk.ErrInvalidRequest)
	}
	for _, id := range r.IDs {
		if strings.ContainsAny(id, "/?#") {
			return nil, fmt.Errorf("%w: not a Handelsbanken payment reference", obsdk.ErrInvalidRequest)
		}
	}
	return &payState{Type: r.Type, Product: r.Product, ID: r.ID, IDs: r.IDs, Body: r.Body}, nil
}

// PaymentStatus reads a payment's status with a client token; no session needed.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	ps, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	pay, err := c.readStatus(ctx, ps, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: pay.Raw}, nil
}

// ---- cancel ----

// CancelPayment cancels a Swedish payment that is not executed yet (in
// practice a future-dated one): the cancellation repeats the payment's
// payload, the user approves it like the payment, and a PUT carries it out.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	ps, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	if c.target.Country != "SE" {
		return nil, fmt.Errorf("%w: Handelsbanken cancels payments in Sweden only", obsdk.ErrUnsupported)
	}
	if len(ps.Body) == 0 || (ps.Product == prodSEK && len(ps.IDs) != 1) {
		return nil, fmt.Errorf("%w: only a payment with one transfer can be cancelled", obsdk.ErrUnsupported)
	}
	m, err := c.method(o.Method)
	if err != nil {
		return nil, err
	}
	f := &flow{Purpose: purposePayment, Method: m, RedirectURL: c.redirectURL(o.RedirectURL)}
	if o.PSU != nil {
		f.PSU = *o.PSU
	}
	if m == methodRedirect && f.RedirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or PaymentCallOptions.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	f.Pay = ps
	if c.business() && c.corporateID(f.PSU) == "" {
		f.Phase = phInput
		return c.pause(f, &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true,
			Message: "Handelsbanken needs the company's id to cancel a business payment.", Fields: []obsdk.Field{corporateField()}})
	}
	return c.startCancel(ctx, f)
}

func (c *client) startCancel(ctx context.Context, f *flow) (*obsdk.Step, error) {
	ps := f.Pay
	id := ps.ID
	if ps.Product == prodSEK {
		id = ps.IDs[0]
	}
	cct, err := c.clientToken(ctx, scopePIS)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodPost, url: c.apiURL(c.cancelPath(ps.Product, id)), api: true, bearer: cct,
		header: c.psuHeaders(f.PSU), psu: psuOrNil(f.PSU), body: ps.Body})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opPayCancel, res)
	}
	var cr struct {
		CancellationID string      `json:"cancellationId"`
		SCAMethods     []scaMethod `json:"scaMethods"`
	}
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.CancellationID == "" {
		return nil, fmt.Errorf("handelsbanken: unreadable cancellation response (HTTP %d)", res.status)
	}
	ps.Cancel = cr.CancellationID
	f.Scope = scopePIS + ":" + cr.CancellationID
	st, err := c.authorize(ctx, f, cr.SCAMethods)
	if err != nil {
		return nil, err
	}
	st.Message = "Send the user to Handelsbanken to approve the cancellation, then pass the callback URL to Resume."
	return st, nil
}

func (c *client) executeCancel(ctx context.Context, f *flow, token string) (*obsdk.Step, error) {
	ps := f.Pay
	id := ps.ID
	if ps.Product == prodSEK {
		id = ps.IDs[0]
	}
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodPut, url: c.apiURL(c.cancelPath(ps.Product, id) + "/" + url.PathEscape(ps.Cancel)),
		api: true, bearer: token, psu: psuOrNil(f.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK && res.status != http.StatusCreated {
		return nil, c.apiErr(opPayCancel, res)
	}
	var s statusJSON
	_ = json.Unmarshal(res.body, &s)
	ps.Cancel = ""
	pay, err := c.toPayment(ps, s.Status, "", res.body)
	if err != nil {
		return nil, err
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: res.body}, nil
}
