package obsdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PaymentType is the kind of credit transfer. It names the scheme, not the
// number of transfers: a request always holds a list of transfers, and
// PaymentSpec.MaxTransfers says how many one payment may carry.
type PaymentType string

const (
	PaymentSEPA        PaymentType = "sepa"         // SEPA credit transfer (EUR)
	PaymentSEPAInstant PaymentType = "sepa_instant" // SEPA instant credit transfer, without fallback to SEPA
	PaymentDomestic    PaymentType = "domestic"     // the country's own scheme in its currency (SE: SEK incl. Bankgiro / Plusgiro, GB: Faster Payments)
	PaymentCrossBorder PaymentType = "crossborder"  // international (SWIFT) transfer
	PaymentInternal    PaymentType = "internal"     // between accounts of the same bank
)

// Identifier schemes used in payments (Identifier.Scheme).
const (
	SchemeIBAN            = "IBAN"
	SchemeBBAN            = "BBAN"
	SchemeSortCodeAccount = "SORT_CODE_ACCOUNT" // UK sort code + account number, 14 digits
	SchemeBankgiro        = "BANKGIRO"
	SchemePlusgiro        = "PLUSGIRO"
)

// Reference schemes (Reference.Scheme).
const (
	ReferenceRF  = "RF"  // ISO 11649 creditor reference
	ReferenceOCR = "OCR" // Swedish OCR number (Bankgiro / Plusgiro)
	ReferenceFI  = "FI"  // Finnish creditor reference (viitenumero)
	ReferenceBE  = "BE"  // Belgian structured communication (OGM-VCS), the 12 digits without +++ and slashes
)

// PaymentRequest starts a payment. Which fields a bank needs, accepts or
// ignores is described by its PaymentSpec (Info.PaymentSpec); InitiatePayment
// validates the request against it before calling the bank.
type PaymentRequest struct {
	Type PaymentType

	// Method picks the SCA approach when the bank offers several ("redirect",
	// "decoupled"). Empty lets the integration choose.
	Method      string
	PSU         PSUContext
	RedirectURL string            // overrides Config.Credentials.RedirectURL
	Language    string            // ISO 639-1, when the bank supports it
	Values      map[string]string // pre-filled answers to input steps (auth_method, personal_id, ...)

	// Session optionally reuses an earlier login (from Connect or a previous
	// payment) where the bank allows it. Banks that allow one token per user
	// (Swedbank) otherwise invalidate the user's existing session.
	Session *Session

	Debtor        *PaymentDebtor
	Transfers     []Transfer
	ExecutionDate string // YYYY-MM-DD; empty means as soon as possible
	ChargeBearer  string // ChargeBearer* values
	Context       string // PaymentContext* values

	// IdempotencyKey is sent where the bank supports one. Empty generates one.
	IdempotencyKey string
}

// Charge bearer values (PaymentRequest.ChargeBearer).
const (
	ChargeBearerDebtor   = "DEBT" // the payer pays all fees ("OUR")
	ChargeBearerCreditor = "CRED" // the payee pays all fees ("BEN")
	ChargeBearerShared   = "SHAR" // each pays their own bank ("SHA")
	ChargeBearerService  = "SLEV" // as the scheme's service level defines (SEPA)
)

// Payment context values (PaymentRequest.Context). Some banks use them for
// risk scoring.
const (
	PaymentContextPartyToParty      = "party_to_party"
	PaymentContextBill              = "bill_payment"
	PaymentContextEcommerceGoods    = "ecommerce_goods"
	PaymentContextEcommerceServices = "ecommerce_services"
	PaymentContextOther             = "other"
)

// PaymentDebtor is the payer. Leave Account empty to let the user pick the
// account at the bank, where the spec allows it.
type PaymentDebtor struct {
	Account  *Identifier `json:"account,omitempty"`
	Name     string      `json:"name,omitempty"`
	Currency string      `json:"currency,omitempty"` // currency to pay from, when it differs from the amount's
}

// Transfer is one credit transfer.
type Transfer struct {
	Amount        Money      `json:"amount"` // positive
	Creditor      Creditor   `json:"creditor"`
	Remittance    []string   `json:"remittance,omitempty"` // unstructured message lines
	Reference     *Reference `json:"reference,omitempty"`  // structured creditor reference
	EndToEndID    string     `json:"end_to_end_id,omitempty"`
	InstructionID string     `json:"instruction_id,omitempty"`
}

// Creditor is the payee.
type Creditor struct {
	Name    string         `json:"name,omitempty"`
	Account Identifier     `json:"account"`
	Agent   *Agent         `json:"agent,omitempty"`
	Address *PostalAddress `json:"address,omitempty"`
}

// Agent identifies the payee's bank.
type Agent struct {
	BIC            string         `json:"bic,omitempty"`
	ClearingSystem string         `json:"clearing_system,omitempty"` // e.g. "GBDSC" (UK sort code), "USABA"
	MemberID       string         `json:"member_id,omitempty"`
	Name           string         `json:"name,omitempty"`    // for international payments, where the bank asks for it
	Address        *PostalAddress `json:"address,omitempty"` // likewise
}

// PostalAddress is a postal address.
type PostalAddress struct {
	Street         string   `json:"street,omitempty"`
	BuildingNumber string   `json:"building_number,omitempty"`
	PostCode       string   `json:"post_code,omitempty"`
	Town           string   `json:"town,omitempty"`
	Country        string   `json:"country,omitempty"` // ISO 3166-1 alpha-2
	Lines          []string `json:"lines,omitempty"`   // unstructured lines, when structured parts are unknown
}

func (a *PostalAddress) empty() bool {
	return a == nil || (a.Street == "" && a.BuildingNumber == "" && a.PostCode == "" && a.Town == "" && a.Country == "" && len(a.Lines) == 0)
}

// Reference is a structured creditor reference.
type Reference struct {
	Scheme string `json:"scheme"` // ReferenceRF, ReferenceOCR, ...
	Value  string `json:"value"`
}

// PaymentStatus is the normalized payment status. It is a separate axis from
// the authorisation Steps: StepDone means the user authorised the payment and
// the bank accepted it, not that the money arrived.
type PaymentStatus string

const (
	PaymentReceived          PaymentStatus = "received"           // created, not yet authorised or checked
	PaymentAccepted          PaymentStatus = "accepted"           // authorised and accepted by the bank (technical and customer checks)
	PaymentInProgress        PaymentStatus = "in_progress"        // being executed or settled; future-dated payments wait here
	PaymentCompleted         PaymentStatus = "completed"          // settled
	PaymentPartiallyAccepted PaymentStatus = "partially_accepted" // more approvals are needed (multi-signer) or only some transfers were accepted
	PaymentRejected          PaymentStatus = "rejected"
	PaymentCancelled         PaymentStatus = "cancelled"
)

// Payment is a payment at the bank.
type Payment struct {
	ID         string        `json:"id"` // the bank's payment id
	Type       PaymentType   `json:"type"`
	Status     PaymentStatus `json:"status"`
	BankStatus string        `json:"bank_status,omitempty"` // the bank's own status code
	Final      bool          `json:"final"`                 // no further status changes are expected
	Reason     string        `json:"reason,omitempty"`      // status reason, when the bank gives one

	// Ref identifies the payment for PaymentStatus and CancelPayment. It is
	// opaque and serializable and holds no tokens; store it with the payment.
	Ref string `json:"ref"`

	Debtor *Identifier     `json:"debtor,omitempty"` // the account the user paid from, when the bank reports it
	Raw    json.RawMessage `json:"raw,omitempty"`
}

// PaymentCallOptions are inputs to PaymentStatus and CancelPayment.
type PaymentCallOptions struct {
	// Session is needed by banks that read payments with the user's token
	// (PaymentSpec.StatusNeedsSession); persist the one the payment's steps returned.
	Session     *Session
	PSU         *PSUContext
	RedirectURL string // for cancellations that need the user's approval
	Method      string
}

// ---- requirements ----

// Field paths of PaymentRequest, as used in PaymentField.Path and FieldIssue.Path.
// "transfers." paths apply to every transfer.
const (
	FieldDebtorAccount       = "debtor.account"
	FieldDebtorName          = "debtor.name"
	FieldDebtorCurrency      = "debtor.currency"
	FieldAmount              = "transfers.amount"
	FieldCreditorName        = "transfers.creditor.name"
	FieldCreditorAccount     = "transfers.creditor.account"
	FieldCreditorBIC         = "transfers.creditor.agent.bic"
	FieldCreditorClearing    = "transfers.creditor.agent.member_id"
	FieldCreditorBankName    = "transfers.creditor.agent.name"
	FieldCreditorBankAddress = "transfers.creditor.agent.address"
	FieldCreditorAddress     = "transfers.creditor.address"
	FieldCreditorCountry     = "transfers.creditor.address.country"
	FieldRemittance          = "transfers.remittance"
	FieldReference           = "transfers.reference"
	FieldEndToEndID          = "transfers.end_to_end_id"
	FieldInstructionID       = "transfers.instruction_id"
	FieldExecutionDate       = "execution_date"
	FieldChargeBearer        = "charge_bearer"
	FieldContext             = "context"
)

// FieldUse says whether a field must be set.
type FieldUse string

const (
	FieldRequired FieldUse = "required"
	FieldOptional FieldUse = "optional"
)

// PaymentField describes one PaymentRequest field for a payment type at a
// bank. Fields not listed in a PaymentSpec are not supported there, and
// setting them is a validation error rather than being dropped silently.
// Amount and creditor account are always required, listed or not.
type PaymentField struct {
	Path string   `json:"path"`
	Use  FieldUse `json:"use"`

	// Ask: when left empty, the value is collected later, by an input Step or
	// on the bank's own pages (e.g. the user picks the debtor account at the bank).
	Ask bool `json:"ask,omitempty"`

	Schemes   []string `json:"schemes,omitempty"`    // accepted identifier or reference schemes
	MaxLength int      `json:"max_length,omitempty"` // per value (per line for remittance)
	MaxItems  int      `json:"max_items,omitempty"`  // lines, for remittance
	Pattern   string   `json:"pattern,omitempty"`    // regexp each value must match
	Options   []Option `json:"options,omitempty"`    // closed set of values
	Label     string   `json:"label,omitempty"`
	Note      string   `json:"note,omitempty"`

	// SchemeRules add limits for values of one scheme, on top of the
	// field's own and the scheme's format (ValidateIdentifier).
	SchemeRules []SchemeRule `json:"scheme_rules,omitempty"`

	// OnlyWith limits the field to requests where another field uses one of
	// the given schemes, e.g. an OCR reference only for Bankgiro payees.
	OnlyWith *FieldCondition `json:"only_with,omitempty"`
}

// SchemeRule constrains the values of one identifier or reference scheme.
type SchemeRule struct {
	Scheme    string `json:"scheme"`
	MaxLength int    `json:"max_length,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	Label     string `json:"label,omitempty"`
	Note      string `json:"note,omitempty"`
}

// FieldCondition names the schemes another field must use. Path is
// FieldDebtorAccount, FieldCreditorAccount or FieldReference.
type FieldCondition struct {
	Path    string   `json:"path"`
	Schemes []string `json:"schemes"`
}

// PaymentSpec is what a bank supports and needs for one payment type.
type PaymentSpec struct {
	Type      PaymentType `json:"type"`
	Countries []Country   `json:"countries,omitempty"` // empty: every country of the integration
	Segments  []Segment   `json:"segments,omitempty"`  // empty: every segment

	Currencies   []string `json:"currencies,omitempty"`    // empty: not restricted by the SDK
	MaxTransfers int      `json:"max_transfers,omitempty"` // transfers per payment; 0 or 1 means single payments only

	// ExecutionDateMaxDays is how far ahead ExecutionDate may be, when the
	// execution_date field is supported. 0 means no published limit.
	ExecutionDateMaxDays int `json:"execution_date_max_days,omitempty"`

	AuthApproaches []string        `json:"auth_approaches,omitempty"` // "redirect", "decoupled"
	FinalStatuses  []PaymentStatus `json:"final_statuses,omitempty"`  // statuses this bank treats as final success
	Cancellable    bool            `json:"cancellable,omitempty"`     // not-yet-executed payments can be cancelled

	// StatusNeedsSession: PaymentStatus and CancelPayment need the user's session.
	StatusNeedsSession bool `json:"status_needs_session,omitempty"`

	Fields []PaymentField `json:"fields"`
	Notes  []string       `json:"notes,omitempty"`
}

// Field returns the spec of a field path.
func (s PaymentSpec) Field(path string) (PaymentField, bool) {
	for _, f := range s.Fields {
		if f.Path == path {
			return f, true
		}
	}
	return PaymentField{}, false
}

func (s PaymentSpec) appliesTo(c Country, seg Segment) bool {
	okC := len(s.Countries) == 0
	for _, x := range s.Countries {
		okC = okC || x == c
	}
	okS := len(s.Segments) == 0 || seg == ""
	for _, x := range s.Segments {
		okS = okS || x == seg
	}
	return okC && okS
}

// PaymentSpec returns the spec of a payment type for a country and segment
// (empty segment matches any).
func (i Info) PaymentSpec(c Country, s Segment, t PaymentType) (PaymentSpec, bool) {
	c = Country(strings.ToUpper(string(c)))
	for _, p := range i.Payments {
		if p.Type == t && p.appliesTo(c, s) {
			return p, true
		}
	}
	return PaymentSpec{}, false
}

// PaymentTypes lists the payment types offered for a country and segment.
func (i Info) PaymentTypes(c Country, s Segment) []PaymentType {
	c = Country(strings.ToUpper(string(c)))
	var out []PaymentType
	for _, p := range i.Payments {
		if p.appliesTo(c, s) {
			out = append(out, p.Type)
		}
	}
	return out
}

// ---- validation ----

// Issue codes (FieldIssue.Code).
const (
	IssueRequired    = "required"
	IssueUnsupported = "unsupported"
	IssueTooLong     = "too_long"
	IssueTooMany     = "too_many"
	IssuePattern     = "pattern"
	IssueScheme      = "scheme"
	IssueOption      = "option"
	IssueCurrency    = "currency"
	IssueAmount      = "amount"
	IssueDate        = "date"
	IssueType        = "type"
	IssueInvalid     = "invalid" // fails the scheme's format or check digits
)

// FieldIssue is one problem with a PaymentRequest.
type FieldIssue struct {
	Path    string `json:"path"`
	Index   int    `json:"index"` // transfer index for "transfers." paths, else -1
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PaymentValidationError lists everything wrong with a request at once, so
// a form can mark every field. It matches ErrInvalidRequest.
type PaymentValidationError struct {
	Issues []FieldIssue
}

func (e *PaymentValidationError) Error() string {
	parts := make([]string, 0, len(e.Issues))
	for _, i := range e.Issues {
		p := i.Path
		if i.Index >= 0 {
			p = strings.Replace(p, "transfers.", fmt.Sprintf("transfers[%d].", i.Index), 1)
		}
		parts = append(parts, p+": "+i.Message)
	}
	return "obsdk: invalid payment: " + strings.Join(parts, "; ")
}
func (e *PaymentValidationError) Is(t error) bool { return t == ErrInvalidRequest }

// ValidatePayment checks a request against a spec without calling the bank.
func ValidatePayment(spec PaymentSpec, r PaymentRequest) error { return spec.Validate(r, time.Now()) }

var amountRE = regexp.MustCompile(`^\d+(\.\d+)?$`)

// Validate checks a request against the spec; now bounds the execution date.
func (s PaymentSpec) Validate(r PaymentRequest, now time.Time) error {
	v := validator{spec: s, req: r}
	if r.Type != s.Type {
		v.add(FieldIssue{Path: "type", Index: -1, Code: IssueType, Message: fmt.Sprintf("spec is for %q, request is %q", s.Type, r.Type)})
	}
	maxT := s.MaxTransfers
	if maxT < 1 {
		maxT = 1
	}
	switch {
	case len(r.Transfers) == 0:
		v.add(FieldIssue{Path: "transfers", Index: -1, Code: IssueRequired, Message: "at least one transfer is needed"})
	case len(r.Transfers) > maxT:
		v.add(FieldIssue{Path: "transfers", Index: -1, Code: IssueTooMany, Message: fmt.Sprintf("at most %d transfer(s) per payment", maxT)})
	}

	var d PaymentDebtor
	if r.Debtor != nil {
		d = *r.Debtor
	}
	if d.Account != nil && d.Account.Value != "" {
		v.ident(FieldDebtorAccount, -1, *d.Account)
	} else {
		v.missing(FieldDebtorAccount, -1)
	}
	v.str(FieldDebtorName, -1, d.Name)
	v.str(FieldDebtorCurrency, -1, d.Currency)
	v.str(FieldExecutionDate, -1, r.ExecutionDate)
	v.str(FieldChargeBearer, -1, r.ChargeBearer)
	v.str(FieldContext, -1, r.Context)
	if r.ExecutionDate != "" {
		v.date(r.ExecutionDate, now)
	}

	for i, t := range r.Transfers {
		v.amount(i, t.Amount)
		if t.Creditor.Account.Value == "" {
			v.add(FieldIssue{Path: FieldCreditorAccount, Index: i, Code: IssueRequired, Message: "is required"})
		} else {
			v.ident(FieldCreditorAccount, i, t.Creditor.Account)
		}
		v.str(FieldCreditorName, i, t.Creditor.Name)
		var ag Agent
		if t.Creditor.Agent != nil {
			ag = *t.Creditor.Agent
		}
		v.str(FieldCreditorBIC, i, ag.BIC)
		v.str(FieldCreditorClearing, i, ag.MemberID)
		v.str(FieldCreditorBankName, i, ag.Name)
		if ag.Address.empty() {
			v.missing(FieldCreditorBankAddress, i)
		} else {
			v.present(FieldCreditorBankAddress, i)
		}
		if t.Creditor.Address.empty() {
			v.missing(FieldCreditorAddress, i)
			v.missing(FieldCreditorCountry, i)
		} else {
			v.present(FieldCreditorAddress, i)
			v.str(FieldCreditorCountry, i, t.Creditor.Address.Country)
		}
		v.lines(i, t.Remittance)
		if t.Reference != nil && t.Reference.Value != "" {
			if f, ok := v.present(FieldReference, i); ok {
				v.scheme(f, i, t.Reference.Scheme)
				v.value(f, i, t.Reference.Value)
				v.schemeValue(f, i, t.Reference.Scheme, t.Reference.Value)
				if err := ValidateReference(*t.Reference); err != nil {
					v.add(FieldIssue{Path: f.Path, Index: i, Code: IssueInvalid, Message: err.Error()})
				}
			}
		} else {
			v.missing(FieldReference, i)
		}
		v.str(FieldEndToEndID, i, t.EndToEndID)
		v.str(FieldInstructionID, i, t.InstructionID)
	}
	if len(v.issues) > 0 {
		return &PaymentValidationError{Issues: v.issues}
	}
	return nil
}

type validator struct {
	spec   PaymentSpec
	req    PaymentRequest
	issues []FieldIssue
}

func (v *validator) add(i FieldIssue) { v.issues = append(v.issues, i) }

// missing reports a required field that was left empty (unless it is asked later).
func (v *validator) missing(path string, idx int) {
	if f, ok := v.spec.Field(path); ok && f.Use == FieldRequired && !f.Ask {
		v.add(FieldIssue{Path: path, Index: idx, Code: IssueRequired, Message: "is required"})
	}
}

// present reports a set field the spec does not support.
func (v *validator) present(path string, idx int) (PaymentField, bool) {
	f, ok := v.spec.Field(path)
	if !ok {
		v.add(FieldIssue{Path: path, Index: idx, Code: IssueUnsupported, Message: "is not supported for this payment type"})
		return f, false
	}
	if c := f.OnlyWith; c != nil && !contains(c.Schemes, v.schemeAt(c.Path, idx)) {
		v.add(FieldIssue{Path: path, Index: idx, Code: IssueUnsupported,
			Message: fmt.Sprintf("is only supported when %s is %s", c.Path, strings.Join(c.Schemes, " or "))})
		return f, false
	}
	return f, true
}

// schemeAt returns the scheme used by an identifier or reference field.
func (v *validator) schemeAt(path string, idx int) string {
	if path == FieldDebtorAccount {
		if d := v.req.Debtor; d != nil && d.Account != nil {
			return d.Account.Scheme
		}
		return ""
	}
	if idx < 0 || idx >= len(v.req.Transfers) {
		return ""
	}
	t := v.req.Transfers[idx]
	switch path {
	case FieldCreditorAccount:
		return t.Creditor.Account.Scheme
	case FieldReference:
		if t.Reference != nil {
			return t.Reference.Scheme
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (v *validator) str(path string, idx int, val string) {
	if val == "" {
		v.missing(path, idx)
		return
	}
	if f, ok := v.present(path, idx); ok {
		v.value(f, idx, val)
	}
}

// value checks length, pattern and options.
func (v *validator) value(f PaymentField, idx int, val string) {
	if f.MaxLength > 0 && len([]rune(val)) > f.MaxLength {
		v.add(FieldIssue{Path: f.Path, Index: idx, Code: IssueTooLong, Message: fmt.Sprintf("is longer than %d characters", f.MaxLength)})
	}
	if f.Pattern != "" {
		if re, err := regexp.Compile(f.Pattern); err == nil && !re.MatchString(val) {
			v.add(FieldIssue{Path: f.Path, Index: idx, Code: IssuePattern, Message: fmt.Sprintf("does not match %s", f.Pattern)})
		}
	}
	if len(f.Options) > 0 {
		ok := false
		for _, o := range f.Options {
			ok = ok || o.Value == val
		}
		if !ok {
			v.add(FieldIssue{Path: f.Path, Index: idx, Code: IssueOption, Message: fmt.Sprintf("%q is not one of the allowed values", val)})
		}
	}
}

// schemeValue applies the field's rule for the value's scheme.
func (v *validator) schemeValue(f PaymentField, idx int, scheme, val string) {
	for _, r := range f.SchemeRules {
		if r.Scheme == scheme {
			v.value(PaymentField{Path: f.Path, MaxLength: r.MaxLength, Pattern: r.Pattern}, idx, val)
		}
	}
}

func (v *validator) scheme(f PaymentField, idx int, scheme string) {
	if len(f.Schemes) == 0 || contains(f.Schemes, scheme) {
		return
	}
	v.add(FieldIssue{Path: f.Path, Index: idx, Code: IssueScheme, Message: fmt.Sprintf("scheme %q is not accepted (want one of %s)", scheme, strings.Join(f.Schemes, ", "))})
}

func (v *validator) ident(path string, idx int, id Identifier) {
	f, ok := v.spec.Field(path)
	if !ok && path != FieldCreditorAccount { // the creditor account is always accepted; the spec may leave it implicit
		v.present(path, idx)
		return
	}
	if ok {
		v.scheme(f, idx, id.Scheme)
		v.value(f, idx, id.Value)
		v.schemeValue(f, idx, id.Scheme, id.Value)
	}
	if err := ValidateIdentifier(id); err != nil {
		v.add(FieldIssue{Path: path, Index: idx, Code: IssueInvalid, Message: err.Error()})
	}
}

func (v *validator) lines(idx int, ls []string) {
	if len(ls) == 0 {
		v.missing(FieldRemittance, idx)
		return
	}
	f, ok := v.present(FieldRemittance, idx)
	if !ok {
		return
	}
	if f.MaxItems > 0 && len(ls) > f.MaxItems {
		v.add(FieldIssue{Path: f.Path, Index: idx, Code: IssueTooMany, Message: fmt.Sprintf("at most %d line(s)", f.MaxItems)})
	}
	for _, l := range ls {
		v.value(f, idx, l)
	}
}

func (v *validator) amount(idx int, m Money) {
	a := string(m.Amount)
	if !amountRE.MatchString(a) {
		v.add(FieldIssue{Path: FieldAmount, Index: idx, Code: IssueAmount, Message: "must be a positive decimal with a dot, e.g. \"10.50\""})
	} else if r, ok := m.Amount.Rat(); !ok || r.Sign() <= 0 {
		v.add(FieldIssue{Path: FieldAmount, Index: idx, Code: IssueAmount, Message: "must be greater than zero"})
	} else if f, ok := v.spec.Field(FieldAmount); ok {
		v.value(f, idx, a)
	}
	switch {
	case len(m.Currency) != 3 || strings.ToUpper(m.Currency) != m.Currency:
		v.add(FieldIssue{Path: FieldAmount, Index: idx, Code: IssueCurrency, Message: "currency must be an ISO 4217 code, e.g. \"EUR\""})
	case len(v.spec.Currencies) > 0:
		for _, c := range v.spec.Currencies {
			if c == m.Currency {
				return
			}
		}
		v.add(FieldIssue{Path: FieldAmount, Index: idx, Code: IssueCurrency, Message: fmt.Sprintf("currency %s is not accepted (want one of %s)", m.Currency, strings.Join(v.spec.Currencies, ", "))})
	}
}

func (v *validator) date(s string, now time.Time) {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		v.add(FieldIssue{Path: FieldExecutionDate, Index: -1, Code: IssueDate, Message: "must be YYYY-MM-DD"})
		return
	}
	// Banks judge "today" in their own time zone; only reject dates that are
	// in the past everywhere and leave the exact cut-off to the bank.
	today := now.UTC().Add(-14 * time.Hour).Truncate(24 * time.Hour)
	if d.Before(today) {
		v.add(FieldIssue{Path: FieldExecutionDate, Index: -1, Code: IssueDate, Message: "is in the past"})
		return
	}
	if max := v.spec.ExecutionDateMaxDays; max > 0 && d.After(now.UTC().Truncate(24*time.Hour).AddDate(0, 0, max)) {
		v.add(FieldIssue{Path: FieldExecutionDate, Index: -1, Code: IssueDate, Message: fmt.Sprintf("is more than %d days ahead", max)})
	}
}

// ErrPaymentRejected: the bank refused the payment (limits, funds, recipient
// not allowed, ...). PaymentRejectedError carries the details.
var ErrPaymentRejected = errors.New("obsdk: payment rejected")

// PaymentRejectedError explains a refused payment.
type PaymentRejectedError struct {
	Reason  string // e.g. "daily_limit", "insufficient_funds", or the bank's code
	Payment *Payment
	Err     error
}

func (e *PaymentRejectedError) Error() string {
	s := "obsdk: payment rejected: " + e.Reason
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}
func (e *PaymentRejectedError) Unwrap() error   { return e.Err }
func (e *PaymentRejectedError) Is(t error) bool { return t == ErrPaymentRejected }
