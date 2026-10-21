package stet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/bgstatus"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation follows STET: a payment request created with a client
// token (POST /payment-requests), the user's approval on the bank's page
// (the consentApproval link), then the PISP's confirmation
// (POST /payment-requests/{id}/confirmation) as Profile.Confirmation says.
// The user comes back to successfulReportUrl or unsuccessfulReportUrl; both
// are the redirect URL with the flow's state (and an error on the latter).

// payFlow is the serialized state of a payment or a cancellation.
type payFlow struct {
	Type   obsdk.PaymentType `json:"type"`
	ID     string            `json:"id"`              // payment request resource id
	Nonce  string            `json:"nonce,omitempty"` // sent with the confirmation
	Cancel bool              `json:"cancel,omitempty"`
}

// paymentRef is what Payment.Ref holds: enough to read the payment later.
type paymentRef struct {
	Integration string            `json:"i"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
}

const errNotApproved = "payment_not_approved"

// ---- request body ----

// PaymentRequestBody is STET's PaymentRequestResource as this adapter sends
// it. Profile.AdjustPayment may change it.
type PaymentRequestBody struct {
	PaymentInformationID      string                 `json:"paymentInformationId"`
	CreationDateTime          string                 `json:"creationDateTime"`
	NumberOfTransactions      int                    `json:"numberOfTransactions"`
	InitiatingParty           Party                  `json:"initiatingParty"`
	PaymentTypeInformation    PaymentTypeInformation `json:"paymentTypeInformation"`
	Debtor                    *Party                 `json:"debtor,omitempty"`
	DebtorAccount             *AccountID             `json:"debtorAccount,omitempty"`
	Beneficiary               *Beneficiary           `json:"beneficiary,omitempty"` // payment level: Profile.PaymentLevel
	ChargeBearer              string                 `json:"chargeBearer,omitempty"`
	RequestedExecutionDate    string                 `json:"requestedExecutionDate,omitempty"` // payment level: Profile.PaymentLevel
	CreditTransferTransaction []CreditTransfer       `json:"creditTransferTransaction"`
	SupplementaryData         SupplementaryData      `json:"supplementaryData"`
}

// Party is a PartyIdentification.
type Party struct {
	Name          string         `json:"name"`
	PostalAddress *PostalAddress `json:"postalAddress,omitempty"`
}

// PostalAddress is the unstructured address SEPA allows: a country and at
// most two lines.
type PostalAddress struct {
	Country     string   `json:"country"`
	AddressLine []string `json:"addressLine,omitempty"`
}

// AccountID is an AccountIdentification.
type AccountID struct {
	IBAN     string     `json:"iban,omitempty"`
	Other    *GenericID `json:"other,omitempty"`
	Currency string     `json:"currency,omitempty"`
}

// GenericID is a GenericIdentification.
type GenericID struct {
	Identification string `json:"identification"`
	SchemeName     string `json:"schemeName"`
}

// PaymentTypeInformation selects the scheme.
type PaymentTypeInformation struct {
	InstructionPriority string `json:"instructionPriority,omitempty"`
	ServiceLevel        string `json:"serviceLevel,omitempty"`
	LocalInstrument     string `json:"localInstrument,omitempty"`
	CategoryPurpose     string `json:"categoryPurpose,omitempty"`
}

// CreditTransfer is one CreditTransferTransaction.
type CreditTransfer struct {
	PaymentID              PaymentID    `json:"paymentId"`
	RequestedExecutionDate string       `json:"requestedExecutionDate,omitempty"`
	InstructedAmount       Amount       `json:"instructedAmount"`
	Beneficiary            *Beneficiary `json:"beneficiary,omitempty"`
	RemittanceInformation  *Remittance  `json:"remittanceInformation,omitempty"`
}

// PaymentID holds the instruction and end-to-end ids.
type PaymentID struct {
	InstructionID string `json:"instructionId"`
	EndToEndID    string `json:"endToEndId,omitempty"`
}

// Amount is an AmountType; the amount is a JSON number written exactly, or
// a JSON string when Quoted (Profile.AmountString).
type Amount struct {
	Amount   json.Number `json:"amount"`
	Currency string      `json:"currency"`
	Quoted   bool        `json:"-"`
}

// MarshalJSON writes the amount as a number, or as a string when Quoted.
func (a Amount) MarshalJSON() ([]byte, error) {
	if a.Quoted {
		return json.Marshal(struct {
			Amount   string `json:"amount"`
			Currency string `json:"currency"`
		}{string(a.Amount), a.Currency})
	}
	type plain Amount
	return json.Marshal(plain(a))
}

// Beneficiary is the creditor with its account and bank.
type Beneficiary struct {
	CreditorAgent   *Agent    `json:"creditorAgent,omitempty"`
	Creditor        Party     `json:"creditor"`
	CreditorAccount AccountID `json:"creditorAccount"`
}

// Agent is a FinancialInstitutionIdentification.
type Agent struct {
	BICFI string `json:"bicFi"`
}

// Remittance is RemittanceInformation.
type Remittance struct {
	Unstructured []string               `json:"unstructured,omitempty"`
	Structured   []StructuredRemittance `json:"structured,omitempty"`
}

// StructuredRemittance carries a creditor reference.
type StructuredRemittance struct {
	CreditorReferenceInformation *CreditorReference `json:"creditorReferenceInformation,omitempty"`
}

// CreditorReference is CreditorReferenceInformation.
type CreditorReference struct {
	Type      *CodeAndIssuer `json:"type,omitempty"`
	Reference string         `json:"reference"`
}

// CodeAndIssuer is a code with its issuer.
type CodeAndIssuer struct {
	Code   string `json:"code"`
	Issuer string `json:"issuer,omitempty"`
}

// SupplementaryData carries the authentication approaches and report URLs.
type SupplementaryData struct {
	AcceptedAuthenticationApproach []string `json:"acceptedAuthenticationApproach"`
	SuccessfulReportURL            string   `json:"successfulReportUrl,omitempty"`
	UnsuccessfulReportURL          string   `json:"unsuccessfulReportUrl,omitempty"`
}

// ShortID turns a generated id into one that fits STET's 35/36 character
// identifiers.
func ShortID(id string, max int) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > max {
		id = id[:max]
	}
	return id
}

func address(a *obsdk.PostalAddress) *PostalAddress {
	if a == nil || a.Country == "" {
		return nil
	}
	lines := a.Lines
	if len(lines) == 0 {
		street := strings.TrimSpace(a.Street + " " + a.BuildingNumber)
		town := strings.TrimSpace(a.PostCode + " " + a.Town)
		for _, l := range []string{street, town} {
			if l != "" {
				lines = append(lines, l)
			}
		}
	}
	return &PostalAddress{Country: a.Country, AddressLine: lines}
}

func accountID(id obsdk.Identifier, currency string) AccountID {
	if id.Scheme == obsdk.SchemeIBAN || id.Scheme == "" {
		return AccountID{IBAN: strings.ReplaceAll(id.Value, " ", ""), Currency: currency}
	}
	return AccountID{Other: &GenericID{Identification: id.Value, SchemeName: id.Scheme}, Currency: currency}
}

// dateTimeLayout is STET's ISODateTime for execution dates: a date-time
// without fractional seconds.
const dateTimeLayout = "2006-01-02T15:04:05-07:00"

// executionDateTime turns YYYY-MM-DD into the date-time STET asks for.
func executionDateTime(d string) string {
	if d == "" || len(d) > 10 {
		return d
	}
	return d + "T00:00:00+00:00"
}

// buildPayment builds the request body for a validated payment.
func (c *client) buildPayment(r obsdk.PaymentRequest, successURL, failureURL string) (*PaymentRequestBody, error) {
	newID := func(max int) string { return ShortID(c.cfg.ID(obsdk.IDRequest), max) }
	now := c.now().UTC()
	b := &PaymentRequestBody{
		PaymentInformationID: newID(35),
		CreationDateTime:     now.Format(dateTimeLayout),
		NumberOfTransactions: len(r.Transfers),
		InitiatingParty:      Party{Name: c.cfg.Param(ParamInitiatingParty)},
		PaymentTypeInformation: PaymentTypeInformation{
			ServiceLevel: "SEPA", CategoryPurpose: "CASH",
		},
		ChargeBearer: "SLEV",
		SupplementaryData: SupplementaryData{AcceptedAuthenticationApproach: []string{"REDIRECT"},
			SuccessfulReportURL: successURL, UnsuccessfulReportURL: failureURL},
	}
	switch r.Type {
	case obsdk.PaymentSEPA:
	case obsdk.PaymentSEPAInstant:
		b.PaymentTypeInformation.LocalInstrument = "INST"
	default:
		return nil, fmt.Errorf("%w: the STET adapter builds SEPA payments only, not %q", obsdk.ErrUnsupported, r.Type)
	}
	switch r.Context {
	case obsdk.PaymentContextEcommerceGoods, obsdk.PaymentContextEcommerceServices:
		b.PaymentTypeInformation.CategoryPurpose = "DVPM" // payment on behalf of a merchant
	}
	if r.ChargeBearer != "" {
		b.ChargeBearer = r.ChargeBearer
	}
	if d := r.Debtor; d != nil {
		if d.Name != "" {
			b.Debtor = &Party{Name: d.Name}
		}
		if d.Account != nil && d.Account.Value != "" {
			a := accountID(*d.Account, d.Currency)
			b.DebtorAccount = &a
		}
	}
	for _, t := range r.Transfers {
		ct := CreditTransfer{
			PaymentID:              PaymentID{InstructionID: firstNonEmpty(t.InstructionID, newID(35)), EndToEndID: firstNonEmpty(t.EndToEndID, newID(35))},
			RequestedExecutionDate: executionDateTime(r.ExecutionDate),
			InstructedAmount:       Amount{Amount: json.Number(t.Amount.Amount), Currency: t.Amount.Currency, Quoted: c.p.AmountString},
			Beneficiary: &Beneficiary{
				Creditor:        Party{Name: t.Creditor.Name, PostalAddress: address(t.Creditor.Address)},
				CreditorAccount: accountID(t.Creditor.Account, ""),
			},
		}
		if a := t.Creditor.Agent; a != nil && a.BIC != "" {
			ct.Beneficiary.CreditorAgent = &Agent{BICFI: a.BIC}
		}
		if len(t.Remittance) > 0 || t.Reference != nil {
			rem := &Remittance{Unstructured: t.Remittance}
			if ref := t.Reference; ref != nil && ref.Value != "" {
				cr := &CreditorReference{Reference: ref.Value}
				switch ref.Scheme {
				case obsdk.ReferenceRF:
					cr.Type = &CodeAndIssuer{Code: "SCOR", Issuer: "ISO"}
				case obsdk.ReferenceBE:
					cr.Type = &CodeAndIssuer{Code: "SCOR", Issuer: "BBA"}
				}
				rem.Structured = []StructuredRemittance{{CreditorReferenceInformation: cr}}
			}
			ct.RemittanceInformation = rem
		}
		b.CreditTransferTransaction = append(b.CreditTransferTransaction, ct)
	}
	if c.p.PaymentLevel && len(b.CreditTransferTransaction) == 1 {
		ct := &b.CreditTransferTransaction[0]
		b.Beneficiary, ct.Beneficiary = ct.Beneficiary, nil
		b.RequestedExecutionDate, ct.RequestedExecutionDate = firstNonEmpty(ct.RequestedExecutionDate, now.Format(dateTimeLayout)), ""
	}
	if c.p.AdjustPayment != nil {
		if err := c.p.AdjustPayment(r, c.target, b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// ---- operations ----

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.p.Info.PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: %s offers no %q payments in %s through this SDK", obsdk.ErrUnsupported, c.p.Info.Name, t, c.target.Country)
}

// reportURLs are the redirect URL with the flow's state, and with an error
// for the unsuccessful case.
func reportURLs(redirectURL, state string) (success, failure string) {
	return withQuery(redirectURL, url.Values{"state": {state}}),
		withQuery(redirectURL, url.Values{"state": {state}, "error": {errNotApproved}})
}

type authRequest struct {
	AppliedAuthenticationApproach string `json:"appliedAuthenticationApproach"`
	Nonce                         string `json:"nonce"`
	Links                         struct {
		ConsentApproval link `json:"consentApproval"`
	} `json:"_links"`
}

// InitiatePayment creates the payment request and returns the redirect to
// the bank's approval page. Resume confirms it.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: %s only supports the redirect method here", obsdk.ErrInvalidRequest, c.target.Bank)
	}
	if c.cfg.Param(ParamInitiatingParty) == "" {
		return nil, &obsdk.ConfigError{Bank: c.target.Bank, Env: c.cfg.Env, Missing: []string{ParamInitiatingParty + " (the PISP's name, sent as initiatingParty)"}}
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	f := &flow{Phase: phPayment, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState)}
	success, failure := reportURLs(redirectURL, f.OAuthState)
	body, err := c.buildPayment(r, success, failure)
	if err != nil {
		return nil, err
	}
	cc, err := c.clientToken(ctx)
	if err != nil {
		return nil, err
	}
	key := firstNonEmpty(r.IdempotencyKey, c.cfg.ID(obsdk.IDRequest))
	q := url.Values{}
	if r.Language != "" {
		q.Set("ui_locales", r.Language)
	}
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: "/payment-requests", query: q, body: body, bearer: cc,
		psu: psuOrNil(r.PSU), header: map[string]string{"Idempotency-Key": key}, pay: true})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.paymentErr(opPayment, res)
	}
	var ar authRequest
	if len(res.body) > 0 {
		if err := json.Unmarshal(res.body, &ar); err != nil {
			return nil, fmt.Errorf("stet: unreadable payment request response (HTTP %d)", res.status)
		}
	}
	id := resourceID(res.header.Get("Location"))
	if id == "" {
		return nil, fmt.Errorf("stet: the payment request response has no Location (HTTP %d)", res.status)
	}
	f.Pay = &payFlow{Type: r.Type, ID: id, Nonce: firstNonEmpty(ar.Nonce, ShortID(c.cfg.ID(obsdk.IDState), 32))}
	pay, err := c.newPayment(f.Pay)
	if err != nil {
		return nil, err
	}
	if ar.AppliedAuthenticationApproach == "NONE" || ar.Links.ConsentApproval.Href == "" {
		// Nothing for the user to approve (an SCA exemption).
		st, err := c.completePayment(ctx, f, "")
		return st, c.withPayment(err, pay)
	}
	if f.AuthURL, err = c.approvalURL(f, ar.Links.ConsentApproval.Href, r.Language); err != nil {
		return nil, err
	}
	st, err := c.pause(f, payStep(f))
	if st != nil {
		st.Payment = pay
	}
	return st, err
}

// resourceID is the last path segment of the Location of a created resource.
func resourceID(loc string) string {
	if loc == "" {
		return ""
	}
	if u, err := url.Parse(loc); err == nil {
		loc = u.EscapedPath()
	}
	id := path.Base(strings.TrimRight(loc, "/"))
	if id == "." || id == "/" {
		return ""
	}
	if un, err := url.PathUnescape(id); err == nil {
		id = un
	}
	return id
}

// approvalURL is the consentApproval link; in the enforced redirect it is
// an authorization endpoint completed with the PISP's OAuth parameters.
func (c *client) approvalURL(f *flow, href, lang string) (string, error) {
	u, err := url.Parse(href)
	if err != nil || !u.IsAbs() {
		return "", fmt.Errorf("stet: the approval link %q is not an absolute URL", href)
	}
	if c.p.confirmation() != ConfirmAuthorizationCode {
		return href, nil
	}
	q := url.Values{"client_id": {c.cfg.Credentials.ClientID}, "redirect_uri": {f.RedirectURL}, "state": {f.OAuthState}}
	have := u.Query()
	if have.Get("response_type") == "" {
		q.Set("response_type", "code")
	}
	if have.Get("scope") == "" {
		q.Set("scope", c.p.scopePIS())
	}
	if lang != "" {
		q.Set("ui_locales", lang)
	}
	return withQuery(href, q), nil
}

func payStep(f *flow) *obsdk.Step {
	msg := "Send the user to the bank to approve the payment, then pass the callback URL to Resume."
	if f.Pay.Cancel {
		msg = "Send the user to the bank to approve the cancellation, then pass the callback URL to Resume."
	}
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL}, Message: msg}
}

func (c *client) newPayment(p *payFlow) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: c.p.ID, ID: p.ID, Type: p.Type})
	if err != nil {
		return nil, err
	}
	return &obsdk.Payment{ID: p.ID, Type: p.Type, Status: obsdk.PaymentReceived, Ref: ref}, nil
}

// withPayment wraps a failure after the payment exists so its id survives.
func (c *client) withPayment(err error, pay *obsdk.Payment) error {
	var fe *obsdk.FlowError
	if err == nil || errors.As(err, &fe) {
		return err
	}
	return &obsdk.FlowError{Payment: pay, Err: err}
}

// resumePayment handles the user's return from the approval page.
func (c *client) resumePayment(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	pay, err := c.newPayment(f.Pay)
	if err != nil {
		return nil, err
	}
	if in.Callback == "" {
		st, err := c.pause(f, payStep(f))
		if st != nil {
			st.Payment = pay
		}
		return st, err
	}
	p, err := callback.Parse(in.Callback)
	switch {
	case errors.Is(err, callback.ErrNoParams):
		// Back without parameters: the status tells what happened.
		p = callback.Params{}
	case err != nil:
		return nil, &obsdk.FlowError{Payment: pay, Err: fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)}
	}
	// A cancellation only reads the status afterwards, so its state is not
	// checked: some banks (BNP Paribas Fortis) send the user back to the
	// report URLs of the original payment, with that payment's state.
	if st := p.Get("state"); st != "" && st != f.OAuthState && !f.Pay.Cancel {
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("callback state does not match the payment that was started")}
	}
	if code, desc, failed := p.Error(); failed {
		cur, rerr := c.readPayment(ctx, f.Pay, psuOrNil(f.PSU))
		if rerr != nil {
			cur = pay
		}
		what := "payment"
		if f.Pay.Cancel {
			what = "cancellation"
		}
		return nil, &obsdk.FlowError{Payment: cur, Err: authFailed("the %s was not approved (%s)", what, strings.TrimSpace(code+" "+desc))}
	}
	if f.Pay.Cancel {
		st, err := c.finishCancel(ctx, f)
		return st, c.withPayment(err, pay)
	}
	st, err := c.completePayment(ctx, f, p.Get("code"))
	return st, c.withPayment(err, pay)
}

// completePayment confirms the approved payment as the profile says and
// reports its status.
func (c *client) completePayment(ctx context.Context, f *flow, code string) (*obsdk.Step, error) {
	var token string
	switch c.p.confirmation() {
	case ConfirmNone:
		pay, err := c.readPayment(ctx, f.Pay, psuOrNil(f.PSU))
		if err != nil {
			return nil, err
		}
		return finished(pay)
	case ConfirmAuthorizationCode:
		if code == "" {
			return nil, fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
		}
		tr, err := c.exchangeCode(ctx, f, code)
		if err != nil {
			return nil, err
		}
		token = tr.AccessToken
	default:
		var err error
		if token, err = c.clientToken(ctx); err != nil {
			return nil, err
		}
	}
	res, err := c.do(ctx, req{op: opConfirm, method: http.MethodPost, path: "/payment-requests/" + url.PathEscape(f.Pay.ID) + "/confirmation",
		body: map[string]string{"nonce": f.Pay.Nonce}, bearer: token, psu: psuOrNil(f.PSU),
		header: map[string]string{"Idempotency-Key": f.Pay.Nonce}})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK && res.status != http.StatusCreated {
		return nil, c.paymentErr(opConfirm, res)
	}
	pay, err := c.toPayment(f.Pay.ID, f.Pay.Type, res.body)
	if err != nil {
		return nil, err
	}
	return finished(pay)
}

// exchangeCode exchanges the enforced redirect's code for the confirmation token.
func (c *client) exchangeCode(ctx context.Context, f *flow, code string) (*tokenResponse, error) {
	tr, r, err := c.tokenCall(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURL}})
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	return tr, nil
}

func finished(pay *obsdk.Payment) (*obsdk.Step, error) {
	switch pay.Status {
	case obsdk.PaymentRejected:
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: strings.ToLower(firstNonEmpty(pay.Reason, pay.BankStatus)), Payment: pay}}
	case obsdk.PaymentCancelled:
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("the payment was cancelled at the bank")}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}

// paymentErr maps a failed payment call: a refusal that carries status RJCT
// is a PaymentRejectedError.
func (c *client) paymentErr(op string, r *resp) error {
	err := c.apiErr(op, r)
	var body struct {
		PaymentInformationStatus string `json:"paymentInformationStatus"`
		StatusReasonInformation  string `json:"statusReasonInformation"`
	}
	if json.Unmarshal(r.body, &body) == nil && body.PaymentInformationStatus == "RJCT" {
		return &obsdk.PaymentRejectedError{Reason: strings.ToLower(firstNonEmpty(body.StatusReasonInformation, "rejected")), Err: err}
	}
	return err
}

// ---- status ----

type paymentRequestJSON struct {
	ResourceID                string     `json:"resourceId"`
	PaymentInformationStatus  string     `json:"paymentInformationStatus"`
	StatusReasonInformation   string     `json:"statusReasonInformation"`
	DebtorAccount             *AccountID `json:"debtorAccount"`
	CreditTransferTransaction []struct {
		TransactionStatus       string `json:"transactionStatus"`
		StatusReasonInformation string `json:"statusReasonInformation"`
	} `json:"creditTransferTransaction"`
}

// toPayment reads a HalPaymentRequest ({"paymentRequest": {...}}).
func (c *client) toPayment(id string, t obsdk.PaymentType, body []byte) (*obsdk.Payment, error) {
	var hal struct {
		PaymentRequest json.RawMessage `json:"paymentRequest"`
	}
	if err := json.Unmarshal(body, &hal); err != nil || len(hal.PaymentRequest) == 0 {
		return nil, fmt.Errorf("stet: unreadable payment request")
	}
	var pr paymentRequestJSON
	if err := json.Unmarshal(hal.PaymentRequest, &pr); err != nil {
		return nil, fmt.Errorf("stet: unreadable payment request: %w", err)
	}
	// The id from the Location is the one the API reads the payment by;
	// some banks put another (internal) number in resourceId.
	pay, err := c.newPayment(&payFlow{Type: t, ID: firstNonEmpty(id, pr.ResourceID)})
	if err != nil {
		return nil, err
	}
	pay.Raw = body
	status, reason := pr.PaymentInformationStatus, pr.StatusReasonInformation
	if status == "" && len(pr.CreditTransferTransaction) == 1 {
		// Some banks report only the transaction's status.
		status = pr.CreditTransferTransaction[0].TransactionStatus
		reason = firstNonEmpty(reason, pr.CreditTransferTransaction[0].StatusReasonInformation)
	}
	pay.BankStatus, pay.Reason = status, reason
	pay.Status, pay.Final = bgstatus.Payment(status)
	if status == "RJCT" && (reason == "DS02" || reason == "CUST") {
		// Rejected because the user ordered its cancellation (DS02, or
		// CUST: cancellation requested by the debtor).
		pay.Status = obsdk.PaymentCancelled
	}
	if a := pr.DebtorAccount; a != nil {
		if a.IBAN != "" {
			pay.Debtor = &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: a.IBAN}
		} else if a.Other != nil && a.Other.Identification != "" {
			pay.Debtor = &obsdk.Identifier{Scheme: a.Other.SchemeName, Value: a.Other.Identification}
		}
	}
	return pay, nil
}

func (c *client) decodeRef(ref string) (*paymentRef, error) {
	var pr paymentRef
	if err := flowstate.Decode(ref, &pr); err != nil || pr.Integration != c.p.ID || pr.ID == "" {
		return nil, fmt.Errorf("%w: not a %s payment reference", obsdk.ErrInvalidRequest, c.target.Bank)
	}
	return &pr, nil
}

// getPayment reads GET /payment-requests/{id} with a client token.
func (c *client) getPayment(ctx context.Context, id string, psu *obsdk.PSUContext) (*resp, error) {
	cc, err := c.clientToken(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: "/payment-requests/" + url.PathEscape(id), bearer: cc, psu: psu})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.apiErr(opPayStatus, res)
	}
	return res, nil
}

func (c *client) readPayment(ctx context.Context, p *payFlow, psu *obsdk.PSUContext) (*obsdk.Payment, error) {
	res, err := c.getPayment(ctx, p.ID, psu)
	if err != nil {
		return nil, err
	}
	return c.toPayment(p.ID, p.Type, res.body)
}

// PaymentStatus reads a payment with a client token (no user session needed).
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	pr, err := c.decodeRef(ref)
	if err != nil {
		return nil, err
	}
	res, err := c.getPayment(ctx, pr.ID, o.PSU)
	if err != nil {
		return nil, err
	}
	p, err := c.toPayment(pr.ID, pr.Type, res.body)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *p, Raw: res.body, Meta: meta(res)}, nil
}

// ---- cancellation ----

// CancelPayment asks the bank to cancel a payment that has not been executed
// (STET: the payment request sent back with status CANC, or the profile's
// CancelStatus, and reason DS02). The bank may want the user to approve it on
// its page.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	pr, err := c.decodeRef(ref)
	if err != nil {
		return nil, err
	}
	spec, err := c.paymentSpec(pr.Type)
	if err != nil {
		return nil, err
	}
	if !spec.Cancellable {
		return nil, fmt.Errorf("%w: %s payments of type %q cannot be cancelled through this API", obsdk.ErrUnsupported, c.target.Bank, pr.Type)
	}
	redirectURL, err := c.redirectURL(o.RedirectURL)
	if err != nil {
		return nil, err
	}
	var psu obsdk.PSUContext
	if o.PSU != nil {
		psu = *o.PSU
	}
	f := &flow{Phase: phPayment, PSU: psu, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState),
		Pay: &payFlow{Type: pr.Type, ID: pr.ID, Cancel: true}}
	cur, err := c.getPayment(ctx, pr.ID, o.PSU)
	if err != nil {
		return nil, err
	}
	var hal struct {
		PaymentRequest map[string]any `json:"paymentRequest"`
	}
	if err := json.Unmarshal(cur.body, &hal); err != nil || hal.PaymentRequest == nil {
		return nil, fmt.Errorf("stet: unreadable payment request")
	}
	body := hal.PaymentRequest
	body["paymentInformationStatus"] = c.p.cancelStatus()
	body["statusReasonInformation"] = "DS02" // ordered by the user
	success, failure := reportURLs(redirectURL, f.OAuthState)
	sd, _ := body["supplementaryData"].(map[string]any)
	if sd == nil {
		sd = map[string]any{}
	}
	sd["acceptedAuthenticationApproach"] = []string{"REDIRECT"}
	sd["successfulReportUrl"], sd["unsuccessfulReportUrl"] = success, failure
	body["supplementaryData"] = sd

	cc, err := c.clientToken(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opCancel, method: http.MethodPut, path: "/payment-requests/" + url.PathEscape(pr.ID), body: body, bearer: cc, psu: o.PSU, pay: true})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK && res.status != http.StatusCreated && res.status != http.StatusNoContent {
		e := c.apiErr(opCancel, res)
		if res.status == http.StatusConflict || res.status == http.StatusForbidden {
			return nil, fmt.Errorf("%w: the payment can no longer be cancelled: %w", obsdk.ErrInvalidRequest, e)
		}
		return nil, e
	}
	var ar authRequest
	if len(res.body) > 0 {
		_ = json.Unmarshal(res.body, &ar)
	}
	if ar.AppliedAuthenticationApproach == "NONE" || ar.Links.ConsentApproval.Href == "" {
		return c.finishCancel(ctx, f)
	}
	// A cancellation is a simple redirect: the link is used as given.
	if u, err := url.Parse(ar.Links.ConsentApproval.Href); err != nil || !u.IsAbs() {
		return nil, fmt.Errorf("stet: the approval link %q is not an absolute URL", ar.Links.ConsentApproval.Href)
	}
	f.AuthURL = ar.Links.ConsentApproval.Href
	st, err := c.pause(f, payStep(f))
	if st != nil {
		st.Payment, _ = c.newPayment(f.Pay)
	}
	return st, err
}

// finishCancel reads the status after a cancellation; it must be cancelled
// (CANC, or RJCT with reason DS02 or CUST).
func (c *client) finishCancel(ctx context.Context, f *flow) (*obsdk.Step, error) {
	pay, err := c.readPayment(ctx, f.Pay, psuOrNil(f.PSU))
	if err != nil {
		return nil, err
	}
	if pay.Status != obsdk.PaymentCancelled {
		return nil, &obsdk.FlowError{Payment: pay, Err: fmt.Errorf("stet: %s did not cancel the payment (status %s)", c.p.Info.Name, pay.BankStatus)}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}
