package rabobank

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/bgstatus"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation (single payments): the payment is created with the
// application's client id and signature only, the user signs it on
// Rabobank's page (scaRedirect, valid 30 minutes) and comes back to
// TPP-Redirect-URI, and the status is read the same way. No user token is
// involved.

const (
	phPayRedirect    = "payment_redirect_wait"
	phCancelRedirect = "cancel_redirect_wait"

	pisBase = "/payments/payment-initiation/pis/v1/payments/"

	productSEPA  = "sepa-credit-transfers"
	productCross = "cross-border-credit-transfers"
)

// payFlow is the serialized state of a payment (or its cancellation) waiting
// for the user at Rabobank.
type payFlow struct {
	Phase   string            `json:"phase"`
	Type    obsdk.PaymentType `json:"type"`
	Product string            `json:"product"`
	ID      string            `json:"id"`
	SCAURL  string            `json:"sca_url"`
	PSU     obsdk.PSUContext  `json:"psu"`
}

// paymentRef is what Payment.Ref holds: enough to read or cancel the payment.
type paymentRef struct {
	Integration string            `json:"i"`
	Product     string            `json:"p"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
}

// ---- specs ----

// crossText is the character set Rabobank lists for cross-border remittance.
const crossText = `^[a-zA-Z0-9./\\+?;(),'@ -]*$`

const bicPattern = `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`

func paymentSpecs() []obsdk.PaymentSpec {
	common := func(schemes ...string) []obsdk.PaymentField {
		return []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,12}(\.\d{1,2})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeIBAN}, Label: "Pay from",
				Note: "Leave empty to let the user pick the account on Rabobank's page."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: schemes, MaxLength: 34, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 140, Pattern: `^.{2,}$`, Label: "Payee name"},
			{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35},
			{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
				Note: "A future date makes a scheduled payment, which can be cancelled until it is executed."},
		}
	}
	base := obsdk.PaymentSpec{
		Countries: []obsdk.Country{"NL"}, MaxTransfers: 1, AuthApproaches: []string{"redirect"}, Cancellable: true,
		FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
	}

	sepa := base
	sepa.Type, sepa.Currencies = obsdk.PaymentSEPA, []string{"EUR"}
	sepa.Fields = append(common(obsdk.SchemeIBAN),
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Description",
			Note: "Either a description or a payment reference, not both."},
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}, MaxLength: 35, Label: "Payment reference",
			Note: "Structured creditor reference (SCOR, issuer ISO)."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: bicPattern, Label: "Payee bank BIC"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address", Note: "Structured only; free address lines are not accepted."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
	)
	sepa.Notes = []string{"Sent as SEPA Instant when the payee's bank is reachable for it, otherwise as a regular SEPA credit transfer; Rabobank decides."}

	cross := base
	cross.Type = obsdk.PaymentCrossBorder
	cross.Fields = append(common(obsdk.SchemeIBAN, obsdk.SchemeBBAN),
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Pattern: crossText, Label: "Description",
			Note: "Where the destination country requires a purpose of payment, put it at the start."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldRequired, Pattern: bicPattern, Label: "Payee bank BIC"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorClearing, Use: obsdk.FieldOptional, MaxLength: 32, Label: "Payee bank code",
			Note: "National bank code (e.g. a US routing number); set Agent.ClearingSystem to its code, e.g. USABA."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldRequired, Label: "Payee address", Note: "Town and country are required; free address lines are not accepted."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldRequired, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
		obsdk.PaymentField{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldRequired, Options: []obsdk.Option{
			{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees"},
			{Value: obsdk.ChargeBearerCreditor, Label: "Payee pays all fees"},
			{Value: obsdk.ChargeBearerShared, Label: "Each pays their own bank"},
			{Value: obsdk.ChargeBearerService, Label: "As the scheme defines"},
		}},
	)
	cross.Notes = []string{"World payment: in EUR outside SEPA, or in another currency. USD accounts are given as BBAN with a clearing code."}
	return []obsdk.PaymentSpec{sepa, cross}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: Rabobank offers no %q payments", obsdk.ErrUnsupported, t)
}

// ---- request body ----

type pisAmount struct {
	Content  string `json:"content"`
	Currency string `json:"currency"`
}

type pisAccount struct {
	Currency string `json:"currency,omitempty"`
	IBAN     string `json:"iban,omitempty"`
	BBAN     string `json:"bban,omitempty"`
}

type pisAddress struct {
	BuildingNumber string `json:"buildingNumber,omitempty"`
	Country        string `json:"country,omitempty"`
	Postcode       string `json:"postcode,omitempty"`
	StreetName     string `json:"streetName,omitempty"`
	TownName       string `json:"townName,omitempty"`
}

type pisStructured struct {
	Reference       string `json:"reference"`
	ReferenceIssuer string `json:"referenceIssuer,omitempty"`
	ReferenceType   string `json:"referenceType,omitempty"`
}

type pisClearing struct {
	Code  string `json:"code"`
	Value string `json:"value"`
}

// pisBody is the SEPA and cross-border credit transfer. Fields are in the
// order of Rabobank's examples; only fields the caller set are sent.
type pisBody struct {
	ChargeBearer           string         `json:"chargeBearer,omitempty"`
	ClearingSystem         *pisClearing   `json:"clearingSystem,omitempty"`
	CreditorAccount        pisAccount     `json:"creditorAccount"`
	CreditorAddress        *pisAddress    `json:"creditorAddress,omitempty"`
	CreditorAgent          string         `json:"creditorAgent,omitempty"`
	CreditorName           string         `json:"creditorName"`
	DebtorAccount          *pisAccount    `json:"debtorAccount,omitempty"`
	EndToEndIdentification string         `json:"endToEndIdentification,omitempty"`
	InstructedAmount       pisAmount      `json:"instructedAmount"`
	Structured             *pisStructured `json:"remittanceInformationStructured,omitempty"`
	Unstructured           string         `json:"remittanceInformationUnstructured,omitempty"`
	RequestedExecutionDate string         `json:"requestedExecutionDate,omitempty"`
}

func productOf(t obsdk.PaymentType) string {
	if t == obsdk.PaymentCrossBorder {
		return productCross
	}
	return productSEPA
}

func invalid(path, msg string) error {
	return &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: path, Index: 0, Code: obsdk.IssueInvalid, Message: msg}}}
}

func buildBody(r obsdk.PaymentRequest) (pisBody, error) {
	t := r.Transfers[0]
	cur := t.Amount.Currency
	b := pisBody{
		CreditorName:           t.Creditor.Name,
		EndToEndIdentification: t.EndToEndID,
		InstructedAmount:       pisAmount{Content: string(t.Amount.Amount), Currency: cur},
		ChargeBearer:           r.ChargeBearer,
		RequestedExecutionDate: r.ExecutionDate,
	}
	if d := r.Debtor; d != nil && d.Account != nil && d.Account.Value != "" {
		b.DebtorAccount = &pisAccount{IBAN: d.Account.Value}
		if r.Type == obsdk.PaymentSEPA {
			// Always EUR; a world payment's account currency may differ from the amount's.
			b.DebtorAccount.Currency = cur
		}
	}
	b.CreditorAccount.Currency = cur
	if t.Creditor.Account.Scheme == obsdk.SchemeBBAN {
		b.CreditorAccount.BBAN = t.Creditor.Account.Value
	} else {
		b.CreditorAccount.IBAN = t.Creditor.Account.Value
	}
	if ag := t.Creditor.Agent; ag != nil {
		b.CreditorAgent = ag.BIC
		if ag.MemberID != "" {
			if ag.ClearingSystem == "" {
				return b, invalid(obsdk.FieldCreditorClearing, "needs Agent.ClearingSystem (e.g. USABA) to say which bank code it is")
			}
			b.ClearingSystem = &pisClearing{Code: ag.ClearingSystem, Value: ag.MemberID}
		}
	}
	if a := t.Creditor.Address; a != nil {
		if len(a.Lines) > 0 {
			return b, invalid(obsdk.FieldCreditorAddress, "Rabobank needs a structured address, without free lines")
		}
		if r.Type == obsdk.PaymentCrossBorder && (a.Town == "" || a.Country == "") {
			return b, invalid(obsdk.FieldCreditorAddress, "Rabobank needs the town and country for a world payment")
		}
		b.CreditorAddress = &pisAddress{BuildingNumber: a.BuildingNumber, Country: a.Country, Postcode: a.PostCode, StreetName: a.Street, TownName: a.Town}
	}
	if len(t.Remittance) > 0 {
		b.Unstructured = t.Remittance[0]
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		if b.Unstructured != "" {
			return b, invalid(obsdk.FieldReference, "Rabobank accepts a description or a payment reference, not both")
		}
		b.Structured = &pisStructured{Reference: ref.Value, ReferenceIssuer: "ISO", ReferenceType: "SCOR"}
	}
	return b, nil
}

// ---- initiate ----

type pisResponse struct {
	TransactionStatus string `json:"transactionStatus"`
	PaymentID         string `json:"paymentId"`
	Links             struct {
		SCARedirect struct {
			Href string `json:"href"`
		} `json:"scaRedirect"`
	} `json:"_links"`
}

func (c *client) redirectURL(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if u := c.cfg.Credentials.RedirectURL; u != "" {
		return u, nil
	}
	return "", fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or the request's RedirectURL)", obsdk.ErrInvalidConfig)
}

// InitiatePayment creates the payment and returns the redirect to
// Rabobank's signing page.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: Rabobank only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	if r.PSU.IP == "" {
		return nil, fmt.Errorf("%w: Rabobank requires the user's IP address (PaymentRequest.PSU.IP)", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	b, err := buildBody(r)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	product := productOf(r.Type)
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: pisBase + product, body: body,
		header: map[string]string{"TPP-Redirect-URI": redirectURL, "PSU-IP-Address": r.PSU.IP}})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.paymentErr(opPayment, res)
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil || pr.PaymentID == "" {
		return nil, fmt.Errorf("rabobank: unreadable payment response (HTTP %d)", res.status)
	}
	pf := &payFlow{Phase: phPayRedirect, Type: r.Type, Product: product, ID: pr.PaymentID, SCAURL: pr.Links.SCARedirect.Href, PSU: r.PSU}
	pay, err := c.toPayment(pf, pr.TransactionStatus, res.body)
	if err != nil {
		return nil, err
	}
	if pay.Status == obsdk.PaymentRejected {
		return nil, &obsdk.PaymentRejectedError{Reason: "rejected", Payment: pay, Err: fmt.Errorf("Rabobank rejected the payment on creation")}
	}
	if pf.SCAURL == "" {
		return nil, fmt.Errorf("rabobank: payment response has no scaRedirect link")
	}
	return c.pausePayment(pf, pay, "Send the user to Rabobank to sign the payment, then call Resume when they come back.")
}

func (c *client) pausePayment(pf *payFlow, pay *obsdk.Payment, msg string) (*obsdk.Step, error) {
	st := &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: pf.SCAURL}, Payment: pay, Message: msg}
	s, err := flowstate.Encode(pf)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// resumePayment reads the status once the user is back from signing the
// payment or its cancellation.
func (c *client) resumePayment(ctx context.Context, pf *payFlow, in obsdk.StepInput) (*obsdk.Step, error) {
	what := "payment was not signed"
	if pf.Phase == phCancelRedirect {
		what = "cancellation was not signed"
	}
	if in.Callback != "" {
		if p, err := callback.Parse(in.Callback); err == nil {
			if code, desc, failed := p.Error(); failed {
				pay, _ := c.toPayment(pf, "", nil)
				return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("%s (%s: %s)", what, code, desc)}
			}
		}
	}
	pay, err := c.readStatus(ctx, pf, &pf.PSU)
	if err != nil {
		return nil, err
	}
	if pf.Phase == phCancelRedirect {
		if pay.Status != obsdk.PaymentCancelled {
			return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("%s (status %s)", what, pay.BankStatus)}
		}
		return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
	}
	switch pay.Status {
	case obsdk.PaymentReceived, obsdk.PaymentCancelled:
		// Back without signing: Rabobank rejects the payment after 30 minutes.
		// CANC here means the user cancelled it on Rabobank's overview page.
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("%s (status %s)", what, pay.BankStatus)}
	case obsdk.PaymentRejected:
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: strings.ToLower(pay.BankStatus), Payment: pay}}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}

// ---- status and cancel ----

type statusResponse struct {
	TransactionStatus string `json:"transactionStatus"`
	FundsAvailable    string `json:"fundsAvailable"`
	PSUMessage        string `json:"psuMessage"`
	TPPMessages       []struct {
		Code string `json:"code"`
	} `json:"tppMessages"`
}

func (c *client) readStatus(ctx context.Context, pf *payFlow, psu *obsdk.PSUContext) (*obsdk.Payment, error) {
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: pisBase + pf.Product + "/" + url.PathEscape(pf.ID) + "/status",
		header: psuHeader(psu)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.paymentErr(opPayStatus, res)
	}
	var sr statusResponse
	if err := json.Unmarshal(res.body, &sr); err != nil || sr.TransactionStatus == "" {
		return nil, fmt.Errorf("rabobank: unreadable payment status (HTTP %d)", res.status)
	}
	pay, err := c.toPayment(pf, sr.TransactionStatus, res.body)
	if err != nil {
		return nil, err
	}
	// A rejection carries its ISO 20022 reason as a tppMessage (AM04:
	// insufficient funds). fundsAvailable=false: the balance was short when
	// the user signed; Rabobank retries for up to three working days.
	switch {
	case len(sr.TPPMessages) > 0 && sr.TPPMessages[0].Code != "":
		pay.Reason = sr.TPPMessages[0].Code
	case strings.EqualFold(sr.FundsAvailable, "false"):
		pay.Reason = "insufficient_funds"
	}
	return pay, nil
}

// paymentStatus maps Rabobank's ISO 20022 codes. ACTC ("not signed yet") and
// PDNG ("in progress for signing") both mean the user has not signed.
func paymentStatus(code string) (obsdk.PaymentStatus, bool) {
	switch code {
	case "ACTC", "PDNG", "":
		return obsdk.PaymentReceived, false
	}
	return bgstatus.Payment(code)
}

func (c *client) toPayment(pf *payFlow, code string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, Product: pf.Product, ID: pf.ID, Type: pf.Type})
	if err != nil {
		return nil, err
	}
	st, final := paymentStatus(code)
	return &obsdk.Payment{ID: pf.ID, Type: pf.Type, Status: st, BankStatus: code, Final: final, Ref: ref, Raw: raw}, nil
}

func decodeRef(ref string) (*payFlow, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.ID == "" ||
		(r.Product != productSEPA && r.Product != productCross) {
		return nil, fmt.Errorf("%w: not a Rabobank payment reference", obsdk.ErrInvalidRequest)
	}
	return &payFlow{Type: r.Type, Product: r.Product, ID: r.ID}, nil
}

// PaymentStatus reads a payment's status. Rabobank asks for the user's IP
// (o.PSU) on this call too.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	pf, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	pay, err := c.readStatus(ctx, pf, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: pay.Raw}, nil
}

// CancelPayment deletes a future-dated payment. Rabobank either cancels it
// at once (204) or asks the user to sign the cancellation (202 with a
// scaRedirect), which comes back as a redirect Step.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	pf, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	redirectURL, err := c.redirectURL(o.RedirectURL)
	if err != nil {
		return nil, err
	}
	h := psuHeader(o.PSU)
	if h == nil {
		h = map[string]string{}
	}
	h["TPP-Redirect-URI"] = redirectURL
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodDelete, path: pisBase + pf.Product + "/" + url.PathEscape(pf.ID), header: h})
	if err != nil {
		return nil, err
	}
	switch res.status {
	case http.StatusNoContent:
		// "The payment is cancelled, no further process needed": no need to
		// read the status again.
		pay, err := c.toPayment(pf, "CANC", nil)
		if err != nil {
			return nil, err
		}
		return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay}, nil
	case http.StatusAccepted:
		var pr pisResponse
		if err := json.Unmarshal(res.body, &pr); err != nil || pr.Links.SCARedirect.Href == "" {
			return nil, fmt.Errorf("rabobank: cancellation needs signing but the response has no scaRedirect link")
		}
		pf.Phase, pf.SCAURL = phCancelRedirect, pr.Links.SCARedirect.Href
		if o.PSU != nil {
			pf.PSU = *o.PSU
		}
		pay, err := c.toPayment(pf, pr.TransactionStatus, res.body)
		if err != nil {
			return nil, err
		}
		return c.pausePayment(pf, pay, "Send the user to Rabobank to sign the cancellation, then call Resume when they come back.")
	}
	return nil, c.paymentErr(opPayCancel, res)
}

// paymentErr maps a failed payment call. Rabobank answers every error with
// transactionStatus RJCT, so only a creation refused for a reason other than
// a malformed request, certificate or signature becomes a
// PaymentRejectedError; the rest are APIErrors.
func (c *client) paymentErr(op string, r *resp) error {
	err := c.apiErr(op, r)
	var body struct {
		TransactionStatus string `json:"transactionStatus"`
	}
	_ = json.Unmarshal(r.body, &body)
	code, _ := parseError(r.body)
	if op == opPayment && body.TransactionStatus == "RJCT" && !requestFault(code) {
		return &obsdk.PaymentRejectedError{Reason: strings.ToLower(code), Err: err}
	}
	return err
}

// requestFault reports Berlin Group codes that blame the request, not the payment.
func requestFault(code string) bool {
	switch code {
	case "", "FORMAT_ERROR", "PARAMETER_NOT_CONSISTENT", "PARAMETER_NOT_SUPPORTED", "SERVICE_INVALID", "RESOURCE_UNKNOWN":
		return true
	}
	return strings.HasPrefix(code, "CERTIFICATE_") || strings.HasPrefix(code, "SIGNATURE_")
}
