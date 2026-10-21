package kbc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/bgstatus"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation (single payments): the payment is created with the QWAC
// only (no OAuth), the user signs it on KBC's page (scaRedirect) and comes
// back to TPP-Redirect-URI, and the status is read the same way.

const (
	phPayRedirect = "payment_redirect_wait"

	productSEPA    = "sepa-credit-transfers"
	productInstant = "instant-sepa-credit-transfers"
	productCross   = "cross-border-transfers"
)

// payFlow is the serialized state of a payment waiting for the user at KBC.
type payFlow struct {
	Phase   string            `json:"phase"`
	Type    obsdk.PaymentType `json:"type"`
	Product string            `json:"product"`
	ID      string            `json:"id"`
	SCAURL  string            `json:"sca_url"`
	PSU     obsdk.PSUContext  `json:"psu"`
}

// paymentRef is what Payment.Ref holds: enough to read the payment.
type paymentRef struct {
	Integration string            `json:"i"`
	Product     string            `json:"p"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
}

// ---- specs ----

const bicPattern = `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`

func paymentSpecs() []obsdk.PaymentSpec {
	common := func() []obsdk.PaymentField {
		return []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,14}(\.\d{1,2})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeIBAN}, Label: "Pay from",
				Note: "Leave empty to let the user pick the account on KBC's page."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, MaxLength: 34, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Description"},
			{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceBE, obsdk.ReferenceRF}, MaxLength: 35, Label: "Payment reference",
				Note: "Belgian structured communication (12 digits) or RF reference."},
			{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35},
			{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: bicPattern, Label: "Payee bank BIC"},
			{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address", Note: "Structured, with the country; free address lines are not accepted."},
			{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
		}
	}
	executionDate := obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
		Note: "Empty means today; KBC's API cannot cancel a future-dated payment."}
	base := obsdk.PaymentSpec{
		Countries: []obsdk.Country{"BE"}, Currencies: []string{"EUR"}, MaxTransfers: 1, AuthApproaches: []string{"redirect"},
		FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
	}

	sepa := base
	sepa.Type = obsdk.PaymentSEPA
	sepa.Fields = append(common(), executionDate)
	sepa.Notes = []string{"KBC executes it as SEPA Instant where the payee's bank supports it, otherwise as a SEPA credit transfer."}

	instant := base
	instant.Type = obsdk.PaymentSEPAInstant
	instant.Fields = common()
	instant.Notes = []string{"SEPA Instant only; executed today."}

	cross := base
	cross.Type = obsdk.PaymentCrossBorder
	cross.Fields = append(common(), executionDate,
		obsdk.PaymentField{Path: obsdk.FieldCreditorClearing, Use: obsdk.FieldOptional, MaxLength: 35, Label: "Payee bank code",
			Note: "National bank code, sent as creditorBankCode."},
		obsdk.PaymentField{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldOptional, Options: []obsdk.Option{
			{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees"},
			{Value: obsdk.ChargeBearerCreditor, Label: "Payee pays all fees"},
			{Value: obsdk.ChargeBearerShared, Label: "Each pays their own bank"},
		}},
	)
	cross.Notes = []string{"Non-SEPA payment in EUR to an IBAN; KBC's specification accepts EUR only."}
	return []obsdk.PaymentSpec{sepa, instant, cross}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: %s offers no %q payments", obsdk.ErrUnsupported, c.brand.name, t)
}

// ---- request body ----

type pisAmount struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"`
}

type pisAccount struct {
	IBAN     string `json:"iban"`
	Currency string `json:"currency,omitempty"`
}

type pisAddress struct {
	Street         string `json:"street,omitempty"`
	BuildingNumber string `json:"buildingNumber,omitempty"`
	City           string `json:"city,omitempty"`
	PostalCode     string `json:"postalCode,omitempty"`
	Country        string `json:"country"`
}

type pisStructured struct {
	Reference       string `json:"reference"`
	ReferenceType   string `json:"referenceType,omitempty"`
	ReferenceIssuer string `json:"referenceIssuer,omitempty"`
}

// pisBody is KBC's paymentInitiation_json; only fields the caller set are sent.
type pisBody struct {
	EndToEndIdentification string         `json:"endToEndIdentification,omitempty"`
	DebtorAccount          *pisAccount    `json:"debtorAccount,omitempty"`
	InstructedAmount       pisAmount      `json:"instructedAmount"`
	CreditorAccount        pisAccount     `json:"creditorAccount"`
	CreditorAgent          string         `json:"creditorAgent,omitempty"`
	CreditorName           string         `json:"creditorName"`
	CreditorAddress        *pisAddress    `json:"creditorAddress,omitempty"`
	CreditorBankCode       string         `json:"creditorBankCode,omitempty"`
	ChargeBearer           string         `json:"chargeBearer,omitempty"`
	Unstructured           string         `json:"remittanceInformationUnstructured,omitempty"`
	Structured             *pisStructured `json:"remittanceInformationStructured,omitempty"`
	RequestedExecutionDate string         `json:"requestedExecutionDate"`
}

func productOf(t obsdk.PaymentType) string {
	switch t {
	case obsdk.PaymentSEPAInstant:
		return productInstant
	case obsdk.PaymentCrossBorder:
		return productCross
	}
	return productSEPA
}

func invalid(path, msg string) error {
	return &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: path, Index: 0, Code: obsdk.IssueInvalid, Message: msg}}}
}

// brussels is KBC's time zone, used for "today" in requestedExecutionDate.
var brussels = func() *time.Location {
	if l, err := time.LoadLocation("Europe/Brussels"); err == nil {
		return l
	}
	return time.FixedZone("CET", 3600)
}()

// buildBody maps the request. requestedExecutionDate is mandatory at KBC:
// without ExecutionDate it is today in Brussels.
func buildBody(r obsdk.PaymentRequest, now time.Time) (pisBody, error) {
	t := r.Transfers[0]
	b := pisBody{
		EndToEndIdentification: t.EndToEndID,
		InstructedAmount:       pisAmount{Currency: t.Amount.Currency, Amount: string(t.Amount.Amount)},
		CreditorAccount:        pisAccount{IBAN: t.Creditor.Account.Value},
		CreditorName:           t.Creditor.Name,
		ChargeBearer:           r.ChargeBearer,
		RequestedExecutionDate: r.ExecutionDate,
	}
	if b.RequestedExecutionDate == "" {
		b.RequestedExecutionDate = now.In(brussels).Format("2006-01-02")
	}
	if d := r.Debtor; d != nil && d.Account != nil && d.Account.Value != "" {
		b.DebtorAccount = &pisAccount{IBAN: d.Account.Value, Currency: t.Amount.Currency}
	}
	if ag := t.Creditor.Agent; ag != nil {
		b.CreditorAgent, b.CreditorBankCode = ag.BIC, ag.MemberID
	}
	if a := t.Creditor.Address; a != nil {
		if len(a.Lines) > 0 {
			return b, invalid(obsdk.FieldCreditorAddress, "KBC needs a structured address, without free lines")
		}
		if a.Country == "" {
			return b, invalid(obsdk.FieldCreditorAddress, "KBC needs the country in the payee's address")
		}
		b.CreditorAddress = &pisAddress{Street: a.Street, BuildingNumber: a.BuildingNumber, City: a.Town, PostalCode: a.PostCode, Country: a.Country}
	}
	if len(t.Remittance) > 0 {
		b.Unstructured = t.Remittance[0]
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		b.Structured = &pisStructured{Reference: ref.Value, ReferenceType: "SCOR", ReferenceIssuer: "ISO"}
		if ref.Scheme == obsdk.ReferenceBE {
			b.Structured.ReferenceIssuer = "BBA"
		}
	}
	return b, nil
}

// ---- initiate ----

type pisResponse struct {
	TransactionStatus string `json:"transactionStatus"`
	PaymentID         string `json:"paymentId"`
	Links             struct {
		SCARedirect link `json:"scaRedirect"`
	} `json:"_links"`
}

// absolute resolves a link KBC may send relative to the API host.
func (c *client) absolute(l string) string {
	u, err := url.Parse(l)
	if err != nil || u.IsAbs() {
		return l
	}
	base, err := url.Parse(c.api)
	if err != nil {
		return l
	}
	return base.ResolveReference(u).String()
}

// InitiatePayment creates the payment and returns the redirect to KBC's
// signing page.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: KBC only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	if r.PSU.IP == "" {
		return nil, fmt.Errorf("%w: KBC requires the user's IP address (PaymentRequest.PSU.IP)", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	b, err := buildBody(r, c.now())
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	product := productOf(r.Type)
	h := psuHeaders(&r.PSU)
	h["TPP-Redirect-URI"] = redirectURL
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: "/payments/" + product, body: body, header: h})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.paymentErr(opPayment, res)
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil || pr.PaymentID == "" {
		return nil, fmt.Errorf("kbc: unreadable payment response (HTTP %d)", res.status)
	}
	pf := &payFlow{Phase: phPayRedirect, Type: r.Type, Product: product, ID: pr.PaymentID, PSU: r.PSU}
	if pr.Links.SCARedirect != "" {
		pf.SCAURL = c.absolute(string(pr.Links.SCARedirect))
	}
	pay, err := c.toPayment(pf, pr.TransactionStatus, res.body)
	if err != nil {
		return nil, err
	}
	if pay.Status == obsdk.PaymentRejected {
		return nil, &obsdk.PaymentRejectedError{Reason: "rejected", Payment: pay, Err: fmt.Errorf("KBC rejected the payment on creation")}
	}
	if pf.SCAURL == "" {
		return nil, &obsdk.FlowError{Payment: pay, Err: fmt.Errorf("kbc: payment response has no scaRedirect link")}
	}
	st := &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: pf.SCAURL}, Payment: pay,
		Message: "Send the user to KBC to sign the payment, then call Resume when they come back."}
	if st.State, err = flowstate.Encode(pf); err != nil {
		return nil, err
	}
	return st, nil
}

// resumePayment reads the status once the user is back from KBC.
func (c *client) resumePayment(ctx context.Context, pf *payFlow, in obsdk.StepInput) (*obsdk.Step, error) {
	if in.Callback != "" {
		if p, err := callback.Parse(in.Callback); err == nil {
			if code, desc, failed := p.Error(); failed {
				pay, _ := c.toPayment(pf, "", nil)
				return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("payment was not signed (%s: %s)", code, desc)}
			}
		}
	}
	pay, err := c.readStatus(ctx, pf, &pf.PSU)
	if err != nil {
		return nil, err
	}
	switch pay.Status {
	case obsdk.PaymentReceived, obsdk.PaymentCancelled:
		// RCVD: back without signing. CANC: the user cancelled on KBC's page.
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("payment was not signed (status %s)", pay.BankStatus)}
	case obsdk.PaymentRejected:
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: strings.ToLower(pay.BankStatus), Payment: pay}}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}

// ---- status ----

func (c *client) readStatus(ctx context.Context, pf *payFlow, psu *obsdk.PSUContext) (*obsdk.Payment, error) {
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: "/payments/" + pf.Product + "/" + url.PathEscape(pf.ID) + "/status",
		header: psuHeaders(psu)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.paymentErr(opPayStatus, res)
	}
	var sr struct {
		TransactionStatus string `json:"transactionStatus"`
	}
	if err := json.Unmarshal(res.body, &sr); err != nil || sr.TransactionStatus == "" {
		return nil, fmt.Errorf("kbc: unreadable payment status (HTTP %d)", res.status)
	}
	return c.toPayment(pf, sr.TransactionStatus, res.body)
}

func (c *client) toPayment(pf *payFlow, code string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: c.integrationID(), Product: pf.Product, ID: pf.ID, Type: pf.Type})
	if err != nil {
		return nil, err
	}
	st, final := bgstatus.Payment(code)
	return &obsdk.Payment{ID: pf.ID, Type: pf.Type, Status: st, BankStatus: code, Final: final, Ref: ref, Raw: raw}, nil
}

func (c *client) decodeRef(ref string) (*payFlow, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != c.integrationID() || r.ID == "" ||
		(r.Product != productSEPA && r.Product != productInstant && r.Product != productCross) {
		return nil, fmt.Errorf("%w: not a %s payment reference", obsdk.ErrInvalidRequest, c.brand.name)
	}
	return &payFlow{Type: r.Type, Product: r.Product, ID: r.ID}, nil
}

// PaymentStatus reads a payment's status; no session is needed.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	pf, err := c.decodeRef(ref)
	if err != nil {
		return nil, err
	}
	pay, err := c.readStatus(ctx, pf, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: pay.Raw}, nil
}

// CancelPayment is not offered: KBC's API has no payment cancellation.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	return nil, fmt.Errorf("%w: KBC's API cannot cancel payments", obsdk.ErrUnsupported)
}

// paymentErr maps a failed payment call. A creation refused with
// PAYMENT_FAILED, or with transactionStatus RJCT for a reason other than a
// malformed request or certificate, becomes a PaymentRejectedError.
func (c *client) paymentErr(op string, r *resp) error {
	err := c.apiErr(op, r)
	code, _ := parseError(r.body)
	var body struct {
		TransactionStatus string `json:"transactionStatus"`
	}
	_ = json.Unmarshal(r.body, &body)
	if op == opPayment && (code == "PAYMENT_FAILED" || body.TransactionStatus == "RJCT" && !requestFault(code)) {
		return &obsdk.PaymentRejectedError{Reason: strings.ToLower(code), Err: err}
	}
	return err
}

// requestFault reports Berlin Group codes that blame the request, not the payment.
func requestFault(code string) bool {
	switch code {
	case "", "FORMAT_ERROR", "PARAMETER_NOT_CONSISTENT", "PARAMETER_NOT_SUPPORTED", "SERVICE_INVALID", "RESOURCE_UNKNOWN",
		"PRODUCT_INVALID", "PRODUCT_UNKNOWN":
		return true
	}
	return strings.HasPrefix(code, "CERTIFICATE_") || strings.HasPrefix(code, "TOKEN_")
}
