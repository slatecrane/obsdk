package berlingroup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/bgstatus"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Single payments: POST /v1/payments/{product}, approved through the same
// authorisation flow as consents, read with .../status and cancelled with
// DELETE (which the bank may want approved too).

// payState identifies a payment inside a flow.
type payState struct {
	Type    obsdk.PaymentType `json:"type"`
	Product string            `json:"product"`
	ID      string            `json:"id,omitempty"`
}

// paymentRef is what Payment.Ref holds: enough to read or cancel the payment.
type paymentRef struct {
	Integration string            `json:"i"`
	Product     string            `json:"p"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
	Institution string            `json:"b,omitempty"`
}

// ---- request body ----

type pisAccount struct {
	IBAN     string `json:"iban,omitempty"`
	BBAN     string `json:"bban,omitempty"`
	Currency string `json:"currency,omitempty"`
}

func pisAccountOf(id obsdk.Identifier, currency string) pisAccount {
	if id.Scheme == obsdk.SchemeBBAN {
		return pisAccount{BBAN: id.Value, Currency: currency}
	}
	return pisAccount{IBAN: id.Value, Currency: currency}
}

// pisBody is the standard's JSON single payment. Address and structured
// remittance each have two shapes: before and from version 1.3.8.
type pisBody struct {
	EndToEndIdentification string      `json:"endToEndIdentification,omitempty"`
	InstructionID          string      `json:"instructionIdentification,omitempty"`
	DebtorAccount          *pisAccount `json:"debtorAccount,omitempty"`
	DebtorName             string      `json:"debtorName,omitempty"`
	InstructedAmount       amountJSON  `json:"instructedAmount"`
	CreditorAccount        pisAccount  `json:"creditorAccount"`
	CreditorAgent          string      `json:"creditorAgent,omitempty"`
	CreditorName           string      `json:"creditorName,omitempty"`
	CreditorAddress        any         `json:"creditorAddress,omitempty"`
	ChargeBearer           string      `json:"chargeBearer,omitempty"`
	Unstructured           string      `json:"remittanceInformationUnstructured,omitempty"`
	Structured             any         `json:"remittanceInformationStructured,omitempty"`
	RequestedExecutionDate string      `json:"requestedExecutionDate,omitempty"`
}

type address138 struct {
	StreetName     string   `json:"streetName,omitempty"`
	BuildingNumber string   `json:"buildingNumber,omitempty"`
	TownName       string   `json:"townName,omitempty"`
	PostCode       string   `json:"postCode,omitempty"`
	Country        string   `json:"country"`
	Lines          []string `json:"addressLine,omitempty"`
}

type addressLegacy struct {
	Street         string `json:"street,omitempty"`
	BuildingNumber string `json:"buildingNumber,omitempty"`
	City           string `json:"city,omitempty"`
	PostalCode     string `json:"postalCode,omitempty"`
	Country        string `json:"country"`
}

type structured138 struct {
	Reference       string `json:"reference"`
	ReferenceType   string `json:"referenceType,omitempty"`
	ReferenceIssuer string `json:"referenceIssuer,omitempty"`
}

func invalid(path, msg string) error {
	return &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: path, Index: 0, Code: obsdk.IssueInvalid, Message: msg}}}
}

func (c *client) buildBody(r obsdk.PaymentRequest) (pisBody, error) {
	t := r.Transfers[0]
	b := pisBody{
		EndToEndIdentification: t.EndToEndID,
		InstructionID:          t.InstructionID,
		InstructedAmount:       amountJSON{Currency: t.Amount.Currency, Amount: string(t.Amount.Amount)},
		CreditorAccount:        pisAccountOf(t.Creditor.Account, ""),
		CreditorName:           t.Creditor.Name,
		ChargeBearer:           r.ChargeBearer,
		RequestedExecutionDate: r.ExecutionDate,
	}
	if d := r.Debtor; d != nil {
		if d.Account != nil && d.Account.Value != "" {
			a := pisAccountOf(*d.Account, firstNonEmpty(d.Currency, t.Amount.Currency))
			b.DebtorAccount = &a
		}
		b.DebtorName = d.Name
	}
	if ag := t.Creditor.Agent; ag != nil {
		b.CreditorAgent = ag.BIC
	}
	if a := t.Creditor.Address; a != nil && (a.Country != "" || len(a.Lines) > 0 || a.Town != "") {
		if a.Country == "" {
			return b, invalid(obsdk.FieldCreditorAddress, "the payee's address needs a country")
		}
		if c.p.LegacyAddress {
			if len(a.Lines) > 0 {
				return b, invalid(obsdk.FieldCreditorAddress, c.p.Info.Name+" needs a structured address, without free lines")
			}
			b.CreditorAddress = addressLegacy{Street: a.Street, BuildingNumber: a.BuildingNumber, City: a.Town, PostalCode: a.PostCode, Country: a.Country}
		} else {
			b.CreditorAddress = address138{StreetName: a.Street, BuildingNumber: a.BuildingNumber, TownName: a.Town, PostCode: a.PostCode,
				Country: a.Country, Lines: a.Lines}
		}
	}
	if len(t.Remittance) > 0 {
		b.Unstructured = strings.Join(t.Remittance, " ")
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		if c.p.ReferenceInEndToEnd {
			if t.EndToEndID != "" && t.EndToEndID != ref.Value {
				return b, invalid(obsdk.FieldEndToEndID, c.p.Info.Name+" carries the payment reference in the end-to-end id; set only the reference")
			}
			b.EndToEndIdentification = ref.Value
			return b, nil
		}
		if c.p.StructuredRemittanceString {
			b.Structured = ref.Value
		} else {
			s := structured138{Reference: ref.Value}
			if ref.Scheme == obsdk.ReferenceRF {
				s.ReferenceType, s.ReferenceIssuer = "SCOR", "ISO"
			}
			b.Structured = s
		}
	}
	return b, nil
}

// ---- initiate ----

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.p.Info.PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: %s offers no %q payments", obsdk.ErrUnsupported, c.p.Info.Name, t)
}

// InitiatePayment validates the request, creates the payment and starts its
// authorisation.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	approach, err := c.approach(r.Method)
	if err != nil {
		return nil, err
	}
	if c, err = c.forNew(); err != nil {
		return nil, err
	}
	f := &flow{Op: flowPayment, Approach: approach, PSU: r.PSU, Language: r.Language, Institution: c.inst,
		Pay: &payState{Type: r.Type, Product: c.p.Products[r.Type]}}
	if c.p.PaymentXML {
		if f.PayXML, err = c.buildPain001(r); err != nil {
			return nil, err
		}
	} else {
		b, err := c.buildBody(r)
		if err != nil {
			return nil, err
		}
		if f.PayBody, err = json.Marshal(b); err != nil {
			return nil, err
		}
	}
	if approach == Redirect {
		if f.RedirectURL, err = c.redirectURL(r.RedirectURL); err != nil {
			return nil, err
		}
	}
	if v := strings.TrimSpace(r.Values[fieldPSUID]); v != "" {
		f.PSU.ID = v
	}
	if f.PSU.ID == "" && (c.p.PSUID == PSUIDRequired || approach == Decoupled) {
		f.Need = needPSUID
		return c.pause(f, psuIDStep())
	}
	return c.createPayment(ctx, f, obsdk.StepInput{Values: r.Values})
}

func (c *client) createPayment(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	h := psuHeaders(&f.PSU)
	c.redirectHeaders(f, h)
	r := req{op: opPayment, method: http.MethodPost, path: "/v1/payments/" + url.PathEscape(f.Pay.Product), header: h}
	if f.PayXML != nil {
		r.raw, r.contentType = f.PayXML, "application/xml"
	} else {
		r.body = f.PayBody
	}
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.paymentErr(opPayment, res)
	}
	var sr scaResponse
	if err := json.Unmarshal(res.body, &sr); err != nil || sr.PaymentID == "" {
		return nil, fmt.Errorf("berlingroup: unreadable payment response (HTTP %d)", res.status)
	}
	f.Pay.ID, f.PayBody, f.PayXML = sr.PaymentID, nil, nil
	f.StatusPath = c.paymentPath(f.Pay) + "/status"
	if sr.TransactionStatus == "RJCT" {
		pay, _ := c.paymentOf(f.Pay, sr.TransactionStatus, res.body)
		return nil, &obsdk.PaymentRejectedError{Reason: "rejected", Payment: pay, Err: fmt.Errorf("%s rejected the payment on creation", c.p.Info.Name)}
	}
	if err := f.absorb(&sr, c.p.linkVersions()...); err != nil {
		return nil, c.wrapFlowErr(f, err)
	}
	f.Need = ""
	st, err := c.advance(ctx, f, in)
	return st, c.wrapFlowErr(f, err)
}

func (c *client) paymentPath(p *payState) string {
	return "/v1/payments/" + url.PathEscape(p.Product) + "/" + url.PathEscape(p.ID)
}

// finishPayment reads the status once the authorisation is over.
func (c *client) finishPayment(ctx context.Context, f *flow) (*obsdk.Step, error) {
	pay, err := c.readStatus(ctx, f.Pay, &f.PSU)
	if err != nil {
		return nil, err
	}
	switch pay.Status {
	case obsdk.PaymentReceived:
		if f.SCAStatus != "finalised" && f.SCAStatus != "exempted" {
			return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("the payment was not approved (status %s)", pay.BankStatus)}
		}
	case obsdk.PaymentCancelled:
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("the payment was cancelled at the bank")}
	case obsdk.PaymentRejected:
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: strings.ToLower(pay.BankStatus), Payment: pay}}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}

// ---- status ----

func (c *client) readStatus(ctx context.Context, p *payState, psu *obsdk.PSUContext) (*obsdk.Payment, error) {
	r := req{op: opPayStatus, method: http.MethodGet, path: c.paymentPath(p) + "/status", header: psuHeaders(psu)}
	if c.p.PaymentXML {
		// pain.001 payments report their status as pain.002.
		r.accept = "application/xml, application/json;q=0.9"
	}
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.paymentErr(opPayStatus, res)
	}
	var sr struct {
		TransactionStatus string `json:"transactionStatus"`
		PSUMessage        string `json:"psuMessage"`
	}
	if isXML(res) {
		if sr.TransactionStatus, sr.PSUMessage, err = parsePain002(res.body); err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(res.body, &sr); err != nil || sr.TransactionStatus == "" {
		return nil, fmt.Errorf("berlingroup: unreadable payment status (HTTP %d)", res.status)
	}
	pay, err := c.paymentOf(p, sr.TransactionStatus, res.body)
	if err == nil && pay.Status == obsdk.PaymentRejected {
		// Some banks explain a rejection here (Sparkassen: "{No.} - {Text}";
		// pain.002: the status reason).
		pay.Reason = sr.PSUMessage
	}
	return pay, err
}

func (c *client) paymentOf(p *payState, code string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: c.p.ID, Product: p.Product, ID: p.ID, Type: p.Type, Institution: c.inst})
	if err != nil {
		return nil, err
	}
	st, final := bgstatus.Payment(code)
	return &obsdk.Payment{ID: p.ID, Type: p.Type, Status: st, BankStatus: code, Final: final, Ref: ref, Raw: raw}, nil
}

// decodeRef reads a payment reference and returns the client for the
// institution the payment was made at.
func (c *client) decodeRef(ref string) (*client, *payState, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != c.p.ID || r.ID == "" || r.Product == "" ||
		strings.ContainsAny(r.Product, "/?#") {
		return nil, nil, fmt.Errorf("%w: not a %s payment reference", obsdk.ErrInvalidRequest, c.p.Info.Name)
	}
	cc, err := c.forInstitution(r.Institution)
	if err != nil {
		return nil, nil, err
	}
	return cc, &payState{Type: r.Type, Product: r.Product, ID: r.ID}, nil
}

// PaymentStatus reads a payment's status; no session is needed.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	c, p, err := c.decodeRef(ref)
	if err != nil {
		return nil, err
	}
	pay, err := c.readStatus(ctx, p, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: pay.Raw}, nil
}

// ---- cancel ----

// CancelPayment deletes a payment. The bank either cancels it at once (204)
// or asks for the user's approval of the cancellation (202 with steering
// links), which then runs like a payment approval.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	c, p, err := c.decodeRef(ref)
	if err != nil {
		return nil, err
	}
	approach, err := c.approach(o.Method)
	if err != nil {
		return nil, err
	}
	f := &flow{Op: flowCancel, Approach: approach, Pay: p, StatusPath: c.paymentPath(p) + "/status", Institution: c.inst}
	if o.PSU != nil {
		f.PSU = *o.PSU
	}
	if c.p.PSUID == PSUIDRequired && f.PSU.ID == "" {
		return nil, fmt.Errorf("%w: %s needs the user's online banking login (PSU.ID) to cancel a payment", obsdk.ErrInvalidRequest, c.p.Info.Name)
	}
	if approach == Redirect {
		if f.RedirectURL, err = c.redirectURL(o.RedirectURL); err != nil {
			return nil, err
		}
	}
	h := psuHeaders(&f.PSU)
	c.redirectHeaders(f, h)
	res, err := c.do(ctx, req{op: opCancel, method: http.MethodDelete, path: c.paymentPath(p), header: h})
	if err != nil {
		return nil, err
	}
	switch res.status {
	case http.StatusNoContent:
		return c.finishCancel(ctx, f)
	case http.StatusOK, http.StatusAccepted:
	default:
		return nil, c.paymentErr(opCancel, res)
	}
	var r scaResponse
	if len(res.body) > 0 {
		if err := json.Unmarshal(res.body, &r); err != nil {
			return nil, fmt.Errorf("berlingroup: unreadable cancellation response (HTTP %d)", res.status)
		}
	}
	if r.TransactionStatus == "CANC" || len(r.Links) == 0 {
		return c.finishCancel(ctx, f)
	}
	if err := f.absorb(&r, c.p.linkVersions()...); err != nil {
		return nil, err
	}
	st, err := c.advance(ctx, f, obsdk.StepInput{})
	return st, c.wrapFlowErr(f, err)
}

func (c *client) finishCancel(ctx context.Context, f *flow) (*obsdk.Step, error) {
	pay, err := c.readStatus(ctx, f.Pay, &f.PSU)
	if err != nil {
		return nil, err
	}
	if pay.Status != obsdk.PaymentCancelled {
		return nil, &obsdk.FlowError{Payment: pay, Err: fmt.Errorf("berlingroup: %s did not cancel the payment (status %s)", c.p.Info.Name, pay.BankStatus)}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
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
	switch {
	case op == opPayment && (code == "PAYMENT_FAILED" || body.TransactionStatus == "RJCT" && !requestFault(code)):
		return &obsdk.PaymentRejectedError{Reason: strings.ToLower(firstNonEmpty(code, "rejected")), Err: err}
	case op == opCancel && code == "CANCELLATION_INVALID":
		return fmt.Errorf("%w: the payment can no longer be cancelled: %w", obsdk.ErrInvalidRequest, err)
	}
	return err
}

// requestFault reports codes that blame the request, not the payment.
func requestFault(code string) bool {
	switch code {
	case "", "FORMAT_ERROR", "PARAMETER_NOT_CONSISTENT", "PARAMETER_NOT_SUPPORTED", "SERVICE_INVALID", "RESOURCE_UNKNOWN",
		"PRODUCT_INVALID", "PRODUCT_UNKNOWN", "SERVICE_BLOCKED":
		return true
	}
	return strings.HasPrefix(code, "CERTIFICATE_") || strings.HasPrefix(code, "TOKEN_") || strings.HasPrefix(code, "SIGNATURE_")
}
