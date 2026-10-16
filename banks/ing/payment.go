package ing

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

// Payment initiation (PIS v2): the payment is created with the application
// token, the user approves it on ING's page (scaRedirect) and comes back to
// TPP-Redirect-URI, and its status is read with the application token. No
// customer token is involved.

const phPayRedirect = "payment_redirect_wait"

// Payment products in ING's paths.
const (
	productSEPA     = "sepa-credit-transfers"
	productCross    = "cross-border-credit-transfers"
	productDomestic = "domestic-credit-transfers"
)

// payFlow is the serialized state of a payment waiting for the user's approval.
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

// ingText is the character set ING accepts in names, remittance and ids.
const ingText = `^[a-zA-Z0-9?:()./,'+ -]+$`

// Countries per payment type, for consumers and SMEs (ING's "Which countries
// are available" and "Which countries support Instant Payments" tables).
var (
	sepaCountries     = []obsdk.Country{"BE", "DE", "ES", "IT", "LU", "NL", "RO"}
	instantCountries  = []obsdk.Country{"BE", "DE", "ES", "IT", "LU", "NL"}
	crossCountries    = []obsdk.Country{"BE", "DE", "ES", "LU", "NL", "RO"}
	domesticCountries = []obsdk.Country{"RO"}
)

func paymentSpecs() []obsdk.PaymentSpec {
	common := func(schemes ...string) []obsdk.PaymentField {
		return []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,13}(\.\d{1,2})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeIBAN}, Label: "Pay from",
				Note: "Leave empty to let the user pick the account on ING's page."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: schemes, MaxLength: 34, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Pattern: ingText, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Pattern: ingText, Label: "Description"},
			{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}, MaxLength: 35, Label: "Payment reference",
				Note: "Structured creditor reference (SCOR)."},
			{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35, Pattern: ingText},
			{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address",
				Note: "Structured only: ING needs the town and country when an address is given; free address lines are not accepted."},
			{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
		}
	}
	base := obsdk.PaymentSpec{
		MaxTransfers: 1, AuthApproaches: []string{"redirect"}, Cancellable: true,
		FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
	}
	withDate := func(fs []obsdk.PaymentField) []obsdk.PaymentField {
		return append(fs, obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
			Note: "A future date makes a scheduled payment, which can be cancelled until it is executed."})
	}

	sepa := base
	sepa.Type, sepa.Countries, sepa.Currencies = obsdk.PaymentSEPA, sepaCountries, []string{"EUR"}
	sepa.Fields = withDate(common(obsdk.SchemeIBAN))

	inst := base
	inst.Type, inst.Countries, inst.Currencies = obsdk.PaymentSEPAInstant, instantCountries, []string{"EUR"}
	inst.Fields = common(obsdk.SchemeIBAN)
	inst.Cancellable = false
	inst.Notes = []string{"Sent as a SEPA credit transfer with localInstrumentCode INST; ING executes it right after the user's approval."}

	dom := base
	dom.Type, dom.Countries, dom.Currencies = obsdk.PaymentDomestic, domesticCountries, []string{"RON"}
	dom.Fields = withDate(common(obsdk.SchemeIBAN))
	dom.Notes = []string{"Romanian lei transfer. Since 1 September 2026 ING processes these instantly only on request (localInstrumentCode INST), which the SDK does not send."}

	cross := base
	cross.Type, cross.Countries = obsdk.PaymentCrossBorder, crossCountries
	cross.Fields = append(withDate(common(obsdk.SchemeIBAN, obsdk.SchemeBBAN)),
		obsdk.PaymentField{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`, Label: "Payee bank BIC",
			Note: "Needed when the payee account is not an IBAN."},
		obsdk.PaymentField{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldOptional, Options: []obsdk.Option{
			{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees"},
			{Value: obsdk.ChargeBearerCreditor, Label: "Payee pays all fees"},
			{Value: obsdk.ChargeBearerShared, Label: "Each pays their own bank"},
		}},
	)
	cross.Notes = []string{"International transfer: in EUR outside SEPA, or in another currency."}
	return []obsdk.PaymentSpec{sepa, inst, dom, cross}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: ING offers no %q payments in %s", obsdk.ErrUnsupported, t, c.target.Country)
}

// ---- request body ----

type pisAmount struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

type pisAccount struct {
	IBAN string `json:"iban,omitempty"`
	BBAN string `json:"bban,omitempty"`
}

type pisAddress struct {
	StreetName     string `json:"streetName,omitempty"`
	BuildingNumber string `json:"buildingNumber,omitempty"`
	PostCode       string `json:"postCode,omitempty"`
	TownName       string `json:"townName"`
	Country        string `json:"country"`
}

type pisStructured struct {
	Reference string `json:"reference"`
	Type      struct {
		CodeOrProprietary struct {
			Code string `json:"code"`
		} `json:"codeOrProprietary"`
	} `json:"type"`
}

// pisInstruction is ING's PaymentInstructionV2. Only fields the caller set
// are sent: the sandbox matches bodies exactly.
type pisInstruction struct {
	EndToEndIdentification string         `json:"endToEndIdentification,omitempty"`
	DebtorAccount          *pisAccount    `json:"debtorAccount,omitempty"`
	InstructedAmount       pisAmount      `json:"instructedAmount"`
	CreditorAccount        pisAccount     `json:"creditorAccount"`
	CreditorAgent          string         `json:"creditorAgent,omitempty"`
	CreditorName           string         `json:"creditorName"`
	CreditorAddress        *pisAddress    `json:"creditorAddress,omitempty"`
	ChargeBearer           string         `json:"chargeBearer,omitempty"`
	Unstructured           string         `json:"remittanceInformationUnstructured,omitempty"`
	Structured             *pisStructured `json:"remittanceInformationStructured,omitempty"`
	LocalInstrumentCode    string         `json:"localInstrumentCode,omitempty"`
	RequestedExecutionDate string         `json:"requestedExecutionDate,omitempty"`
}

func productOf(t obsdk.PaymentType) string {
	switch t {
	case obsdk.PaymentCrossBorder:
		return productCross
	case obsdk.PaymentDomestic:
		return productDomestic
	}
	return productSEPA
}

func buildInstruction(r obsdk.PaymentRequest) (pisInstruction, error) {
	t := r.Transfers[0]
	in := pisInstruction{
		EndToEndIdentification: t.EndToEndID,
		InstructedAmount:       pisAmount{Amount: string(t.Amount.Amount), Currency: t.Amount.Currency},
		CreditorName:           t.Creditor.Name,
		ChargeBearer:           r.ChargeBearer,
		RequestedExecutionDate: r.ExecutionDate,
	}
	if r.Type == obsdk.PaymentSEPAInstant {
		in.LocalInstrumentCode = "INST"
	}
	if d := r.Debtor; d != nil && d.Account != nil && d.Account.Value != "" {
		in.DebtorAccount = &pisAccount{IBAN: d.Account.Value}
	}
	switch t.Creditor.Account.Scheme {
	case obsdk.SchemeBBAN:
		in.CreditorAccount.BBAN = t.Creditor.Account.Value
	default:
		in.CreditorAccount.IBAN = t.Creditor.Account.Value
	}
	if ag := t.Creditor.Agent; ag != nil {
		in.CreditorAgent = ag.BIC
	}
	if a := t.Creditor.Address; a != nil {
		if len(a.Lines) > 0 || a.Town == "" || a.Country == "" {
			return in, &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: obsdk.FieldCreditorAddress, Index: 0, Code: obsdk.IssueInvalid,
				Message: "ING needs a structured address with town and country, without free lines"}}}
		}
		in.CreditorAddress = &pisAddress{StreetName: a.Street, BuildingNumber: a.BuildingNumber, PostCode: a.PostCode, TownName: a.Town, Country: a.Country}
	}
	if len(t.Remittance) > 0 {
		in.Unstructured = t.Remittance[0]
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		in.Structured = &pisStructured{Reference: ref.Value}
		in.Structured.Type.CodeOrProprietary.Code = "SCOR"
	}
	return in, nil
}

// ---- initiate ----

type pisResponse struct {
	TransactionStatus string `json:"transactionStatus"`
	PaymentID         string `json:"paymentId"`
	Links             struct {
		SCARedirect json.RawMessage `json:"scaRedirect"`
	} `json:"_links"`
}

// href reads a link given either as a string or as {"href": "..."}.
func href(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var l linkJSON
	_ = json.Unmarshal(raw, &l)
	return l.Href
}

// InitiatePayment creates the payment and returns the redirect to ING's
// approval page.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: ING only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	if r.PSU.IP == "" {
		return nil, fmt.Errorf("%w: ING requires the user's IP address (PaymentRequest.PSU.IP)", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or PaymentRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	in, err := buildInstruction(r)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	app, err := c.applicationToken(ctx)
	if err != nil {
		return nil, err
	}
	product := productOf(r.Type)
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: "/v2/payments/" + product, body: body, bearer: app, signed: true,
		header: map[string]string{"TPP-Redirect-URI": redirectURL, "PSU-IP-Address": r.PSU.IP}})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.paymentErr(opPayment, res, nil)
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil || pr.PaymentID == "" {
		return nil, fmt.Errorf("ing: unreadable payment response (HTTP %d)", res.status)
	}
	pf := &payFlow{Phase: phPayRedirect, Type: r.Type, Product: product, ID: pr.PaymentID, SCAURL: href(pr.Links.SCARedirect), PSU: r.PSU}
	pay, err := c.toPayment(pf, pr.TransactionStatus, "", res.body)
	if err != nil {
		return nil, err
	}
	if pay.Status == obsdk.PaymentRejected {
		return nil, &obsdk.PaymentRejectedError{Reason: "rejected", Payment: pay, Err: fmt.Errorf("ING rejected the payment on creation")}
	}
	if pf.SCAURL == "" {
		return nil, fmt.Errorf("ing: payment response has no scaRedirect link")
	}
	return c.pausePayment(pf, pay)
}

func (c *client) pausePayment(pf *payFlow, pay *obsdk.Payment) (*obsdk.Step, error) {
	st := &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: pf.SCAURL}, Payment: pay,
		Message: "Send the user to ING to approve the payment, then call Resume when they come back."}
	s, err := flowstate.Encode(pf)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// resumePayment reads the payment's status once the user is back from ING.
func (c *client) resumePayment(ctx context.Context, pf *payFlow, in obsdk.StepInput) (*obsdk.Step, error) {
	// ING returns the user to TPP-Redirect-URI as is; a callback is only read
	// for an error the user's browser may carry.
	if in.Callback != "" {
		if p, err := callback.Parse(in.Callback); err == nil {
			if code, desc, failed := p.Error(); failed {
				pay, _ := c.toPayment(pf, "RCVD", "", nil)
				return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("payment was not approved (%s: %s)", code, desc)}
			}
		}
	}
	pay, err := c.readStatus(ctx, pf, &pf.PSU)
	if err != nil {
		return nil, err
	}
	switch pay.Status {
	case obsdk.PaymentReceived:
		// The user came back without approving (or aborted at ING).
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("payment was not approved (status %s)", pay.BankStatus)}
	case obsdk.PaymentRejected:
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: rejectReason(pay), Payment: pay}}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}

func rejectReason(p *obsdk.Payment) string {
	if p.Reason != "" {
		return p.Reason
	}
	return "rejected"
}

// ---- status and cancel ----

type statusResponse struct {
	TransactionStatus string `json:"transactionStatus"`
	StsRsnInf         []struct {
		Rsn struct {
			Cd    string `json:"cd"`
			Prtry string `json:"prtry"`
		} `json:"rsn"`
		AddtlInf []string `json:"addtlInf"`
	} `json:"stsRsnInf"`
}

func (c *client) readStatus(ctx context.Context, pf *payFlow, psu *obsdk.PSUContext) (*obsdk.Payment, error) {
	app, err := c.applicationToken(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: "/v2/payments/" + pf.Product + "/" + url.PathEscape(pf.ID) + "/status",
		bearer: app, header: psuHeader(psu)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.paymentErr(opPayStatus, res, nil)
	}
	var sr statusResponse
	if err := json.Unmarshal(res.body, &sr); err != nil || sr.TransactionStatus == "" {
		return nil, fmt.Errorf("ing: unreadable payment status (HTTP %d)", res.status)
	}
	var reason string
	if len(sr.StsRsnInf) > 0 {
		reason = sr.StsRsnInf[0].Rsn.Cd
		if reason == "" {
			reason = sr.StsRsnInf[0].Rsn.Prtry
		}
	}
	return c.toPayment(pf, sr.TransactionStatus, reason, res.body)
}

func psuHeader(p *obsdk.PSUContext) map[string]string {
	if p == nil || p.IP == "" {
		return nil
	}
	return map[string]string{"PSU-IP-Address": p.IP}
}

// paymentStatus maps ING's ISO 20022 codes. ING uses ACTC for "the user
// logged in but has not authorised yet", so it counts as received here.
func paymentStatus(code string) (obsdk.PaymentStatus, bool) {
	if code == "ACTC" {
		return obsdk.PaymentReceived, false
	}
	return bgstatus.Payment(code)
}

func (c *client) toPayment(pf *payFlow, code, reason string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, Product: pf.Product, ID: pf.ID, Type: pf.Type})
	if err != nil {
		return nil, err
	}
	st, final := paymentStatus(code)
	return &obsdk.Payment{ID: pf.ID, Type: pf.Type, Status: st, BankStatus: code, Final: final, Reason: reason, Ref: ref, Raw: raw}, nil
}

func decodeRef(ref string) (*payFlow, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.ID == "" {
		return nil, fmt.Errorf("%w: not an ING payment reference", obsdk.ErrInvalidRequest)
	}
	switch r.Product {
	case productSEPA, productCross, productDomestic:
	default:
		return nil, fmt.Errorf("%w: not an ING payment reference", obsdk.ErrInvalidRequest)
	}
	return &payFlow{Type: r.Type, Product: r.Product, ID: r.ID}, nil
}

// PaymentStatus reads a payment's status with the application token.
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

// CancelPayment deletes a payment that has not been executed yet (in
// practice a future-dated one). ING needs no approval from the user for it.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	pf, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	app, err := c.applicationToken(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodDelete, path: "/v2/payments/" + pf.Product + "/" + url.PathEscape(pf.ID),
		bearer: app, header: psuHeader(o.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusNoContent && res.status != http.StatusOK {
		return nil, c.paymentErr(opPayCancel, res, nil)
	}
	pay, err := c.readStatus(ctx, pf, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}

// paymentErr maps a failed payment call. A 4xx on creation that names the
// payment as rejected becomes a PaymentRejectedError; the rest are APIErrors.
func (c *client) paymentErr(op string, r *resp, pay *obsdk.Payment) error {
	err := c.apiErr(op, r)
	var body struct {
		TransactionStatus string `json:"transactionStatus"`
	}
	_ = json.Unmarshal(r.body, &body)
	if op == opPayment && body.TransactionStatus == "RJCT" {
		code, _ := parseError(r.body)
		return &obsdk.PaymentRejectedError{Reason: strings.ToLower(code), Payment: pay, Err: err}
	}
	return err
}
