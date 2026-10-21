package abnamro

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/bgstatus"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation (v2): the payment is registered with a client-credentials
// token, the user approves it on the consent page (OAuth authorization code
// with transactionId = the payment id), and the code's token executes it
// (PUT). That token, and only that token, reads the status and cancels a
// future-dated payment, for 30 days through its refresh token. So the
// approval's StepDone returns it as a session of its own (consent kind
// "pis"), which PaymentStatus and CancelPayment take back.

const (
	phPayRedirect = "payment_redirect_wait"

	// paymentKind names a payment's token in Session.Consents.
	paymentKind = "pis"

	pisBase = "/payment/v2/"

	productSEPA  = "sepa-credit-transfers"
	productCross = "cross-border-credit-transfers"

	// ReferenceCurrence is the Dutch payment reference (betalingskenmerk, as
	// on an acceptgiro), issued under Currence's scheme. ABN AMRO also accepts
	// ISO 11649 (obsdk.ReferenceRF) and Belgian structured communications
	// (obsdk.ReferenceBE).
	ReferenceCurrence = "CUR"
	// Deprecated: use obsdk.ReferenceBE.
	ReferenceBelgian = obsdk.ReferenceBE
)

// payFlow is the serialized state of a payment waiting for the user's approval.
type payFlow struct {
	Phase       string            `json:"phase"`
	Type        obsdk.PaymentType `json:"type"`
	Product     string            `json:"product"`
	ID          string            `json:"id"`
	AuthURL     string            `json:"auth_url"`
	RedirectURL string            `json:"redirect_url"`
	OAuthState  string            `json:"oauth_state"`
}

// paymentRef is what Payment.Ref holds. It carries no tokens: those are in
// the payment's session.
type paymentRef struct {
	Integration string            `json:"i"`
	Product     string            `json:"p"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
}

// ---- specs ----

// textPattern is ABN AMRO's character set for names, remittance and address
// parts (the SEPA set plus Latin-1 letters).
const textPattern = "^[0-9A-Za-z !&'()+\\-./:?_`,àÀáÁâÂãÃäÄåÅæÆçÇèÈéÉêÊëËìÌíÍîÎïÏðÐñÑòÒóÓôÔõÕöÖ×øØùÙúÚûÛüÜýÝþÞßÿ]+$"

const bicPattern = `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`

func paymentSpecs() []obsdk.PaymentSpec {
	common := func(schemes ...string) []obsdk.PaymentField {
		return []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,12}(\.\d{1,2})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeIBAN}, MaxLength: 34, Label: "Pay from",
				Note: "Leave empty to let the user pick the account on ABN AMRO's page; when set, the user cannot change it."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: schemes, MaxLength: 34, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Pattern: textPattern, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Pattern: textPattern, Label: "Description"},
			{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
				Note: "A future date makes a scheduled payment, which can be cancelled until it is executed."},
		}
	}
	base := obsdk.PaymentSpec{
		Countries: []obsdk.Country{"NL"}, MaxTransfers: 1, AuthApproaches: []string{"redirect"}, Cancellable: true,
		StatusNeedsSession: true, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
	}

	sepa := base
	sepa.Type, sepa.Currencies = obsdk.PaymentSEPA, []string{"EUR"}
	sepa.Fields = append(common(obsdk.SchemeIBAN),
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, MaxLength: 35, Pattern: textPattern, Label: "Payment reference",
			Schemes: []string{obsdk.ReferenceRF, ReferenceCurrence, obsdk.ReferenceBE},
			Note:    "Either a description or a payment reference, not both. CUR is the Dutch betalingskenmerk."},
	)
	sepa.Notes = []string{"There is no duplicate check: a payment posted twice is registered twice."}

	cross := base
	cross.Type = obsdk.PaymentCrossBorder
	cross.Fields = append(common(obsdk.SchemeIBAN, obsdk.SchemeBBAN),
		obsdk.PaymentField{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldRequired, Pattern: bicPattern, Label: "Payee bank BIC"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address",
			Note: "Structured only (street up to 70 characters, building number and post code up to 16, town up to 35); free address lines are not accepted."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
		obsdk.PaymentField{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldOptional, Options: []obsdk.Option{
			{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees"},
			{Value: obsdk.ChargeBearerCreditor, Label: "Payee pays all fees"},
			{Value: obsdk.ChargeBearerShared, Label: "Each pays their own bank"},
		}},
	)
	cross.Notes = []string{
		"A payment in another currency than EUR, or in EUR outside the euro zone.",
		"The user can approve it with an e.dentifier only, not in the mobile app.",
	}
	return []obsdk.PaymentSpec{sepa, cross}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: ABN AMRO offers no %q payments", obsdk.ErrUnsupported, t)
}

// ---- request body ----

type pisAccount struct {
	IBAN     string `json:"iban,omitempty"`
	BBAN     string `json:"bban,omitempty"`
	Currency string `json:"currency,omitempty"`
}

type pisAmount struct {
	Currency string      `json:"currency"`
	Amount   json.Number `json:"amount"` // a JSON number, written exactly as given
}

type pisAddress struct {
	StreetName     string `json:"streetName,omitempty"`
	BuildingNumber string `json:"buildingNumber,omitempty"`
	PostCode       string `json:"postCode,omitempty"`
	TownName       string `json:"townName,omitempty"`
	Country        string `json:"country,omitempty"`
}

type pisStructured struct {
	Issuer    string `json:"issuer"`
	Reference string `json:"reference"`
}

// pisBody is the SEPA and cross-border credit transfer, in the field order
// of ABN AMRO's examples. ABN AMRO takes no end-to-end id.
type pisBody struct {
	DebtorAccount          *pisAccount    `json:"debtorAccount,omitempty"`
	CreditorAccount        pisAccount     `json:"creditorAccount"`
	CreditorAgent          string         `json:"creditorAgent,omitempty"`
	CreditorName           string         `json:"creditorName"`
	CreditorAddress        *pisAddress    `json:"creditorAddress,omitempty"`
	InstructedAmount       pisAmount      `json:"instructedAmount"`
	ChargeBearer           string         `json:"chargeBearer,omitempty"`
	RequestedExecutionDate string         `json:"requestedExecutionDate,omitempty"`
	Unstructured           string         `json:"remittanceInformationUnstructured,omitempty"`
	Structured             *pisStructured `json:"remittanceInformationStructured,omitempty"`
}

func productOf(t obsdk.PaymentType) string {
	if t == obsdk.PaymentCrossBorder {
		return productCross
	}
	return productSEPA
}

// scopeOf names a product's OAuth scopes ("sepa" or "xborder").
func scopeOf(product string) string {
	if product == productCross {
		return "psd2:payment:xborder"
	}
	return "psd2:payment:sepa"
}

func invalid(path, msg string) error {
	return &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: path, Index: 0, Code: obsdk.IssueInvalid, Message: msg}}}
}

func buildBody(r obsdk.PaymentRequest) (pisBody, error) {
	t := r.Transfers[0]
	b := pisBody{
		CreditorName:           t.Creditor.Name,
		InstructedAmount:       pisAmount{Currency: t.Amount.Currency, Amount: json.Number(t.Amount.Amount)},
		ChargeBearer:           r.ChargeBearer,
		RequestedExecutionDate: r.ExecutionDate,
	}
	if d := r.Debtor; d != nil && d.Account != nil && d.Account.Value != "" {
		b.DebtorAccount = &pisAccount{IBAN: d.Account.Value}
	}
	if t.Creditor.Account.Scheme == obsdk.SchemeBBAN {
		b.CreditorAccount.BBAN = t.Creditor.Account.Value
	} else {
		b.CreditorAccount.IBAN = t.Creditor.Account.Value
	}
	if r.Type == obsdk.PaymentCrossBorder {
		b.CreditorAccount.Currency = t.Amount.Currency
		if ag := t.Creditor.Agent; ag != nil {
			b.CreditorAgent = ag.BIC
		}
	}
	if a := t.Creditor.Address; a != nil {
		if len(a.Lines) > 0 {
			return b, invalid(obsdk.FieldCreditorAddress, "ABN AMRO needs a structured address, without free lines")
		}
		b.CreditorAddress = &pisAddress{StreetName: a.Street, BuildingNumber: a.BuildingNumber, PostCode: a.PostCode, TownName: a.Town, Country: a.Country}
	}
	if len(t.Remittance) > 0 {
		b.Unstructured = t.Remittance[0]
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		if b.Unstructured != "" {
			return b, invalid(obsdk.FieldReference, "ABN AMRO accepts a description or a payment reference, not both")
		}
		issuer := ref.Scheme
		switch issuer {
		case obsdk.ReferenceRF:
			issuer = "ISO"
		case obsdk.ReferenceBE:
			issuer = "BBA"
		}
		b.Structured = &pisStructured{Issuer: issuer, Reference: ref.Value}
	}
	return b, nil
}

// ---- initiate ----

type pisResponse struct {
	PaymentID     string `json:"paymentId"`
	PaymentStatus string `json:"paymentStatus"`
	DebtorName    string `json:"debtorName"`
	DebtorAccount struct {
		IBAN string `json:"iban"`
	} `json:"debtorAccount"`
	StatusDetails struct {
		StatusISORsn  string `json:"statusISORsn"`
		WithRecipient string `json:"withRecipient"`
	} `json:"statusDetails"`
}

// InitiatePayment registers the payment and returns the redirect to ABN
// AMRO's consent page.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: ABN AMRO only supports the redirect method", obsdk.ErrInvalidRequest)
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
	tr, tres, err := c.tokenCall(ctx, opPayToken, url.Values{"grant_type": {"client_credentials"}, "scope": {scopeOf(product) + ":write"}})
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, c.apiErr(opPayToken, tres)
	}
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: pisBase + product, body: body, bearer: tr.AccessToken})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opPayment, res)
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil || pr.PaymentID == "" {
		return nil, fmt.Errorf("abnamro: unreadable payment response (HTTP %d)", res.status)
	}
	pf := &payFlow{Phase: phPayRedirect, Type: r.Type, Product: product, ID: pr.PaymentID, RedirectURL: redirectURL, OAuthState: c.newState()}
	pf.AuthURL = c.authorizeURL([]string{scopeOf(product) + ":write", scopeOf(product) + ":read"}, redirectURL, pf.OAuthState, pf.ID)
	pay, err := c.toPayment(pf.Type, pf.Product, pf.ID, &pr, res.body)
	if err != nil {
		return nil, err
	}
	return c.pausePayment(pf, pay)
}

func (c *client) pausePayment(pf *payFlow, pay *obsdk.Payment) (*obsdk.Step, error) {
	st := &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: pf.AuthURL}, Payment: pay,
		Message: "Send the user to ABN AMRO to approve the payment, then pass the callback URL to Resume."}
	s, err := flowstate.Encode(pf)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// resumePayment exchanges the approval's code and executes the payment.
func (c *client) resumePayment(ctx context.Context, pf *payFlow, in obsdk.StepInput) (*obsdk.Step, error) {
	pay, err := c.toPayment(pf.Type, pf.Product, pf.ID, nil, nil)
	if err != nil {
		return nil, err
	}
	if in.Callback == "" {
		return c.pausePayment(pf, pay)
	}
	code, err := codeFromCallback(in.Callback, pf.OAuthState, "payment was not approved")
	if err != nil {
		return nil, &obsdk.FlowError{Payment: pay, Err: err}
	}
	tr, r, err := c.tokenCall(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {pf.RedirectURL}})
	if err != nil {
		return nil, &obsdk.FlowError{Payment: pay, Err: err}
	}
	if tr == nil {
		return nil, &obsdk.FlowError{Payment: pay, Err: fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))}
	}
	s := c.newSession()
	s.Consents[paymentKind] = obsdk.Consent{ID: pf.ID, Kind: paymentKind, Status: "valid"}
	c.applyToken(s, tr)

	res, err := c.do(ctx, req{op: opPayExecute, method: http.MethodPut, path: c.paymentPath(pf.Product, pf.ID), bearer: s.AccessToken})
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Payment: pay, Err: err}
	}
	if res.status != http.StatusOK {
		return nil, &obsdk.FlowError{Session: s.Clone(), Payment: pay, Err: c.apiErr(opPayExecute, res)}
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Payment: pay, Err: fmt.Errorf("abnamro: unreadable payment execution response: %w", err)}
	}
	if pay, err = c.toPayment(pf.Type, pf.Product, pf.ID, &pr, res.body); err != nil {
		return nil, err
	}
	if pay.Status == obsdk.PaymentRejected {
		return nil, &obsdk.FlowError{Session: s, Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: pay.Reason, Payment: pay}}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Payment: pay, Raw: res.body}, nil
}

func (c *client) paymentPath(product, id string) string {
	return pisBase + product + "/" + url.PathEscape(id)
}

// ---- status and cancel ----

// paymentStatus maps ABN AMRO's ISO 20022 codes. RTRN (returned by the
// payee's bank) is final and not a success.
func paymentStatus(code string) (obsdk.PaymentStatus, bool) {
	if code == "RTRN" {
		return obsdk.PaymentRejected, true
	}
	return bgstatus.Payment(code)
}

func (c *client) toPayment(t obsdk.PaymentType, product, id string, pr *pisResponse, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, Product: product, ID: id, Type: t})
	if err != nil {
		return nil, err
	}
	pay := &obsdk.Payment{ID: id, Type: t, Status: obsdk.PaymentReceived, Ref: ref, Raw: raw}
	if pr != nil {
		pay.BankStatus = pr.PaymentStatus
		pay.Status, pay.Final = paymentStatus(pr.PaymentStatus)
		pay.Reason = pr.StatusDetails.StatusISORsn
		if pr.DebtorAccount.IBAN != "" {
			pay.Debtor = &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: pr.DebtorAccount.IBAN}
		}
	}
	return pay, nil
}

func decodeRef(ref string) (*paymentRef, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.ID == "" ||
		(r.Product != productSEPA && r.Product != productCross) {
		return nil, fmt.Errorf("%w: not an ABN AMRO payment reference", obsdk.ErrInvalidRequest)
	}
	return &r, nil
}

// paymentSession checks that s is the session the payment's approval
// returned, refreshing its token when it has expired. The second result is
// the refreshed session, nil when unchanged.
func (c *client) paymentSession(ctx context.Context, s *obsdk.Session, id string) (*obsdk.Session, *obsdk.Session, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("%w: ABN AMRO reads a payment only with the session its approval returned (PaymentCallOptions.Session)", obsdk.ErrInvalidRequest)
	}
	if err := c.checkSession(s); err != nil {
		return nil, nil, err
	}
	if cons, ok := s.Consents[paymentKind]; !ok || cons.ID != id {
		return nil, nil, fmt.Errorf("%w: the session is not the one payment %s returned", obsdk.ErrInvalidRequest, id)
	}
	if !s.AccessExpired(c.now()) {
		return s, nil, nil
	}
	ns, err := c.refresh(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	return ns, ns, nil
}

// PaymentStatus reads a payment's status with the session its approval
// returned (o.Session). When the token had to be refreshed, Result.Session
// carries the new session: store it.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	r, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	s, changed, err := c.paymentSession(ctx, o.Session, r.ID)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: c.paymentPath(r.Product, r.ID) + "/status", bearer: s.AccessToken})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.apiErr(opPayStatus, res)
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil || pr.PaymentStatus == "" {
		return nil, fmt.Errorf("abnamro: unreadable payment status (HTTP %d)", res.status)
	}
	pay, err := c.toPayment(r.Type, r.Product, r.ID, &pr, res.body)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: res.body, Session: changed}, nil
}

// CancelPayment deletes a future-dated payment with the session its approval
// returned. ABN AMRO cancels at once (204); no approval is needed.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	r, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	s, changed, err := c.paymentSession(ctx, o.Session, r.ID)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodDelete, path: c.paymentPath(r.Product, r.ID), bearer: s.AccessToken})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusNoContent && res.status != http.StatusOK {
		return nil, c.apiErr(opPayCancel, res)
	}
	pay, err := c.toPayment(r.Type, r.Product, r.ID, &pisResponse{PaymentStatus: "CANC"}, nil)
	if err != nil {
		return nil, err
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Session: changed}, nil
}
