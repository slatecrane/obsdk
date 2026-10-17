package hsbc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation follows OBIE: a payment consent created with a client
// token, the user's approval on the bank's page, then the payment itself
// submitted with the user's token and the same Initiation. Offered for the
// UK brands (v4.0): single and future-dated Faster Payments in GBP.

const phPayRedirect = "payment_redirect_wait"

const (
	familyDomestic          = "domestic"
	familyDomesticScheduled = "domestic-scheduled"
)

// idField is the payment id's name in each family's responses.
var idField = map[string]string{
	familyDomestic:          "DomesticPaymentId",
	familyDomesticScheduled: "DomesticScheduledPaymentId",
}

// payFlow is the serialized state of a payment between consent and submission.
type payFlow struct {
	Type       obsdk.PaymentType `json:"type"`
	Family     string            `json:"family"`
	ConsentID  string            `json:"consent_id"`
	Initiation json.RawMessage   `json:"initiation"` // resubmitted unchanged with the payment
	Risk       json.RawMessage   `json:"risk"`
	Scheduled  bool              `json:"scheduled,omitempty"`
	SubmitKey  string            `json:"submit_key"` // idempotency key of the submission, kept for retries
}

// paymentRef is what Payment.Ref holds: enough to read the payment later.
type paymentRef struct {
	Integration string            `json:"i"`
	Family      string            `json:"f"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
}

// ---- specs ----

var contextOptions = []obsdk.Option{
	{Value: obsdk.PaymentContextPartyToParty, Label: "Person to person"},
	{Value: obsdk.PaymentContextBill, Label: "Bill payment"},
	{Value: obsdk.PaymentContextEcommerceGoods, Label: "Online purchase of goods"},
	{Value: obsdk.PaymentContextEcommerceServices, Label: "Online purchase of services"},
}

// contextCodes are v4.0 Risk.PaymentContextCode values.
var contextCodes = map[string]string{
	obsdk.PaymentContextPartyToParty:      "TransferToThirdParty",
	obsdk.PaymentContextBill:              "BillingGoodsAndServicesInArrears",
	obsdk.PaymentContextEcommerceGoods:    "EcommerceMerchantInitiatedPayment",
	obsdk.PaymentContextEcommerceServices: "EcommerceMerchantInitiatedPayment",
}

// referencePattern is what HSBC accepts in a Faster Payments reference.
const referencePattern = `^[A-Za-z0-9&\-./]{1,18}$`

// paymentSpecs describes the payments HSBC's UK brands take. Rules come from
// the HSBC UK Open Banking implementation guide (v4.0.1, section 18).
func paymentSpecs() []obsdk.PaymentSpec {
	return []obsdk.PaymentSpec{{
		Type: obsdk.PaymentDomestic, Countries: []obsdk.Country{"GB"}, Currencies: []string{"GBP"},
		MaxTransfers: 1, AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
		Fields: []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,13}(\.\d{1,2})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeSortCodeAccount}, Label: "Pay from",
				Note: "Leave empty to let the user pick the account on the bank's page."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeSortCodeAccount}, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name",
				Note: "Checked against the account holder's name (Confirmation of Payee)."},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldRequired, MaxItems: 1, MaxLength: 18, Pattern: referencePattern, Label: "Payment reference",
				Note: "Letters, digits and & - . / only (no spaces). Paying a credit card needs at least 4 digits in it."},
			{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 31, Note: "Generated when empty."},
			{Path: obsdk.FieldInstructionID, Use: obsdk.FieldOptional, MaxLength: 35, Note: "Generated when empty."},
			{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
				Note: "Makes a future-dated payment. Its status then only says whether it was scheduled."},
			{Path: obsdk.FieldContext, Use: obsdk.FieldOptional, Options: contextOptions},
		},
		Notes: []string{"Faster Payments. Payments made 23:45-00:00 may need extra fraud checks and can be declined."},
	}}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if c.brand.version == "v4.0" {
		for _, s := range paymentSpecs() {
			if s.Type == t {
				return s, nil
			}
		}
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: %s offers no %q payments through this SDK", obsdk.ErrUnsupported, c.brand.name, t)
}

// ---- request bodies ----

type obAmount struct {
	Amount   string `json:"Amount"`
	Currency string `json:"Currency"`
}

type obAccount struct {
	SchemeName     string `json:"SchemeName"`
	Identification string `json:"Identification"`
	Name           string `json:"Name,omitempty"`
}

type obRemittance struct {
	Structured []obStructured `json:"Structured,omitempty"`
}

type obStructured struct {
	CreditorReferenceInformation struct {
		Reference string `json:"Reference"`
	} `json:"CreditorReferenceInformation"`
}

type initiation struct {
	InstructionIdentification  string        `json:"InstructionIdentification"`
	EndToEndIdentification     string        `json:"EndToEndIdentification"`
	LocalInstrument            string        `json:"LocalInstrument,omitempty"`
	RequestedExecutionDateTime string        `json:"RequestedExecutionDateTime,omitempty"`
	InstructedAmount           obAmount      `json:"InstructedAmount"`
	DebtorAccount              *obAccount    `json:"DebtorAccount,omitempty"`
	CreditorAccount            obAccount     `json:"CreditorAccount"`
	RemittanceInformation      *obRemittance `json:"RemittanceInformation,omitempty"`
}

// obDecimal makes sure the amount has a decimal point.
func obDecimal(d obsdk.Decimal) string {
	s := string(d)
	if !strings.Contains(s, ".") {
		s += ".00"
	}
	return s
}

// shortID turns a generated id into one that fits OBIE's 31/35 character fields.
func shortID(id string, max int) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > max {
		id = id[:max]
	}
	return id
}

func (c *client) buildInitiation(r obsdk.PaymentRequest) (family string, ini initiation, risk map[string]any) {
	t := r.Transfers[0]
	family = familyDomestic
	if r.ExecutionDate != "" {
		family = familyDomesticScheduled
		// Midday UTC keeps the date the same in the UK all year.
		ini.RequestedExecutionDateTime = r.ExecutionDate + "T12:00:00+00:00"
	}
	ini.InstructionIdentification = t.InstructionID
	if ini.InstructionIdentification == "" {
		ini.InstructionIdentification = shortID(c.cfg.ID(obsdk.IDRequest), 35)
	}
	ini.EndToEndIdentification = t.EndToEndID
	if ini.EndToEndIdentification == "" {
		ini.EndToEndIdentification = shortID(c.cfg.ID(obsdk.IDRequest), 31)
	}
	ini.LocalInstrument = "UK.OBIE.FPS"
	ini.InstructedAmount = obAmount{Amount: obDecimal(t.Amount.Amount), Currency: t.Amount.Currency}
	if r.Debtor != nil && r.Debtor.Account != nil && r.Debtor.Account.Value != "" {
		ini.DebtorAccount = &obAccount{SchemeName: "UK.OBIE.SortCodeAccountNumber", Identification: r.Debtor.Account.Value, Name: r.Debtor.Name}
	}
	ini.CreditorAccount = obAccount{SchemeName: "UK.OBIE.SortCodeAccountNumber", Identification: t.Creditor.Account.Value, Name: t.Creditor.Name}
	if len(t.Remittance) > 0 && t.Remittance[0] != "" {
		var s obStructured
		s.CreditorReferenceInformation.Reference = t.Remittance[0]
		ini.RemittanceInformation = &obRemittance{Structured: []obStructured{s}}
	}
	risk = map[string]any{}
	if code := contextCodes[r.Context]; code != "" {
		risk["PaymentContextCode"] = code
	}
	return family, ini, risk
}

// paymentBody builds {"Data":{...},"Risk":{...}} for a consent (consentID
// empty) or a submission. Scheduled payments carry Permission "Create".
func paymentBody(consentID string, ini, risk json.RawMessage, scheduled bool) ([]byte, error) {
	data := map[string]any{"Initiation": ini}
	if consentID != "" {
		data["ConsentId"] = consentID
	}
	if scheduled {
		data["Permission"] = "Create"
	}
	return json.Marshal(map[string]any{"Data": data, "Risk": risk})
}

// postSigned sends a body with its detached JWS and an idempotency key.
func (c *client) postSigned(ctx context.Context, op, path string, body []byte, bearer, key string, psu *obsdk.PSUContext) (*resp, error) {
	sig, err := c.signBody(body)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, req{op: op, method: http.MethodPost, path: path, raw: body, bearer: bearer, psu: psu,
		header: map[string]string{"x-jws-signature": sig, "x-idempotency-key": key}})
}

// ---- operations ----

// InitiatePayment creates a payment consent and returns the redirect that
// lets the user approve it. Resume submits the payment.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: HSBC only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	if _, err := c.signBody([]byte("{}")); err != nil { // fail on missing signing config before any call
		return nil, err
	}

	family, ini, risk := c.buildInitiation(r)
	iniJSON, err := json.Marshal(ini)
	if err != nil {
		return nil, err
	}
	riskJSON, err := json.Marshal(risk)
	if err != nil {
		return nil, err
	}
	pf := &payFlow{Type: r.Type, Family: family, Initiation: iniJSON, Risk: riskJSON,
		Scheduled: family == familyDomesticScheduled, SubmitKey: c.cfg.ID(obsdk.IDRequest)}
	body, err := paymentBody("", iniJSON, riskJSON, pf.Scheduled)
	if err != nil {
		return nil, err
	}
	cc, err := c.clientToken(ctx, "payments")
	if err != nil {
		return nil, err
	}
	key := r.IdempotencyKey
	if key == "" {
		key = c.cfg.ID(obsdk.IDRequest)
	}
	res, err := c.postSigned(ctx, opPayConsent, c.apiPath("pisp")+"/"+family+"-payment-consents", body, cc, shortID(key, 40), psuOrNil(r.PSU))
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opPayConsent, res)
	}
	var cr consentResponse
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.Data.ConsentID == "" {
		return nil, fmt.Errorf("hsbc: unreadable payment consent response (HTTP %d)", res.status)
	}
	if cr.Data.Status == "RJCT" || cr.Data.Status == "Rejected" {
		return nil, &obsdk.PaymentRejectedError{Reason: "consent_rejected", Err: fmt.Errorf("hsbc rejected the payment consent")}
	}
	pf.ConsentID = cr.Data.ConsentID

	f := &flow{Phase: phPayRedirect, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Pay: pf}
	if f.AuthURL, err = c.authorizeURL(f, pf.ConsentID, "payments"); err != nil {
		return nil, err
	}
	return c.pause(f, payRedirectStep(f))
}

func payRedirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to the bank to approve the payment, then pass the callback URL (with its #fragment) to Resume."}
}

// resumePayment exchanges the callback's code and submits the payment.
func (c *client) resumePayment(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	if in.Callback == "" {
		return c.pause(f, payRedirectStep(f))
	}
	tr, err := c.exchangeCallback(ctx, f, in.Callback)
	if err != nil {
		return nil, err
	}
	pf := f.Pay
	body, err := paymentBody(pf.ConsentID, pf.Initiation, pf.Risk, pf.Scheduled)
	if err != nil {
		return nil, err
	}
	res, err := c.postSigned(ctx, opPayment, c.apiPath("pisp")+"/"+pf.Family+"-payments", body, tr.AccessToken, shortID(pf.SubmitKey, 40), psuOrNil(f.PSU))
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opPayment, res)
	}
	pay, err := c.toPayment(pf.Family, pf.Type, res.body)
	if err != nil {
		return nil, err
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: res.body}, nil
}

type paymentResponse struct {
	Data map[string]json.RawMessage `json:"Data"`
}

func (c *client) toPayment(family string, t obsdk.PaymentType, body []byte) (*obsdk.Payment, error) {
	var pr paymentResponse
	if err := json.Unmarshal(body, &pr); err != nil || pr.Data == nil {
		return nil, fmt.Errorf("hsbc: unreadable payment response")
	}
	var id, status string
	_ = json.Unmarshal(pr.Data[idField[family]], &id)
	_ = json.Unmarshal(pr.Data["Status"], &status)
	if id == "" {
		return nil, fmt.Errorf("hsbc: payment response has no %s", idField[family])
	}
	ref, err := flowstate.Encode(paymentRef{Integration: c.integrationID(), Family: family, ID: id, Type: t})
	if err != nil {
		return nil, err
	}
	p := &obsdk.Payment{ID: id, Type: t, BankStatus: status, Ref: ref, Raw: body}
	p.Status, p.Final = mapPaymentStatus(status)
	if status == "INCO" || status == "InitiationCompleted" {
		p.Reason = "scheduled; the later execution is not reported through this API"
	}
	var ini struct {
		DebtorAccount *obAccount `json:"DebtorAccount"`
	}
	if json.Unmarshal(pr.Data["Initiation"], &ini) == nil && ini.DebtorAccount != nil && ini.DebtorAccount.Identification != "" {
		p.Debtor = &obsdk.Identifier{Scheme: sdkScheme(ini.DebtorAccount.SchemeName), Value: ini.DebtorAccount.Identification}
	}
	return p, nil
}

// mapPaymentStatus maps OBIE payment statuses: v4.0 ISO codes and the v3.1
// names. Scheduled payments only report whether the schedule was set up.
func mapPaymentStatus(s string) (obsdk.PaymentStatus, bool) {
	switch s {
	case "RCVD", "PDNG", "Pending", "InitiationPending":
		return obsdk.PaymentAccepted, false
	case "ACTC", "ACCP", "ACSP", "ACWC", "ACWP", "AcceptedSettlementInProcess":
		return obsdk.PaymentInProgress, false
	case "ACSC", "ACCC", "AcceptedSettlementCompleted", "AcceptedCreditSettlementCompleted":
		return obsdk.PaymentCompleted, true
	case "INCO", "InitiationCompleted":
		return obsdk.PaymentInProgress, true
	case "RJCT", "INFA", "Rejected", "InitiationFailed":
		return obsdk.PaymentRejected, true
	case "CANC", "Cancelled":
		return obsdk.PaymentCancelled, true
	}
	return obsdk.PaymentReceived, false
}

// PaymentStatus reads a payment with a client token (no user session needed).
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	var pr paymentRef
	if err := flowstate.Decode(ref, &pr); err != nil || pr.Integration != c.integrationID() || idField[pr.Family] == "" {
		return nil, fmt.Errorf("%w: not an HSBC payment reference", obsdk.ErrInvalidRequest)
	}
	cc, err := c.clientToken(ctx, "payments")
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: c.apiPath("pisp") + "/" + pr.Family + "-payments/" + url.PathEscape(pr.ID), bearer: cc, psu: o.PSU})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.apiErr(opPayStatus, res)
	}
	p, err := c.toPayment(pr.Family, pr.Type, res.body)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *p, Raw: res.body, Meta: meta(res)}, nil
}

// CancelPayment is not offered: the OBIE payment API has no cancellation.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	return nil, fmt.Errorf("%w: HSBC's API cannot cancel payments", obsdk.ErrUnsupported)
}
