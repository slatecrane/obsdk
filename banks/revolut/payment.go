package revolut

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation follows OBIE v3.1: a payment consent created with a
// client token, the user's approval on Revolut's consent page, then the
// payment itself submitted with the user's token and the same Initiation.

const phPayRedirect = "payment_redirect_wait"

// Endpoint families. Domestic covers GBP in the UK and EUR (SEPA) in the EEA.
const (
	familyDomestic          = "domestic"
	familyDomesticScheduled = "domestic-scheduled"
	familyInternational     = "international"
	familyIntlScheduled     = "international-scheduled"
)

// idField is the payment id's name in each family's responses.
var idField = map[string]string{
	familyDomestic:          "DomesticPaymentId",
	familyDomesticScheduled: "DomesticScheduledPaymentId",
	familyInternational:     "InternationalPaymentId",
	familyIntlScheduled:     "InternationalScheduledPaymentId",
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
	{Value: obsdk.PaymentContextOther, Label: "Other"},
}

var contextCodes = map[string]string{
	obsdk.PaymentContextPartyToParty:      "PartyToParty",
	obsdk.PaymentContextBill:              "BillPayment",
	obsdk.PaymentContextEcommerceGoods:    "EcommerceGoods",
	obsdk.PaymentContextEcommerceServices: "EcommerceServices",
	obsdk.PaymentContextOther:             "Other",
}

// paymentSpecs describes what Revolut's payment API takes, per type. Lengths
// come from Revolut's OpenAPI spec (open-banking.yaml, v3.1.0).
func paymentSpecs() []obsdk.PaymentSpec {
	common := func(currency, accountScheme string, refLen, e2eLen int) []obsdk.PaymentField {
		return []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,13}(\.\d{1,5})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{accountScheme}, Label: "Pay from",
				Note: "Leave empty to let the user pick the account on Revolut's page; when set, the user can only approve from that account."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{accountScheme}, MaxLength: 256, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name", Note: "Revolut may check it against the account holder's name."},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: refLen, Label: "Payment reference",
				Note: "Sent as the payment reference the payee sees."},
			{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: e2eLen, Note: "Generated when empty."},
			{Path: obsdk.FieldInstructionID, Use: obsdk.FieldOptional, MaxLength: 35, Note: "Generated when empty."},
			{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
				Note: "Makes a scheduled payment (Revolut marks scheduled payments beta). Its status then only says whether the schedule was set up."},
			{Path: obsdk.FieldContext, Use: obsdk.FieldOptional, Options: contextOptions},
		}
	}
	base := obsdk.PaymentSpec{
		MaxTransfers: 1, AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
	}
	gb := base
	gb.Type, gb.Countries, gb.Currencies = obsdk.PaymentDomestic, []obsdk.Country{"GB"}, []string{"GBP"}
	gb.Fields = common("GBP", obsdk.SchemeSortCodeAccount, 18, 31)
	gb.Notes = []string{"Faster Payments: the reference holds at most 18 characters and the end-to-end id 31."}

	sepa := base
	sepa.Type, sepa.Countries, sepa.Currencies = obsdk.PaymentSEPA, eea, []string{"EUR"}
	sepa.Fields = common("EUR", obsdk.SchemeIBAN, 35, 35)

	intl := base
	intl.Type = obsdk.PaymentCrossBorder
	intl.Fields = append(common("", obsdk.SchemeIBAN, 35, 35),
		obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldRequired, Label: "Payee address",
			Note: "Revolut answers \"Address is required for this beneficiary\" without it."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldRequired, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: `^[A-Z0-9]{8}([A-Z0-9]{3})?$`, Label: "Payee bank BIC"},
		obsdk.PaymentField{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldOptional, Options: []obsdk.Option{
			{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees"},
			{Value: obsdk.ChargeBearerService, Label: "As the scheme defines"},
		}},
	)
	for i := range intl.Fields {
		if intl.Fields[i].Path == obsdk.FieldDebtorAccount || intl.Fields[i].Path == obsdk.FieldCreditorAccount {
			intl.Fields[i].Schemes = []string{obsdk.SchemeIBAN, obsdk.SchemeSortCodeAccount}
		}
	}
	intl.Notes = []string{"SWIFT transfer in any currency Revolut supports; the user may pay from an account in another currency."}
	return []obsdk.PaymentSpec{gb, sepa, intl}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	for _, s := range paymentSpecs() {
		if s.Type == t && (len(s.Countries) == 0 || containsCountry(s.Countries, c.target.Country)) {
			return s, nil
		}
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: Revolut offers no %q payments in %s", obsdk.ErrUnsupported, t, c.target.Country)
}

func containsCountry(cs []obsdk.Country, c obsdk.Country) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
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

type obAddress struct {
	StreetName     string   `json:"StreetName,omitempty"`
	BuildingNumber string   `json:"BuildingNumber,omitempty"`
	PostCode       string   `json:"PostCode,omitempty"`
	TownName       string   `json:"TownName,omitempty"`
	Country        string   `json:"Country,omitempty"`
	AddressLine    []string `json:"AddressLine,omitempty"`
}

type initiation struct {
	InstructionIdentification  string            `json:"InstructionIdentification"`
	EndToEndIdentification     string            `json:"EndToEndIdentification"`
	RequestedExecutionDateTime string            `json:"RequestedExecutionDateTime,omitempty"`
	CurrencyOfTransfer         string            `json:"CurrencyOfTransfer,omitempty"`
	ChargeBearer               string            `json:"ChargeBearer,omitempty"`
	InstructedAmount           obAmount          `json:"InstructedAmount"`
	DebtorAccount              *obAccount        `json:"DebtorAccount,omitempty"`
	Creditor                   *obCreditor       `json:"Creditor,omitempty"`
	CreditorAgent              *obAccount        `json:"CreditorAgent,omitempty"`
	CreditorAccount            obAccount         `json:"CreditorAccount"`
	RemittanceInformation      map[string]string `json:"RemittanceInformation,omitempty"`
}

type obCreditor struct {
	Name          string     `json:"Name,omitempty"`
	PostalAddress *obAddress `json:"PostalAddress,omitempty"`
}

var obSchemes = map[string]string{
	obsdk.SchemeIBAN:            "UK.OBIE.IBAN",
	obsdk.SchemeSortCodeAccount: "UK.OBIE.SortCodeAccountNumber",
}

// obDecimal makes sure the amount has the decimal point Revolut's pattern needs.
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

func (c *client) buildInitiation(r obsdk.PaymentRequest, spec obsdk.PaymentSpec) (family string, ini initiation, risk map[string]any) {
	t := r.Transfers[0]
	international := r.Type == obsdk.PaymentCrossBorder
	family = familyDomestic
	if international {
		family = familyInternational
	}
	if r.ExecutionDate != "" {
		family += "-scheduled"
		// Midday UTC keeps the date the same in every European time zone.
		ini.RequestedExecutionDateTime = r.ExecutionDate + "T12:00:00+00:00"
	}
	e2eMax := 35
	if f, ok := spec.Field(obsdk.FieldEndToEndID); ok && f.MaxLength > 0 {
		e2eMax = f.MaxLength
	}
	ini.InstructionIdentification = t.InstructionID
	if ini.InstructionIdentification == "" {
		ini.InstructionIdentification = shortID(c.cfg.ID(obsdk.IDRequest), 35)
	}
	ini.EndToEndIdentification = t.EndToEndID
	if ini.EndToEndIdentification == "" {
		ini.EndToEndIdentification = shortID(c.cfg.ID(obsdk.IDRequest), e2eMax)
	}
	ini.InstructedAmount = obAmount{Amount: obDecimal(t.Amount.Amount), Currency: t.Amount.Currency}
	if r.Debtor != nil && r.Debtor.Account != nil && r.Debtor.Account.Value != "" {
		ini.DebtorAccount = &obAccount{SchemeName: obSchemes[r.Debtor.Account.Scheme], Identification: r.Debtor.Account.Value, Name: r.Debtor.Name}
	}
	ini.CreditorAccount = obAccount{SchemeName: obSchemes[t.Creditor.Account.Scheme], Identification: t.Creditor.Account.Value, Name: t.Creditor.Name}
	if len(t.Remittance) > 0 && t.Remittance[0] != "" {
		ini.RemittanceInformation = map[string]string{"Reference": t.Remittance[0]}
	}
	if international {
		ini.CurrencyOfTransfer = t.Amount.Currency
		cr := &obCreditor{Name: t.Creditor.Name}
		if a := t.Creditor.Address; a != nil {
			cr.PostalAddress = &obAddress{StreetName: a.Street, BuildingNumber: a.BuildingNumber, PostCode: a.PostCode,
				TownName: a.Town, Country: a.Country, AddressLine: a.Lines}
		}
		ini.Creditor = cr
		if ag := t.Creditor.Agent; ag != nil && ag.BIC != "" {
			ini.CreditorAgent = &obAccount{SchemeName: "UK.OBIE.BICFI", Identification: ag.BIC}
		}
		switch r.ChargeBearer {
		case obsdk.ChargeBearerDebtor:
			ini.ChargeBearer = "BorneByDebtor"
		case obsdk.ChargeBearerService:
			ini.ChargeBearer = "FollowingServiceLevel"
		}
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
		return nil, fmt.Errorf("%w: Revolut only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or PaymentRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	if _, err := c.signBody([]byte("{}")); err != nil { // fail on missing signing config before any call
		return nil, err
	}

	family, ini, risk := c.buildInitiation(r, spec)
	iniJSON, err := json.Marshal(ini)
	if err != nil {
		return nil, err
	}
	riskJSON, err := json.Marshal(risk)
	if err != nil {
		return nil, err
	}
	pf := &payFlow{Type: r.Type, Family: family, Initiation: iniJSON, Risk: riskJSON,
		Scheduled: strings.HasSuffix(family, "-scheduled"), SubmitKey: c.cfg.ID(obsdk.IDRequest)}
	body, err := paymentBody("", iniJSON, riskJSON, pf.Scheduled)
	if err != nil {
		return nil, err
	}
	cc, err := c.clientTokenFor(ctx, "payments")
	if err != nil {
		return nil, err
	}
	key := r.IdempotencyKey
	if key == "" {
		key = c.cfg.ID(obsdk.IDRequest)
	}
	res, err := c.postSigned(ctx, opPayConsent, "/"+family+"-payment-consents", body, cc, key, psuOrNil(r.PSU))
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opPayConsent, res)
	}
	var cr consentResponse
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.Data.ConsentID == "" {
		return nil, fmt.Errorf("revolut: unreadable payment consent response (HTTP %d)", res.status)
	}
	if cr.Data.Status == "Rejected" {
		return nil, &obsdk.PaymentRejectedError{Reason: "consent_rejected", Err: fmt.Errorf("revolut rejected the payment consent")}
	}
	pf.ConsentID = cr.Data.ConsentID

	f := &flow{Phase: phPayRedirect, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Pay: pf}
	jwt, err := c.signRequestObject(pf.ConsentID, redirectURL, f.OAuthState, "payments")
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"response_type": {"code id_token"}, "scope": {"payments"}, "redirect_uri": {redirectURL},
		"client_id": {c.cfg.Credentials.ClientID}, "request": {jwt}, "state": {f.OAuthState},
	}
	f.AuthURL = c.ui + "?" + q.Encode()
	return c.pause(f, payRedirectStep(f))
}

func payRedirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to Revolut to approve the payment, then pass the callback URL to Resume."}
}

// resumePayment exchanges the callback's code and submits the payment.
func (c *client) resumePayment(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	if in.Callback == "" {
		return c.pause(f, payRedirectStep(f))
	}
	p, err := callback.Parse(in.Callback)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if code, desc, failed := p.Error(); failed {
		return nil, authFailed("payment was not approved (%s: %s)", code, desc)
	}
	if st := p.Get("state"); st != f.OAuthState {
		return nil, authFailed("callback state does not match the payment that was started")
	}
	code := p.Get("code")
	if code == "" {
		return nil, fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}})
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	pf := f.Pay
	body, err := paymentBody(pf.ConsentID, pf.Initiation, pf.Risk, pf.Scheduled)
	if err != nil {
		return nil, err
	}
	res, err := c.postSigned(ctx, opPayment, "/"+pf.Family+"-payments", body, tr.AccessToken, pf.SubmitKey, psuOrNil(f.PSU))
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
		return nil, fmt.Errorf("revolut: unreadable payment response")
	}
	var id, status string
	_ = json.Unmarshal(pr.Data[idField[family]], &id)
	_ = json.Unmarshal(pr.Data["Status"], &status)
	if id == "" {
		return nil, fmt.Errorf("revolut: payment response has no %s", idField[family])
	}
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, Family: family, ID: id, Type: t})
	if err != nil {
		return nil, err
	}
	p := &obsdk.Payment{ID: id, Type: t, BankStatus: status, Ref: ref, Raw: body}
	p.Status, p.Final = mapPaymentStatus(status)
	if status == "InitiationCompleted" {
		p.Reason = "scheduled; Revolut does not report the later execution through this API"
	}
	var ini struct {
		DebtorAccount *obAccount `json:"DebtorAccount"`
	}
	if json.Unmarshal(pr.Data["Initiation"], &ini) == nil && ini.DebtorAccount != nil && ini.DebtorAccount.Identification != "" {
		p.Debtor = &obsdk.Identifier{Scheme: sdkScheme(ini.DebtorAccount.SchemeName), Value: ini.DebtorAccount.Identification}
	}
	return p, nil
}

// mapPaymentStatus maps OBIE payment statuses (single payments, and
// scheduled ones, which only report whether the schedule was set up).
func mapPaymentStatus(s string) (obsdk.PaymentStatus, bool) {
	switch s {
	case "Pending", "InitiationPending":
		return obsdk.PaymentAccepted, false
	case "AcceptedSettlementInProcess":
		return obsdk.PaymentInProgress, false
	case "AcceptedSettlementCompleted":
		return obsdk.PaymentCompleted, true
	case "InitiationCompleted":
		return obsdk.PaymentInProgress, true
	case "Rejected", "InitiationFailed":
		return obsdk.PaymentRejected, true
	}
	return obsdk.PaymentReceived, false
}

// PaymentStatus reads a payment with a client token (no user session needed).
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	var pr paymentRef
	if err := flowstate.Decode(ref, &pr); err != nil || pr.Integration != integrationID || idField[pr.Family] == "" {
		return nil, fmt.Errorf("%w: not a Revolut payment reference", obsdk.ErrInvalidRequest)
	}
	cc, err := c.clientTokenFor(ctx, "payments")
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: "/" + pr.Family + "-payments/" + url.PathEscape(pr.ID), bearer: cc, psu: o.PSU})
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

// CancelPayment is not offered: Revolut's API has no cancellation endpoint.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	return nil, fmt.Errorf("%w: Revolut's API cannot cancel payments", obsdk.ErrUnsupported)
}
