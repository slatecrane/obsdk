package obie

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
// submitted with the user's token and the same Initiation. The bank's
// Profile.Payments decides the family (domestic, international, their
// -scheduled variants) and builds the Initiation.

// payFlow is the serialized state of a payment between consent and submission.
type payFlow struct {
	Type       obsdk.PaymentType `json:"type"`
	Family     string            `json:"family"`
	ConsentID  string            `json:"consent_id"`
	Initiation json.RawMessage   `json:"initiation"` // resubmitted unchanged with the payment
	Risk       json.RawMessage   `json:"risk"`
	SubmitKey  string            `json:"submit_key"` // idempotency key of the submission, kept for retries
}

// paymentRef is what Payment.Ref holds: enough to read the payment later.
type paymentRef struct {
	Integration string            `json:"i"`
	Family      string            `json:"f"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
}

// scheduled reports whether a family is a future-dated one, whose consent
// carries Permission "Create" and which can be deleted before it runs.
func scheduled(family string) bool { return strings.HasSuffix(family, "-scheduled") }

// idField is the payment id's name in a family's responses, e.g.
// "international-scheduled" -> "InternationalScheduledPaymentId".
func idField(family string) string {
	var b strings.Builder
	for _, part := range strings.Split(family, "-") {
		if part != "" {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String() + "PaymentId"
}

// ---- helpers for builders ----

// Amount is an OBIE amount.
type Amount struct {
	Amount   string `json:"Amount"`
	Currency string `json:"Currency"`
}

// Account is an OBIE account identification.
type Account struct {
	SchemeName     string `json:"SchemeName"`
	Identification string `json:"Identification"`
	Name           string `json:"Name,omitempty"`
}

// Decimal makes sure an amount has a decimal point, as OBIE wants.
func Decimal(d obsdk.Decimal) string {
	s := string(d)
	if !strings.Contains(s, ".") {
		s += ".00"
	}
	return s
}

// ShortID turns a generated id into one that fits OBIE's 31/35 character fields.
func ShortID(id string, max int) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > max {
		id = id[:max]
	}
	return id
}

// ---- operations ----

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if c.p.Payments != nil {
		for _, s := range c.p.Info.Payments {
			if s.Type != t {
				continue
			}
			ok := len(s.Countries) == 0
			for _, cc := range s.Countries {
				ok = ok || cc == c.target.Country
			}
			if ok {
				return s, nil
			}
		}
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: %s offers no %q payments in %s through this SDK", obsdk.ErrUnsupported, c.p.Info.Name, t, c.target.Country)
}

// paymentBody builds {"Data":{...},"Risk":{...}} for a consent (consentID
// empty) or a submission. Scheduled payments carry Permission "Create".
func paymentBody(consentID, family string, ini, risk json.RawMessage) ([]byte, error) {
	data := map[string]any{"Initiation": ini}
	if consentID != "" {
		data["ConsentId"] = consentID
	}
	if scheduled(family) && consentID == "" {
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
		return nil, fmt.Errorf("%w: %s only supports the redirect method here", obsdk.ErrInvalidRequest, c.target.Bank)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	if _, err := c.signBody([]byte("{}")); err != nil { // fail on missing signing config before any call
		return nil, err
	}
	family, ini, risk, err := c.p.Payments(r, c.target, func() string { return c.cfg.ID(obsdk.IDRequest) })
	if err != nil {
		return nil, err
	}
	if risk == nil {
		risk = map[string]any{}
	}
	iniJSON, err := json.Marshal(ini)
	if err != nil {
		return nil, err
	}
	riskJSON, err := json.Marshal(risk)
	if err != nil {
		return nil, err
	}
	pf := &payFlow{Type: r.Type, Family: family, Initiation: iniJSON, Risk: riskJSON, SubmitKey: c.cfg.ID(obsdk.IDRequest)}
	body, err := paymentBody("", family, iniJSON, riskJSON)
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
	res, err := c.postSigned(ctx, opPayConsent, c.p.PISPath+"/"+family+"-payment-consents", body, cc, ShortID(key, 40), psuOrNil(r.PSU))
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opPayConsent, res)
	}
	var cr consentResponse
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.Data.ConsentID == "" {
		return nil, fmt.Errorf("obie: unreadable payment consent response (HTTP %d)", res.status)
	}
	if cr.Data.Status == "RJCT" || cr.Data.Status == "Rejected" {
		return nil, &obsdk.PaymentRejectedError{Reason: "consent_rejected", Err: fmt.Errorf("%s rejected the payment consent", c.target.Bank)}
	}
	pf.ConsentID = cr.Data.ConsentID

	f := &flow{Phase: phPayRedirect, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Pay: pf}
	if f.AuthURL, err = c.authorizeURL(f, c.p.intentID(KindPayment, pf.ConsentID), "payments", r.Language); err != nil {
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
	body, err := paymentBody(pf.ConsentID, pf.Family, pf.Initiation, pf.Risk)
	if err != nil {
		return nil, err
	}
	res, err := c.postSigned(ctx, opPayment, c.p.PISPath+"/"+pf.Family+"-payments", body, tr.AccessToken, ShortID(pf.SubmitKey, 40), psuOrNil(f.PSU))
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
		return nil, fmt.Errorf("obie: unreadable payment response")
	}
	var id, status string
	_ = json.Unmarshal(pr.Data[idField(family)], &id)
	_ = json.Unmarshal(pr.Data["Status"], &status)
	if id == "" {
		return nil, fmt.Errorf("obie: payment response has no %s", idField(family))
	}
	ref, err := flowstate.Encode(paymentRef{Integration: c.p.ID, Family: family, ID: id, Type: t})
	if err != nil {
		return nil, err
	}
	p := &obsdk.Payment{ID: id, Type: t, BankStatus: status, Ref: ref, Raw: body}
	p.Status, p.Final = mapPaymentStatus(status)
	if status == "INCO" || status == "InitiationCompleted" {
		p.Reason = "scheduled; the later execution is not reported through this API"
	}
	var ini struct {
		DebtorAccount *Account `json:"DebtorAccount"`
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

func (c *client) decodeRef(ref string) (*paymentRef, error) {
	var pr paymentRef
	if err := flowstate.Decode(ref, &pr); err != nil || pr.Integration != c.p.ID || pr.Family == "" || pr.ID == "" {
		return nil, fmt.Errorf("%w: not a %s payment reference", obsdk.ErrInvalidRequest, c.target.Bank)
	}
	return &pr, nil
}

func (c *client) paymentPath(pr *paymentRef) string {
	return c.p.PISPath + "/" + pr.Family + "-payments/" + url.PathEscape(pr.ID)
}

// PaymentStatus reads a payment with a client token (no user session needed).
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	pr, err := c.decodeRef(ref)
	if err != nil {
		return nil, err
	}
	cc, err := c.clientToken(ctx, "payments")
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: c.paymentPath(pr), bearer: cc, psu: o.PSU})
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

// CancelPayment deletes a scheduled payment before it runs, with a client
// token, where the bank's spec says it can (PaymentSpec.Cancellable).
// Immediate payments cannot be cancelled through OBIE.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	pr, err := c.decodeRef(ref)
	if err != nil {
		return nil, err
	}
	spec, err := c.paymentSpec(pr.Type)
	if err != nil {
		return nil, err
	}
	if !scheduled(pr.Family) || !spec.Cancellable {
		return nil, fmt.Errorf("%w: %s can only cancel scheduled payments through this API", obsdk.ErrUnsupported, c.target.Bank)
	}
	cc, err := c.clientToken(ctx, "payments")
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodDelete, path: c.paymentPath(pr), bearer: cc, psu: o.PSU})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusNoContent && res.status != http.StatusOK {
		return nil, c.apiErr(opPayment, res)
	}
	st, err := c.PaymentStatus(ctx, ref, o)
	if err != nil {
		// Deleted, but the status read failed: report what is known.
		return &obsdk.Step{Kind: obsdk.StepDone, Payment: &obsdk.Payment{ID: pr.ID, Type: pr.Type, Status: obsdk.PaymentCancelled, Final: true, Ref: ref}}, nil
	}
	p := st.Data
	if p.Status != obsdk.PaymentCancelled {
		// The DELETE succeeded, which is what counts. Crosskey's sandbox keeps
		// answering the old status (InitiationCompleted) after it.
		p.Reason = "deleted; the bank still reports " + p.BankStatus
		p.Status, p.Final = obsdk.PaymentCancelled, true
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: &p, Raw: st.Raw}, nil
}
