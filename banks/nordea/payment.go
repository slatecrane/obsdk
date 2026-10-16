package nordea

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation uses Nordea's Single SCA API (personal, v4): the TPP
// creates the payment without a user token, the user signs it on Nordea's
// page, and Nordea redirects back with an auth_code. The status is readable
// without a token; the auth_code buys a token that can delete (cancel) it.

const phPayRedirect = "payment_redirect_wait"

const (
	opPayment   = "payment"
	opPayStatus = "payment_status"
	opPayCancel = "payment_cancel"
)

// payFlow is the serialized state of a payment waiting for the user's signature.
type payFlow struct {
	Phase       string            `json:"phase"`
	Type        obsdk.PaymentType `json:"type"`
	ID          string            `json:"id"`
	State       string            `json:"state"`
	RedirectURL string            `json:"redirect_url"`
	SignURL     string            `json:"sign_url"`
	PSU         obsdk.PSUContext  `json:"psu"`
}

// paymentRef is what Payment.Ref holds.
type paymentRef struct {
	Integration string            `json:"i"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
}

// ---- specs ----

// SchemeKID is the Norwegian payment reference (KID), sent as reference type OCR.
const SchemeKID = "KID"

func paymentSpecs() []obsdk.PaymentSpec {
	base := obsdk.PaymentSpec{
		Segments: []obsdk.Segment{obsdk.Personal}, MaxTransfers: 1, AuthApproaches: []string{"redirect"}, Cancellable: true,
		StatusNeedsSession: false, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
	}
	debtor := func(schemes ...string) obsdk.PaymentField {
		return obsdk.PaymentField{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: schemes, Label: "Pay from",
			Note: "Nordea needs the account up front; it must be in the payment's currency."}
	}
	common := []obsdk.PaymentField{
		{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,11}(\.\d{1,2})?$`, Label: "Amount"},
		{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35, Note: "Sent as external_id; generated when empty."},
		{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date", Note: "A future date can be cancelled until it is executed."},
	}
	with := func(fs ...obsdk.PaymentField) []obsdk.PaymentField {
		return append(append([]obsdk.PaymentField(nil), common...), fs...)
	}
	message := obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message",
		Note: "Not together with a payment reference."}

	sepa := base
	sepa.Type, sepa.Countries, sepa.Currencies = obsdk.PaymentSEPA, []obsdk.Country{"FI"}, []string{"EUR"}
	sepa.Fields = with(debtor(obsdk.SchemeIBAN),
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Payee account"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
		message,
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}, Label: "Reference",
			Note: "Not together with a message."},
	)
	sepa.Notes = []string{"Finland uses SEPA for domestic euro payments too."}

	inst := sepa
	inst.Type = obsdk.PaymentSEPAInstant
	inst.Fields = append([]obsdk.PaymentField(nil), sepa.Fields...)
	inst.Notes = []string{"Sent with urgency \"express\"; Nordea offers it for Finland."}

	se := base
	se.Type, se.Countries, se.Currencies = obsdk.PaymentDomestic, []obsdk.Country{"SE"}, []string{"SEK"}
	se.Fields = with(debtor(obsdk.SchemeIBAN, obsdk.SchemeBBAN),
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Label: "Payee account",
			Schemes: []string{obsdk.SchemeIBAN, obsdk.SchemeBBAN, obsdk.SchemeBankgiro, obsdk.SchemePlusgiro}},
		obsdk.PaymentField{Path: obsdk.FieldCreditorName, Use: obsdk.FieldOptional, MaxLength: 70, Label: "Payee name",
			Note: "Needed for account and Plusgiro payees; not sent for Bankgiro."},
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message",
			Note: "At most 25 characters to a Plusgiro payee. Not together with an OCR reference."},
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceOCR}, Label: "OCR reference",
			OnlyWith: &obsdk.FieldCondition{Path: obsdk.FieldCreditorAccount, Schemes: []string{obsdk.SchemeBankgiro, obsdk.SchemePlusgiro}}},
	)

	dk := base
	dk.Type, dk.Countries, dk.Currencies = obsdk.PaymentDomestic, []obsdk.Country{"DK"}, []string{"DKK"}
	dk.Fields = with(debtor(obsdk.SchemeIBAN, obsdk.SchemeBBAN),
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN, obsdk.SchemeBBAN}, Label: "Payee account"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 140, Label: "Payee name"},
		message,
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}, Label: "Reference",
			Note: "Not together with a message."},
	)
	dk.Notes = []string{"Danish giro forms (GIRO_DK, types 01-75) are not supported."}

	no := base
	no.Type, no.Countries, no.Currencies = obsdk.PaymentDomestic, []obsdk.Country{"NO"}, []string{"NOK"}
	no.Fields = with(debtor(obsdk.SchemeIBAN, obsdk.SchemeBBAN),
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN, obsdk.SchemeBBAN}, Label: "Payee account"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorName, Use: obsdk.FieldOptional, MaxLength: 70, Label: "Payee name"},
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message",
			Note: "Makes the payment a transfer with advice. Not together with a KID."},
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{SchemeKID}, Pattern: `^[0-9]{2,25}-?$`, Label: "KID"},
	)
	return []obsdk.PaymentSpec{sepa, inst, se, dk, no}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: Nordea payments of type %q are not available for %s %s customers", obsdk.ErrUnsupported, t, c.target.Country, c.target.Segment)
}

// ---- request body ----

type pisAccount struct {
	Value    string `json:"value"`
	Type     string `json:"type"`
	Currency string `json:"currency,omitempty"`
}

type pisReference struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type pisPayment struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
	Creditor struct {
		Account   pisAccount    `json:"account"`
		Name      string        `json:"name,omitempty"`
		Message   string        `json:"message,omitempty"`
		Reference *pisReference `json:"reference,omitempty"`
	} `json:"creditor"`
	Debtor struct {
		Account pisAccount `json:"account"`
	} `json:"debtor"`
	ExternalID             string `json:"external_id"`
	RequestedExecutionDate string `json:"requested_execution_date,omitempty"`
	Urgency                string `json:"urgency,omitempty"`
}

type pisRequest struct {
	Payment        pisPayment `json:"payment"`
	Authentication struct {
		State       string `json:"state"`
		RedirectURI string `json:"redirect_uri"`
		Language    string `json:"language,omitempty"`
	} `json:"authentication"`
}

// accountType maps an SDK identifier scheme to Nordea's account type.
func (c *client) accountType(scheme string) string {
	switch scheme {
	case obsdk.SchemeBBAN:
		return "BBAN_" + string(c.target.Country)
	case obsdk.SchemeBankgiro:
		return "BGNR"
	case obsdk.SchemePlusgiro:
		return "PGNR"
	}
	return scheme // IBAN
}

func (c *client) buildPayment(r obsdk.PaymentRequest) (pisPayment, error) {
	t := r.Transfers[0]
	var p pisPayment
	p.Amount, p.Currency = string(t.Amount.Amount), t.Amount.Currency
	p.Debtor.Account = pisAccount{Value: r.Debtor.Account.Value, Type: c.accountType(r.Debtor.Account.Scheme), Currency: t.Amount.Currency}
	cr := t.Creditor.Account
	p.Creditor.Account = pisAccount{Value: strings.ReplaceAll(cr.Value, "-", ""), Type: c.accountType(cr.Scheme)}
	if cr.Scheme == obsdk.SchemeIBAN || cr.Scheme == obsdk.SchemeBBAN {
		p.Creditor.Account.Currency = t.Amount.Currency
	}
	if cr.Scheme != obsdk.SchemeBankgiro {
		p.Creditor.Name = t.Creditor.Name
	}
	if len(t.Remittance) > 0 {
		p.Creditor.Message = t.Remittance[0]
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		if p.Creditor.Message != "" {
			return p, &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: obsdk.FieldReference, Index: 0, Code: obsdk.IssueUnsupported,
				Message: "Nordea takes either a message or a reference, not both"}}}
		}
		typ := ref.Scheme // RF, OCR
		if typ == SchemeKID {
			typ = "OCR"
		}
		p.Creditor.Reference = &pisReference{Value: ref.Value, Type: typ}
	}
	p.ExternalID = t.EndToEndID
	if p.ExternalID == "" {
		p.ExternalID = c.cfg.ID(obsdk.IDRequest)
	}
	p.RequestedExecutionDate = r.ExecutionDate
	if r.Type == obsdk.PaymentSEPAInstant {
		p.Urgency = "express"
	}
	return p, nil
}

// ---- initiate ----

type linksResponse struct {
	Response struct {
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"_links"`
	} `json:"response"`
}

var paymentIDRE = regexp.MustCompile(`/single-sca-payments/([^/?]+)`)

// InitiatePayment creates the payment and returns the redirect to Nordea's
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
		return nil, fmt.Errorf("%w: only the redirect method is implemented for Nordea payments", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or PaymentRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	p, err := c.buildPayment(r)
	if err != nil {
		return nil, err
	}
	pf := &payFlow{Phase: phPayRedirect, Type: r.Type, State: c.cfg.ID(obsdk.IDState), RedirectURL: redirectURL, PSU: r.PSU}
	var body pisRequest
	body.Payment = p
	body.Authentication.State, body.Authentication.RedirectURI, body.Authentication.Language = pf.State, redirectURL, r.Language

	product := "domestic-credit-transfer"
	if r.Type == obsdk.PaymentSEPA || r.Type == obsdk.PaymentSEPAInstant {
		product = "sepa-credit-transfer"
	}
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: "/personal/v4/payments/authorization/" + product, body: body, psu: psuOrNil(r.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opPayment, res)
	}
	var lr linksResponse
	if err := json.Unmarshal(res.body, &lr); err != nil {
		return nil, fmt.Errorf("nordea: unreadable payment response (HTTP %d)", res.status)
	}
	for _, l := range lr.Response.Links {
		switch l.Rel {
		case "redirect":
			pf.SignURL = l.Href
		case "status", "details":
			if m := paymentIDRE.FindStringSubmatch(l.Href); m != nil {
				pf.ID = m[1]
			}
		}
	}
	if pf.SignURL == "" || pf.ID == "" {
		return nil, fmt.Errorf("nordea: payment response lacks the signing link or the payment id")
	}
	pay, err := c.toPayment(pf.ID, pf.Type, "PendingUserApproval", "", res.body)
	if err != nil {
		return nil, err
	}
	return c.pausePayment(pf, pay)
}

func (c *client) pausePayment(pf *payFlow, pay *obsdk.Payment) (*obsdk.Step, error) {
	st := &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: pf.SignURL}, Payment: pay,
		Message: "Send the user to Nordea to sign the payment, then pass the callback URL to Resume."}
	s, err := flowstate.Encode(pf)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// resumePayment handles the return from Nordea's signing page:
// ?success=true&state=...&auth_code=...&response_code=...
func (c *client) resumePayment(ctx context.Context, pf *payFlow, in obsdk.StepInput) (*obsdk.Step, error) {
	if in.Callback == "" {
		pay, _ := c.toPayment(pf.ID, pf.Type, "PendingUserApproval", "", nil)
		return c.pausePayment(pf, pay)
	}
	p, err := callback.Parse(in.Callback)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if st := p.Get("state"); st != pf.State {
		return nil, authFailed("callback state does not match the payment that was started")
	}
	pay, err := c.readStatus(ctx, pf.ID, pf.Type, psuOrNil(pf.PSU))
	if err != nil {
		return nil, err
	}
	if code, desc, failed := p.Error(); failed || p.Get("success") != "true" {
		if code == "" {
			code = "success=" + p.Get("success")
		}
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("payment was not signed (%s %s, status %s)", code, desc, pay.BankStatus)}
	}
	if pay.Status == obsdk.PaymentRejected {
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: strings.ToLower(pay.BankStatus), Payment: pay}}
	}
	st := &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}
	// The auth_code buys a token for this payment, needed only to cancel it.
	if code := p.Get("auth_code"); code != "" {
		if tr, _, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {pf.RedirectURL}}); err == nil && tr != nil {
			s := &obsdk.Session{Bank: bankKey, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: integrationID,
				Meta: map[string]string{"purpose": "payment", "payment_id": pf.ID}}
			c.applyToken(s, tr)
			st.Session = s
		}
	}
	return st, nil
}

// ---- status and cancel ----

type statusResponse struct {
	Response struct {
		PaymentID   string `json:"payment_id"`
		Status      string `json:"status"`
		TPPMessages []struct {
			Category string `json:"category"`
			Code     string `json:"code"`
			Text     string `json:"text"`
		} `json:"tpp_messages"`
	} `json:"response"`
}

func (c *client) readStatus(ctx context.Context, id string, t obsdk.PaymentType, psu *obsdk.PSUContext) (*obsdk.Payment, error) {
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: "/personal/v4/single-sca-payments/" + url.PathEscape(id) + "/status", psu: psu})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.apiErr(opPayStatus, res)
	}
	var sr statusResponse
	if err := json.Unmarshal(res.body, &sr); err != nil || sr.Response.Status == "" {
		return nil, fmt.Errorf("nordea: unreadable payment status (HTTP %d)", res.status)
	}
	var reason string
	for _, m := range sr.Response.TPPMessages {
		if m.Category == "ERROR" {
			reason = m.Code
			if reason == "" {
				reason = m.Text
			}
		}
	}
	return c.toPayment(id, t, sr.Response.Status, reason, res.body)
}

// paymentStatus maps Nordea's payment statuses.
func paymentStatus(s string) (obsdk.PaymentStatus, bool) {
	switch s {
	case "PendingConfirmation", "PendingUserApproval", "UserApprovalFailed", "UserApprovalTimeout", "UserApprovalCancelled", "Unknown":
		return obsdk.PaymentReceived, false
	case "PendingSecondConfirmation":
		return obsdk.PaymentPartiallyAccepted, false
	case "Confirmed":
		return obsdk.PaymentAccepted, false
	case "OnHold":
		return obsdk.PaymentInProgress, false
	case "Paid":
		return obsdk.PaymentCompleted, true
	case "Rejected", "InsufficientFunds", "LimitExceeded":
		return obsdk.PaymentRejected, true
	case "Cancelled", "Stopped", "Deleted":
		return obsdk.PaymentCancelled, true
	}
	return obsdk.PaymentReceived, false
}

func (c *client) toPayment(id string, t obsdk.PaymentType, status, reason string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, ID: id, Type: t})
	if err != nil {
		return nil, err
	}
	st, final := paymentStatus(status)
	return &obsdk.Payment{ID: id, Type: t, Status: st, BankStatus: status, Final: final, Reason: reason, Ref: ref, Raw: raw}, nil
}

func decodeRef(ref string) (*paymentRef, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.ID == "" || strings.ContainsAny(r.ID, "/?#") {
		return nil, fmt.Errorf("%w: not a Nordea payment reference", obsdk.ErrInvalidRequest)
	}
	return &r, nil
}

// PaymentStatus reads a payment's status; no user token is needed.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	r, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	pay, err := c.readStatus(ctx, r.ID, r.Type, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: pay.Raw}, nil
}

// CancelPayment deletes a payment that is not executed yet (in practice a
// future-dated one). It needs the session the payment's last step returned:
// Nordea deletes payments only with the token bought by its auth_code.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	r, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	s := o.Session
	if s == nil || s.AccessToken == "" {
		return nil, fmt.Errorf("%w: Nordea cancels a payment with the session its approval returned (PaymentCallOptions.Session)", obsdk.ErrInvalidRequest)
	}
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	body := map[string]any{"payments": []map[string]string{{"payment_id": r.ID}}}
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodDelete, path: "/personal/v4/single-sca-payments", body: body, bearer: s.AccessToken, psu: o.PSU})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK && res.status != http.StatusNoContent {
		return nil, c.apiErr(opPayCancel, res)
	}
	var dr struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(res.body, &dr) == nil && len(dr.Errors) > 0 {
		return nil, fmt.Errorf("nordea: payment not deleted: %s", dr.Errors[0])
	}
	pay, err := c.readStatus(ctx, r.ID, r.Type, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}
