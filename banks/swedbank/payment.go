package swedbank

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

// Payments are Berlin Group style: POST {base}/payments/{product} with the
// user's token, then the approval the bank steers to (redirect or app), then
// the payment status.
//
// Products and body fields come from Swedbank's v3/v4 API as used by public
// clients; the v5 payment swagger has not been read. The SE sandbox accepted
// domestic, Bankgiro (OCR) and international payments with app approval, and
// cancelled a future-dated one (2026-10-14). Baltic products and field
// lengths (Berlin Group defaults) are unverified.

const (
	opPayment = "payment"

	phPayPost      = "pay_post"
	phPayDebtor    = "pay_debtor"
	phPayCheck     = "pay_check"
	phCancelDelete = "cancel_delete"
	phCancelCheck  = "cancel_check"

	productSEDomestic = "se-domestic-credit-transfers"
	productSEIntl     = "se-international-credit-transfers"
	productSEPA       = "sepa-credit-transfers"
	productSEPAInst   = "instant-sepa-credit-transfers"
	productCrossB     = "cross-border-credit-transfers"
)

// payFlow is the serialized state of a payment or its cancellation.
type payFlow struct {
	Type       obsdk.PaymentType `json:"type"`
	Product    string            `json:"product"`
	Body       json.RawMessage   `json:"body,omitempty"` // built at initiation, sent once the user is logged in
	NeedDebtor bool              `json:"need_debtor,omitempty"`
	ID         string            `json:"id,omitempty"`
	Status     string            `json:"status,omitempty"` // bank transactionStatus
	StatusPath string            `json:"status_path,omitempty"`
	SelfPath   string            `json:"self_path,omitempty"`
	Raw        json.RawMessage   `json:"raw,omitempty"`
}

// paymentRef is what Payment.Ref holds. It carries no tokens.
type paymentRef struct {
	Integration string            `json:"i"`
	Product     string            `json:"p"`
	Type        obsdk.PaymentType `json:"t"`
	ID          string            `json:"id"`
	StatusPath  string            `json:"s,omitempty"`
	SelfPath    string            `json:"self,omitempty"`
}

// payment returns the payment once the bank created it, else nil.
func (p *payFlow) payment() *obsdk.Payment {
	if p == nil || p.ID == "" {
		return nil
	}
	ref, _ := flowstate.Encode(paymentRef{Integration: integrationID, Product: p.Product, Type: p.Type, ID: p.ID, StatusPath: p.StatusPath, SelfPath: p.SelfPath})
	st, final := bgstatus.Payment(p.Status)
	return &obsdk.Payment{ID: p.ID, Type: p.Type, Status: st, BankStatus: p.Status, Final: final, Ref: ref, Raw: p.Raw}
}

// ---- specs ----

func paymentSpecs() []obsdk.PaymentSpec {
	baltic := []obsdk.Country{"EE", "LV", "LT"}
	se := []obsdk.Country{"SE"}
	base := obsdk.PaymentSpec{
		MaxTransfers: 1, AuthApproaches: []string{"redirect", "decoupled"}, StatusNeedsSession: true,
		FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
		Notes: []string{
			"Field lengths are Berlin Group defaults, not published by Swedbank.",
			"A new login invalidates the user's other Swedbank token; pass the AIS session in PaymentRequest.Session to keep one login.",
			"In Sweden the payee may need to be on the user's recipient list.",
		},
	}
	debtor := func(schemes ...string) obsdk.PaymentField {
		return obsdk.PaymentField{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: schemes, Label: "Pay from",
			Note: "With redirect approval the user can pick the account at the bank; with app approval it is asked for (an input Step)."}
	}
	remit := obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message"}
	date := obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date", Note: "Future-dated payments can be cancelled until executed."}

	domestic := base
	domestic.Type, domestic.Countries, domestic.Currencies, domestic.Cancellable = obsdk.PaymentDomestic, se, []string{"SEK"}, true
	domestic.Fields = []obsdk.PaymentField{
		debtor(obsdk.SchemeBBAN, obsdk.SchemeIBAN),
		{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeIBAN, obsdk.SchemeBankgiro, obsdk.SchemePlusgiro},
			Label: "Payee account", SchemeRules: []obsdk.SchemeRule{
				{Scheme: obsdk.SchemeBBAN, Label: "Clearing and account number", Note: "Clearing number + account number."},
				{Scheme: obsdk.SchemeBankgiro, Label: "Bankgiro number", Note: "7 or 8 digits, e.g. 5051-6905."},
				{Scheme: obsdk.SchemePlusgiro, Label: "Plusgiro number", Note: "2 to 8 digits, e.g. 1234-4."},
			}},
		{Path: obsdk.FieldCreditorName, Use: obsdk.FieldOptional, MaxLength: 70, Label: "Payee name"},
		{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceOCR}, Label: "OCR number",
			OnlyWith: &obsdk.FieldCondition{Path: obsdk.FieldCreditorAccount, Schemes: []string{obsdk.SchemeBankgiro, obsdk.SchemePlusgiro}}},
		remit, date,
	}
	domestic.Notes = append(append([]string(nil), base.Notes...), "For Bankgiro / Plusgiro payees send either an OCR reference or a message, as the payee's agreement requires.")

	seIntl := base
	seIntl.Type, seIntl.Countries = obsdk.PaymentCrossBorder, se
	seIntl.Fields = []obsdk.PaymentField{
		{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeBBAN, obsdk.SchemeIBAN}, Label: "Pay from"},
		{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN, obsdk.SchemeBBAN}, Label: "Payee account"},
		{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
		{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldRequired, Label: "Payee address"},
		{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldRequired, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
		{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: `^[A-Z0-9]{8}([A-Z0-9]{3})?$`, Label: "Payee bank BIC"},
		{Path: obsdk.FieldRemittance, Use: obsdk.FieldRequired, MaxItems: 1, MaxLength: 140, Label: "Message"},
		{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldRequired, Options: []obsdk.Option{
			{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees (OUR)"},
			{Value: obsdk.ChargeBearerShared, Label: "Each pays their own bank (SHA)"},
		}},
		date,
	}

	sepa := base
	sepa.Type, sepa.Countries, sepa.Currencies, sepa.Cancellable = obsdk.PaymentSEPA, baltic, []string{"EUR"}, true
	sepa.Fields = []obsdk.PaymentField{
		debtor(obsdk.SchemeIBAN),
		{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Payee IBAN"},
		{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
		{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: `^[A-Z0-9]{8}([A-Z0-9]{3})?$`, Label: "Payee bank BIC"},
		{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35, Note: "Generated when empty."},
		remit, date,
	}
	inst := sepa
	inst.Type, inst.Cancellable = obsdk.PaymentSEPAInstant, false
	inst.Fields = append([]obsdk.PaymentField(nil), sepa.Fields[:len(sepa.Fields)-1]...) // no execution date
	inst.Notes = append(append([]string(nil), base.Notes...), "The user's own instant-payment limits apply.")

	cross := base
	cross.Type, cross.Countries = obsdk.PaymentCrossBorder, baltic
	cross.Fields = []obsdk.PaymentField{
		debtor(obsdk.SchemeIBAN),
		{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Payee IBAN"},
		{Path: obsdk.FieldCreditorName, Use: obsdk.FieldOptional, MaxLength: 70, Label: "Payee name"},
		{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: `^[A-Z0-9]{8}([A-Z0-9]{3})?$`, Label: "Payee bank BIC"},
		remit, date,
	}
	return []obsdk.PaymentSpec{domestic, seIntl, sepa, inst, cross}
}

var products = map[obsdk.PaymentType]map[bool]string{ // type -> baltic? -> product
	obsdk.PaymentDomestic:    {false: productSEDomestic},
	obsdk.PaymentCrossBorder: {false: productSEIntl, true: productCrossB},
	obsdk.PaymentSEPA:        {true: productSEPA},
	obsdk.PaymentSEPAInstant: {true: productSEPAInst},
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, string, error) {
	product := products[t][isBaltic(c.target.Country)]
	for _, s := range paymentSpecs() {
		if s.Type == t && product != "" {
			for _, x := range s.Countries {
				if x == c.target.Country {
					return s, product, nil
				}
			}
		}
	}
	return obsdk.PaymentSpec{}, "", fmt.Errorf("%w: Swedbank offers no %q payments in %s", obsdk.ErrUnsupported, t, c.target.Country)
}

// ---- request body ----

func accountRefJSON(id obsdk.Identifier) map[string]string {
	switch id.Scheme {
	case obsdk.SchemeIBAN:
		return map[string]string{"iban": id.Value}
	case obsdk.SchemeBankgiro:
		return map[string]string{"bban": "BG " + id.Value}
	case obsdk.SchemePlusgiro:
		return map[string]string{"bban": "PG " + id.Value}
	}
	return map[string]string{"bban": id.Value}
}

func (c *client) paymentBody(r obsdk.PaymentRequest, product string) map[string]any {
	t := r.Transfers[0]
	b := map[string]any{
		"instructedAmount": map[string]string{"amount": string(t.Amount.Amount), "currency": t.Amount.Currency},
		"creditorAccount":  accountRefJSON(t.Creditor.Account),
	}
	if r.Debtor != nil && r.Debtor.Account != nil && r.Debtor.Account.Value != "" {
		b["debtorAccount"] = accountRefJSON(*r.Debtor.Account)
	}
	if len(t.Remittance) > 0 && t.Remittance[0] != "" {
		b["remittanceInformationUnstructured"] = t.Remittance[0]
	}
	if t.Creditor.Agent != nil && t.Creditor.Agent.BIC != "" {
		b["creditorAgent"] = t.Creditor.Agent.BIC
	}
	switch product {
	case productSEDomestic:
		if t.Creditor.Name != "" {
			b["creditorFriendlyName"] = t.Creditor.Name
		}
		if t.Reference != nil && t.Reference.Value != "" {
			b["remittanceInformationStructured"] = map[string]string{"reference": t.Reference.Value, "referenceType": "OCR"}
		}
		if r.ExecutionDate != "" {
			b["executionDate"] = r.ExecutionDate
		}
	case productSEIntl:
		b["creditorName"] = t.Creditor.Name
		if a := t.Creditor.Address; a != nil {
			// One free-text line: the sandbox rejects structured addresses
			// with "bad address format" (seen 2026-10-14).
			b["creditorAddress"] = addressText(a)
		}
		if t.Creditor.Agent != nil && t.Creditor.Agent.BIC != "" {
			delete(b, "creditorAgent")
			b["bic"] = t.Creditor.Agent.BIC
		}
		b["chargeBearer"] = map[string]string{obsdk.ChargeBearerDebtor: "OUR", obsdk.ChargeBearerShared: "SHA"}[r.ChargeBearer]
		b["priority"] = "NORMAL"
		if r.ExecutionDate != "" {
			b["executionDate"] = r.ExecutionDate
		}
	default: // SEPA, instant SEPA, cross-border (Berlin Group names)
		if t.Creditor.Name != "" {
			b["creditorName"] = t.Creditor.Name
		}
		e2e := t.EndToEndID
		if e2e == "" && product != productCrossB {
			e2e = strings.ReplaceAll(c.cfg.ID(obsdk.IDRequest), "-", "")
			if len(e2e) > 35 {
				e2e = e2e[:35]
			}
		}
		if e2e != "" {
			b["endToEndIdentification"] = e2e
		}
		if r.ExecutionDate != "" {
			b["requestedExecutionDate"] = r.ExecutionDate
		}
	}
	return b
}

// addressText writes an address as one line: "street number, postcode town, country".
func addressText(a *obsdk.PostalAddress) string {
	join := func(sep string, parts ...string) string {
		var out []string
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return strings.Join(out, sep)
	}
	return join(", ", join(", ", a.Lines...), join(" ", a.Street, a.BuildingNumber), join(" ", a.PostCode, a.Town), a.Country)
}

// ---- initiation ----

// InitiatePayment logs the user in (unless PaymentRequest.Session can be
// reused), creates the payment and drives its approval.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, product, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.PSU.IP == "" || r.PSU.UserAgent == "" {
		return nil, fmt.Errorf("%w: PSU.IP and PSU.UserAgent are required (Swedbank needs them to initiate payments)", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or PaymentRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	method := r.Method
	if method == "" {
		method = methodRedirect
	}
	if method != methodRedirect && method != methodDecoupled {
		return nil, fmt.Errorf("%w: unknown method %q (want redirect or decoupled)", obsdk.ErrInvalidRequest, method)
	}
	body, err := json.Marshal(c.paymentBody(r, product))
	if err != nil {
		return nil, err
	}
	f := &flow{
		Goal: goalPayment, Phase: phStart, Method: method, PSU: r.PSU, RedirectURL: redirectURL, Language: r.Language,
		Values: map[string]string{},
		Pay:    &payFlow{Type: r.Type, Product: product, Body: body, NeedDebtor: method == methodDecoupled && (r.Debtor == nil || r.Debtor.Account == nil)},
	}
	for k, v := range r.Values {
		f.Values[k] = v
	}
	if r.Session != nil {
		s, err := c.usableSession(ctx, r.Session)
		if err != nil {
			return nil, err
		}
		f.Session, f.Phase = s, phPayPost
		if v := s.Meta["auth_method"]; v != "" && f.Values["auth_method"] == "" {
			f.Values["auth_method"] = v
		}
	}
	return c.run(ctx, f, obsdk.StepInput{})
}

// usableSession returns a copy of s with a valid token, refreshing it when
// it has expired.
func (c *client) usableSession(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if !s.AccessExpired(c.now()) {
		return s.Clone(), nil
	}
	return c.Refresh(ctx, s)
}

// payDebtor asks which account to pay from (app approval cannot let the user
// pick it at the bank). With a data consent the choice is a list.
func (c *client) payDebtor(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	if v := f.Values["debtor_account"]; v != "" {
		var body map[string]any
		if err := json.Unmarshal(f.Pay.Body, &body); err != nil {
			return nil, false, err
		}
		scheme := obsdk.SchemeBBAN
		if len(v) >= 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z' {
			scheme = obsdk.SchemeIBAN
		}
		body["debtorAccount"] = accountRefJSON(obsdk.Identifier{Scheme: scheme, Value: v})
		b, err := json.Marshal(body)
		if err != nil {
			return nil, false, err
		}
		f.Pay.Body, f.Pay.NeedDebtor, f.Phase = b, false, phPayPost
		return nil, true, nil
	}
	field := obsdk.Field{Key: "debtor_account", Label: "Account to pay from (IBAN or clearing + account number)", Kind: obsdk.FieldText, Required: true}
	if _, ok := f.Session.Consents[kindDetailed]; ok {
		if accs, _, _, err := c.listAccounts(ctx, f.Session, kindDetailed, &f.PSU); err == nil && len(accs) > 0 {
			field.Kind, field.Label = obsdk.FieldSelect, "Account to pay from"
			for _, a := range accs {
				if ref := accountRef(a); ref != "" {
					label := a.Name
					if label == "" {
						label = ref
					}
					field.Options = append(field.Options, obsdk.Option{Value: ref, Label: label})
				}
			}
		}
	}
	return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "Which account should the payment be made from?",
		Fields: []obsdk.Field{field}}, false, nil
}

type paymentCreated struct {
	ID     string          `json:"paymentId"`
	Status string          `json:"transactionStatus"`
	Links  map[string]link `json:"_links"`
	Chosen *authObject     `json:"chosenScaMethod"`
}

func (c *client) paymentPath(product, id string) string {
	return c.apiBase() + "/payments/" + product + "/" + url.PathEscape(id)
}

func (c *client) payPost(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	pf := f.Pay
	if pf.NeedDebtor {
		f.Phase = phPayDebtor
		return nil, true, nil
	}
	hdr := c.tppRedirectHeaders(f)
	hdr["TPP-Nok-Redirect-URI"] = f.RedirectURL
	r, err := c.callAuthed(ctx, f.Session, req{op: opPayment, method: http.MethodPost, path: c.apiBase() + "/payments/" + pf.Product,
		body: pf.Body, header: hdr}, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusCreated && r.status != http.StatusOK {
		return nil, false, c.apiErr(opPayment, r)
	}
	var b paymentCreated
	if err := json.Unmarshal(r.body, &b); err != nil || b.ID == "" {
		return nil, false, fmt.Errorf("swedbank: unreadable payment response (HTTP %d)", r.status)
	}
	pf.ID, pf.Status, pf.Raw, pf.Body = b.ID, b.Status, r.body, nil
	pf.SelfPath = b.Links["self"].Href
	if pf.SelfPath == "" {
		pf.SelfPath = c.paymentPath(pf.Product, pf.ID)
	}
	pf.StatusPath = b.Links["status"].Href
	if pf.StatusPath == "" {
		pf.StatusPath = pf.SelfPath + "/status"
	}
	if b.Status == "RJCT" {
		return nil, false, &obsdk.PaymentRejectedError{Reason: "rejected_at_initiation", Err: fmt.Errorf("%s", tppSummary(parseTPP(r.body)))}
	}
	sca := &scaFlow{Purpose: "approve the payment", Subject: "the payment", Op: opPayment, After: phPayCheck, PollAfterRedirect: true}
	sca.scaLinks(b.Links)
	if b.Chosen != nil {
		sca.ChosenMethod = b.Chosen.ID
	}
	if sca.RedirectURL == "" && sca.StartAuth == "" && sca.SelectPath == "" && sca.ScaPath == "" {
		f.Phase = phPayCheck // no approval asked for
		return nil, true, nil
	}
	return startSCA(f, sca)
}

// readStatus reads the payment's transactionStatus into f.Pay.
func (c *client) readStatus(ctx context.Context, s *obsdk.Session, pf *payFlow, psu *obsdk.PSUContext) error {
	r, err := c.callAuthed(ctx, s, req{op: opPayment, method: http.MethodGet, path: pf.StatusPath}, psu)
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return c.apiErr(opPayment, r)
	}
	var b struct {
		Status string `json:"transactionStatus"`
	}
	if err := json.Unmarshal(r.body, &b); err != nil || b.Status == "" {
		return fmt.Errorf("swedbank: unreadable payment status")
	}
	pf.Status, pf.Raw = b.Status, r.body
	return nil
}

// payCheck confirms the outcome with the payment status: Swedbank advises
// never to rely on the callback or the approval status alone.
func (c *client) payCheck(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	if err := c.readStatus(ctx, f.Session, f.Pay, &f.PSU); err != nil {
		return nil, false, err
	}
	switch f.Pay.Status {
	case "RCVD":
		// Approved but not yet picked up; ask again shortly.
		return waitStep(f, false, pollInterval), false, nil
	case "RJCT":
		return nil, false, &obsdk.PaymentRejectedError{Reason: "rejected", Err: fmt.Errorf("%s", tppSummary(parseTPP(f.Pay.Raw)))}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: f.Pay.payment(), Raw: f.Pay.Raw}, false, nil
}

// ---- status and cancellation ----

func decodeRef(ref string) (paymentRef, error) {
	var pr paymentRef
	if err := flowstate.Decode(ref, &pr); err != nil || pr.Integration != integrationID || pr.ID == "" {
		return pr, fmt.Errorf("%w: not a Swedbank payment reference", obsdk.ErrInvalidRequest)
	}
	return pr, nil
}

func (pr paymentRef) flow() *payFlow {
	return &payFlow{Type: pr.Type, Product: pr.Product, ID: pr.ID, StatusPath: pr.StatusPath, SelfPath: pr.SelfPath}
}

// PaymentStatus reads a payment with the user's session (opts.Session).
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	pr, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	if o.Session == nil {
		return nil, fmt.Errorf("%w: Swedbank reads payments with the user's session (PaymentCallOptions.Session)", obsdk.ErrInvalidRequest)
	}
	pf := pr.flow()
	if err := c.readStatus(ctx, o.Session, pf, o.PSU); err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pf.payment(), Raw: pf.Raw}, nil
}

// CancelPayment deletes a payment that has not been executed. The bank may
// ask the user to approve the cancellation.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	pr, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	if o.Session == nil {
		return nil, fmt.Errorf("%w: Swedbank cancels payments with the user's session (PaymentCallOptions.Session)", obsdk.ErrInvalidRequest)
	}
	s, err := c.usableSession(ctx, o.Session)
	if err != nil {
		return nil, err
	}
	redirectURL := o.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	method := o.Method
	if method == "" {
		method = methodRedirect
	}
	f := &flow{Goal: goalCancel, Phase: phCancelDelete, Method: method, RedirectURL: redirectURL, Session: s, Values: map[string]string{}, Pay: pr.flow()}
	if o.PSU != nil {
		f.PSU = *o.PSU
	}
	if v := s.Meta["auth_method"]; v != "" {
		f.Values["auth_method"] = v
	}
	return c.run(ctx, f, obsdk.StepInput{})
}

func (c *client) cancelDelete(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	pf := f.Pay
	r, err := c.callAuthed(ctx, f.Session, req{op: opPayment, method: http.MethodDelete, path: pf.SelfPath, header: c.tppRedirectHeaders(f)}, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	switch r.status {
	case http.StatusNoContent:
		f.Phase = phCancelCheck
		return nil, true, nil
	case http.StatusOK, http.StatusAccepted:
	default:
		return nil, false, c.apiErr(opPayment, r)
	}
	var b struct {
		Status string          `json:"transactionStatus"`
		Links  map[string]link `json:"_links"`
	}
	_ = json.Unmarshal(r.body, &b)
	if b.Status != "" {
		pf.Status, pf.Raw = b.Status, r.body
	}
	sca := &scaFlow{Purpose: "approve the cancellation", Subject: "the cancellation", Op: opPayment, After: phCancelCheck, PollAfterRedirect: true}
	sca.scaLinks(b.Links)
	if h := b.Links["startCancellationAuthorisation"].Href; h != "" {
		sca.StartAuth = h
	}
	if sca.RedirectURL == "" && sca.StartAuth == "" && sca.SelectPath == "" && sca.ScaPath == "" {
		f.Phase = phCancelCheck
		return nil, true, nil
	}
	return startSCA(f, sca)
}

func (c *client) cancelCheck(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	if err := c.readStatus(ctx, f.Session, f.Pay, &f.PSU); err != nil {
		return nil, false, err
	}
	if f.Pay.Status != "CANC" {
		return nil, false, fmt.Errorf("swedbank: the bank did not cancel the payment (status %s)", f.Pay.Status)
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: f.Pay.payment(), Raw: f.Pay.Raw}, false, nil
}
