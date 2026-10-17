package op

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation (PIS API v2): each transfer is created with a client
// token and a detached JWS; the first one opens an authorisation bundle that
// the others join. The user approves the bundle on OP's page, and each
// payment is then submitted with the user's token.

const pisBase = "/payments-psd2/v2"

// Endpoint families.
const (
	kindSEPA      = "sepa-payments"
	kindScheduled = "scheduled-sepa-payments"
	kindForeign   = "foreign-payments"
)

// maxBundle is how many transfers the SDK puts in one authorisation bundle.
// OP documents no limit; this keeps a single approval reviewable.
const maxBundle = 20

// referenceFI is the scheme of a Finnish creditor reference (viitenumero).
const referenceFI = "FI"

// payState is a payment's part of the flow, and (as paymentRef) its Ref.
type payState struct {
	Type            obsdk.PaymentType `json:"type"`
	Kind            string            `json:"kind"`
	AuthorizationID string            `json:"authorization_id"`
	IDs             []string          `json:"ids"`
	Cancel          string            `json:"cancel,omitempty"` // the payment a cancellation flow is for
}

type paymentRef struct {
	Integration     string            `json:"i"`
	Type            obsdk.PaymentType `json:"t"`
	Kind            string            `json:"k"`
	AuthorizationID string            `json:"a"`
	IDs             []string          `json:"ids"`
}

// ---- specs ----

const amountPattern = `^\d{1,13}(\.\d{1,2})?$`

func paymentSpecs() []obsdk.PaymentSpec {
	final := []obsdk.PaymentStatus{obsdk.PaymentCompleted}
	redirect := []string{"redirect"}
	debtor := obsdk.PaymentField{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeIBAN},
		Pattern: `^FI`, Label: "Pay from", Note: "An OP account. Leave empty to let the user pick it on OP's page; the user can change it there either way."}

	sepa := obsdk.PaymentSpec{
		Type: obsdk.PaymentSEPA, Currencies: []string{"EUR"}, MaxTransfers: maxBundle, ExecutionDateMaxDays: 365,
		AuthApproaches: redirect, FinalStatuses: final, Cancellable: true,
		Fields: []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: amountPattern, Label: "Amount", Note: "0.01 to 999 999 999.99 euros."},
			debtor,
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Payee IBAN"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
			{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldOptional, Label: "Payee address",
				Note: "Required when the payee's IBAN is not Finnish. Sent as up to 4 lines of 35 characters."},
			{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{2}$`, Label: "Payee country",
				Note: "Required with an address."},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message",
				Note: "A message or a reference is required."},
			{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{referenceFI, obsdk.ReferenceRF}, Label: "Reference",
				Note:        "Finnish reference (scheme FI, 4 to 20 digits with a check digit) or RF creditor reference. A message or a reference is required.",
				SchemeRules: []obsdk.SchemeRule{{Scheme: referenceFI, Pattern: `^\d{4,20}$`}}},
			{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35, Note: "Sent as payerReference and passed on to the payee's bank."},
			{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date",
				Note: "Makes a scheduled payment, which OP executes on that date and which can be cancelled (with the user's approval) until then."},
		},
		Notes: []string{
			fmt.Sprintf("Up to %d transfers are approved together as one OP authorisation bundle.", maxBundle),
			"OP sends the payment as SEPA Instant when it can (status Credited); otherwise as a SEPA credit transfer (Debited).",
		},
	}

	foreign := obsdk.PaymentSpec{
		Type: obsdk.PaymentCrossBorder, MaxTransfers: maxBundle, AuthApproaches: redirect, FinalStatuses: final, Cancellable: true,
		Fields: []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: amountPattern, Label: "Amount",
				Note: "In the currency of the transfer; euro payments to SEPA countries must be sent as sepa."},
			debtor,
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN, obsdk.SchemeBBAN}, MaxLength: 34, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 35, Label: "Payee name"},
			{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: `^[A-Z0-9]{8}([A-Z0-9]{3})?$`, Label: "Payee bank BIC",
				Note: "Highly recommended; without it, give the clearing system id."},
			{Path: obsdk.FieldCreditorClearing, Use: obsdk.FieldOptional, Label: "Payee bank clearing id", Note: "Only without a BIC."},
			{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldRequired, Label: "Payee address", Note: "Sent as two lines of 35 characters."},
			{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldRequired, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldRequired, MaxItems: 1, MaxLength: 140, Label: "Message"},
			{Path: obsdk.FieldChargeBearer, Use: obsdk.FieldOptional, Options: []obsdk.Option{
				{Value: obsdk.ChargeBearerShared, Label: "Each pays their own bank's fees (default)"},
				{Value: obsdk.ChargeBearerDebtor, Label: "Payer pays all fees"},
			}},
		},
		Notes: []string{"Foreign payments cannot share a bundle with SEPA payments."},
	}
	return []obsdk.PaymentSpec{sepa, foreign}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	for _, s := range paymentSpecs() {
		if s.Type == t {
			return s, nil
		}
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: OP offers no %q payments", obsdk.ErrUnsupported, t)
}

// checkRemittance enforces OP's rule that a SEPA payment has a message or a reference.
func checkRemittance(r obsdk.PaymentRequest) error {
	var issues []obsdk.FieldIssue
	for i, t := range r.Transfers {
		if len(t.Remittance) == 0 && (t.Reference == nil || t.Reference.Value == "") {
			issues = append(issues, obsdk.FieldIssue{Path: obsdk.FieldRemittance, Index: i, Code: obsdk.IssueRequired,
				Message: "a message or a reference is required"})
		}
	}
	if len(issues) > 0 {
		return &obsdk.PaymentValidationError{Issues: issues}
	}
	return nil
}

// ---- request bodies ----

type ibanJSON struct {
	IBAN string `json:"iban"`
}

type sepaPayee struct {
	IBAN    string   `json:"iban"`
	Name    string   `json:"name"`
	Address []string `json:"address,omitempty"`
	Country string   `json:"country,omitempty"`
}

type sepaBody struct {
	AuthorizationID string    `json:"authorizationId,omitempty"`
	AmountEUR       string    `json:"amountEUR"`
	Payee           sepaPayee `json:"payee"`
	Payer           *ibanJSON `json:"payer,omitempty"`
	Message         string    `json:"message,omitempty"`
	Reference       string    `json:"reference,omitempty"`
	PayerReference  string    `json:"payerReference,omitempty"`
	DueDate         string    `json:"dueDate,omitempty"`
}

type foreignBody struct {
	AuthorizationID string `json:"authorizationId,omitempty"`
	DetailsOfCharge string `json:"detailsOfCharges,omitempty"`
	Amount          string `json:"amount"`
	Currency        string `json:"currency"`
	Payee           struct {
		BankAccount struct {
			ID         string `json:"id"`
			SchemeName string `json:"schemeName"`
		} `json:"bankAccount"`
		Name                 string `json:"name"`
		FinancialInstitution struct {
			BIC              string `json:"bic,omitempty"`
			ClearingSystemID string `json:"clearingSystemId,omitempty"`
		} `json:"financialInstitution"`
		ForeignAddress struct {
			AddressLine1 string `json:"addressLine1"`
			AddressLine2 string `json:"addressLine2"`
			Country      string `json:"country,omitempty"`
		} `json:"foreignAddress"`
	} `json:"payee"`
	Payer   *ibanJSON `json:"payer,omitempty"`
	Message string    `json:"message"`
}

// twoDecimals writes an amount the way OP's pattern wants it: no decimals
// or exactly two.
func twoDecimals(d obsdk.Decimal) string {
	s := string(d)
	whole, frac, ok := strings.Cut(s, ".")
	if !ok {
		return s
	}
	switch len(frac) {
	case 0:
		return whole
	case 1:
		return whole + "." + frac + "0"
	}
	return s
}

// addressLines flattens a postal address into lines of at most 35
// characters, at most max of them.
func addressLines(a *obsdk.PostalAddress, max int) []string {
	if a == nil {
		return nil
	}
	lines := append([]string(nil), a.Lines...)
	if len(lines) == 0 {
		street := strings.TrimSpace(a.Street + " " + a.BuildingNumber)
		town := strings.TrimSpace(a.PostCode + " " + a.Town)
		for _, l := range []string{street, town} {
			if l != "" {
				lines = append(lines, l)
			}
		}
	}
	for i, l := range lines {
		if r := []rune(l); len(r) > 35 {
			lines[i] = string(r[:35])
		}
	}
	if len(lines) > max {
		lines = lines[:max]
	}
	return lines
}

func debtorIBAN(r obsdk.PaymentRequest) *ibanJSON {
	if r.Debtor != nil && r.Debtor.Account != nil && r.Debtor.Account.Value != "" {
		return &ibanJSON{IBAN: r.Debtor.Account.Value}
	}
	return nil
}

// buildBody makes the JSON body of one transfer. authorizationID joins the
// bundle the first transfer opened.
func buildBody(r obsdk.PaymentRequest, t obsdk.Transfer, authorizationID string) ([]byte, error) {
	if r.Type == obsdk.PaymentCrossBorder {
		var b foreignBody
		b.AuthorizationID = authorizationID
		b.Amount, b.Currency = twoDecimals(t.Amount.Amount), t.Amount.Currency
		b.Payee.Name = t.Creditor.Name
		b.Payee.BankAccount.ID, b.Payee.BankAccount.SchemeName = t.Creditor.Account.Value, t.Creditor.Account.Scheme
		if ag := t.Creditor.Agent; ag != nil {
			b.Payee.FinancialInstitution.BIC = ag.BIC
			if ag.BIC == "" {
				b.Payee.FinancialInstitution.ClearingSystemID = ag.MemberID
			}
		}
		lines := addressLines(t.Creditor.Address, 2)
		for len(lines) < 2 {
			lines = append(lines, "-") // OP requires both lines
		}
		b.Payee.ForeignAddress.AddressLine1, b.Payee.ForeignAddress.AddressLine2 = lines[0], lines[1]
		if t.Creditor.Address != nil {
			b.Payee.ForeignAddress.Country = t.Creditor.Address.Country
		}
		switch r.ChargeBearer {
		case obsdk.ChargeBearerDebtor:
			b.DetailsOfCharge = "OUR"
		case obsdk.ChargeBearerShared:
			b.DetailsOfCharge = "SHA"
		}
		b.Payer = debtorIBAN(r)
		if len(t.Remittance) > 0 {
			b.Message = t.Remittance[0]
		}
		return json.Marshal(b)
	}
	b := sepaBody{
		AuthorizationID: authorizationID, AmountEUR: twoDecimals(t.Amount.Amount),
		Payee: sepaPayee{IBAN: t.Creditor.Account.Value, Name: t.Creditor.Name}, Payer: debtorIBAN(r),
		PayerReference: t.EndToEndID, DueDate: r.ExecutionDate,
	}
	if a := t.Creditor.Address; a != nil {
		b.Payee.Address, b.Payee.Country = addressLines(a, 4), a.Country
	}
	if len(t.Remittance) > 0 {
		b.Message = t.Remittance[0]
	}
	if t.Reference != nil {
		b.Reference = t.Reference.Value
	}
	return json.Marshal(b)
}

func kindOf(r obsdk.PaymentRequest) string {
	switch {
	case r.Type == obsdk.PaymentCrossBorder:
		return kindForeign
	case r.ExecutionDate != "":
		return kindScheduled
	}
	return kindSEPA
}

// ---- operations ----

type paymentJSON struct {
	AuthorizationID string `json:"authorizationId"`
	PaymentID       string `json:"paymentId"`
	Status          string `json:"status"`
	Payer           struct {
		IBAN string `json:"iban"`
		Name string `json:"name"`
	} `json:"payer"`
}

// InitiatePayment creates the transfers in one authorisation bundle and
// returns the redirect that lets the user approve it. Resume submits them.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Type == obsdk.PaymentSEPA {
		if err := checkRemittance(r); err != nil {
			return nil, err
		}
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: OP only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	if _, _, err := c.alg(); err != nil { // fail on missing signing config before any call
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
	ps := &payState{Type: r.Type, Kind: kindOf(r)}
	var first []byte
	for i, t := range r.Transfers {
		body, err := buildBody(r, t, ps.AuthorizationID)
		if err != nil {
			return nil, err
		}
		sig, err := c.signBody(body)
		if err != nil {
			return nil, err
		}
		res, err := c.do(ctx, req{op: opPayCreate, method: http.MethodPost, path: pisBase + "/" + ps.Kind, raw: body, bearer: cc, psu: psuOrNil(r.PSU),
			header: map[string]string{"x-jws-signature": sig, "x-idempotency-key": transferKey(key, i)}})
		if err == nil && res.status != http.StatusCreated && res.status != http.StatusOK {
			err = c.apiErr(opPayCreate, res)
		}
		var pj paymentJSON
		if err == nil && (json.Unmarshal(res.body, &pj) != nil || pj.PaymentID == "" || pj.AuthorizationID == "") {
			err = fmt.Errorf("op: unreadable payment response (HTTP %d)", res.status)
		}
		if err != nil {
			if ps.AuthorizationID != "" {
				// Don't leave half a bundle behind.
				c.revoke(ctx, cc, ps.AuthorizationID)
			}
			return nil, err
		}
		if i == 0 {
			first = res.body
		}
		ps.AuthorizationID = pj.AuthorizationID
		ps.IDs = append(ps.IDs, pj.PaymentID)
	}

	f := &flow{Phase: phPayment, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Pay: ps}
	if err := c.authorizeURL(f, ps.AuthorizationID, "", "payments"); err != nil {
		return nil, err
	}
	pay, err := c.toPayment(ps, []paymentJSON{{Status: "Unauthorized"}}, first)
	if err != nil {
		return nil, err
	}
	st := redirectStep(f, "Send the user to OP to approve the payment, then pass the callback URL to Resume.")
	st.Payment = pay
	return c.pause(f, st)
}

// transferKey makes one idempotency key per transfer (OP allows 40 characters).
func transferKey(key string, i int) string {
	if i > 0 {
		key += "-" + strconv.Itoa(i)
	}
	if len(key) > 40 {
		key = key[len(key)-40:]
	}
	return key
}

// revoke deletes an unapproved bundle, best effort.
func (c *client) revoke(ctx context.Context, cc, authorizationID string) {
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodDelete, path: pisBase + "/authorizations/" + url.PathEscape(authorizationID), bearer: cc})
	if err != nil || res.status >= 300 {
		c.log.Debug("op: could not revoke payment bundle", "authorization", authorizationID, "err", err)
	}
}

// resumePayment exchanges the callback's code and submits every payment of the bundle.
func (c *client) resumePayment(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	ps := f.Pay
	if in.Callback == "" {
		pay, _ := c.toPayment(ps, []paymentJSON{{Status: "Unauthorized"}}, nil)
		st := redirectStep(f, "Send the user to OP to approve the payment, then pass the callback URL to Resume.")
		st.Payment = pay
		return c.pause(f, st)
	}
	tr, err := c.exchangeCode(ctx, f, in, "payment")
	if err != nil {
		// Report what OP now says about the payment (Rejected when the user declined).
		var pay *obsdk.Payment
		if all, raw, _, rerr := c.readPayments(ctx, ps, psuOrNil(f.PSU)); rerr == nil {
			pay, _ = c.toPayment(ps, all, raw)
		}
		return nil, &obsdk.FlowError{Payment: pay, Err: err}
	}
	var all []paymentJSON
	var raws []json.RawMessage
	for _, id := range ps.IDs {
		// The body is an empty JSON object: without it OP answers 400 VALIDATION.
		res, err := c.do(ctx, req{op: opPaySubmit, method: http.MethodPost, path: pisBase + "/" + ps.Kind + "/" + url.PathEscape(id) + "/submit",
			raw: []byte("{}"), bearer: tr.AccessToken, psu: psuOrNil(f.PSU)})
		if err == nil && res.status != http.StatusOK && res.status != http.StatusCreated {
			err = c.apiErr(opPaySubmit, res)
		}
		if err != nil {
			pay, _ := c.toPayment(ps, append(all, paymentJSON{PaymentID: id, Status: "Authorized"}), nil)
			if rej, ok := err.(*obsdk.PaymentRejectedError); ok {
				rej.Payment = pay
			}
			return nil, &obsdk.FlowError{Payment: pay, Err: err}
		}
		var pj paymentJSON
		if json.Unmarshal(res.body, &pj) != nil || pj.Status == "" {
			return nil, fmt.Errorf("op: unreadable submit response (HTTP %d)", res.status)
		}
		all, raws = append(all, pj), append(raws, res.body)
	}
	raw := rawList(raws)
	pay, err := c.toPayment(ps, all, raw)
	if err != nil {
		return nil, err
	}
	if pay.Status == obsdk.PaymentRejected {
		return nil, &obsdk.FlowError{Payment: pay, Err: &obsdk.PaymentRejectedError{Reason: strings.ToLower(pay.BankStatus), Payment: pay}}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: raw}, nil
}

func rawList(raws []json.RawMessage) []byte {
	if len(raws) == 1 {
		return raws[0]
	}
	b, _ := json.Marshal(raws)
	return b
}

// ---- status ----

// opStatus maps OP's payment statuses. Debited is final: for a SEPA credit
// transfer it is the last status OP reports (Credited only comes with SEPA Instant).
func opStatus(s string) (obsdk.PaymentStatus, bool) {
	switch s {
	case "Unauthorized", "Authorizing":
		return obsdk.PaymentReceived, false
	case "Authorized":
		return obsdk.PaymentAccepted, false
	case "Accepted", "SubmissionPending", "AwaitingDueDate", "AwaitingFunds", "Processing":
		return obsdk.PaymentInProgress, false
	case "Debited", "Credited":
		return obsdk.PaymentCompleted, true
	case "Rejected":
		return obsdk.PaymentRejected, true
	case "Revoked", "Cancelled":
		return obsdk.PaymentCancelled, true
	}
	return obsdk.PaymentReceived, false
}

// rank orders statuses for a bundle summary: the least advanced wins.
var rank = map[obsdk.PaymentStatus]int{
	obsdk.PaymentReceived: 0, obsdk.PaymentAccepted: 1, obsdk.PaymentInProgress: 2, obsdk.PaymentPartiallyAccepted: 3,
	obsdk.PaymentCompleted: 4, obsdk.PaymentCancelled: 5, obsdk.PaymentRejected: 6,
}

// toPayment builds the Payment of a single transfer or sums up a bundle.
func (c *client) toPayment(ps *payState, all []paymentJSON, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, Type: ps.Type, Kind: ps.Kind, AuthorizationID: ps.AuthorizationID, IDs: ps.IDs})
	if err != nil {
		return nil, err
	}
	p := &obsdk.Payment{ID: ps.AuthorizationID, Type: ps.Type, Ref: ref, Raw: raw}
	if len(ps.IDs) == 1 {
		p.ID = ps.IDs[0]
	}
	if len(all) == 0 {
		all = []paymentJSON{{Status: "Unauthorized"}}
	}
	// Several transfers: the least advanced status, or partially accepted
	// when some were refused and some not.
	worst, refused, final := all[0].Status, 0, true
	for _, s := range all {
		st, fin := opStatus(s.Status)
		w, _ := opStatus(worst)
		if rank[st] < rank[w] {
			worst = s.Status
		}
		if st == obsdk.PaymentRejected || st == obsdk.PaymentCancelled {
			refused++
		}
		final = final && fin
	}
	p.BankStatus = worst
	p.Status, p.Final = opStatus(worst)
	if len(all) > 1 && refused > 0 && refused < len(all) {
		p.Status, p.Reason = obsdk.PaymentPartiallyAccepted, fmt.Sprintf("%d of %d transfers refused", refused, len(all))
	}
	p.Final = final
	if all[0].Payer.IBAN != "" {
		p.Debtor = &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: all[0].Payer.IBAN}
	}
	return p, nil
}

func decodeRef(ref string) (*payState, error) {
	var pr paymentRef
	if err := flowstate.Decode(ref, &pr); err != nil || pr.Integration != integrationID || len(pr.IDs) == 0 {
		return nil, fmt.Errorf("%w: not an OP payment reference", obsdk.ErrInvalidRequest)
	}
	switch pr.Kind {
	case kindSEPA, kindScheduled, kindForeign:
	default:
		return nil, fmt.Errorf("%w: not an OP payment reference", obsdk.ErrInvalidRequest)
	}
	return &payState{Type: pr.Type, Kind: pr.Kind, AuthorizationID: pr.AuthorizationID, IDs: pr.IDs}, nil
}

// readPayments reads every payment of a bundle with a client token.
func (c *client) readPayments(ctx context.Context, ps *payState, psu *obsdk.PSUContext) ([]paymentJSON, []byte, *resp, error) {
	cc, err := c.clientToken(ctx, "payments")
	if err != nil {
		return nil, nil, nil, err
	}
	var all []paymentJSON
	var raws []json.RawMessage
	var last *resp
	for _, id := range ps.IDs {
		res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: pisBase + "/" + ps.Kind + "/" + url.PathEscape(id), bearer: cc, psu: psu})
		if err != nil {
			return nil, nil, nil, err
		}
		if res.status != http.StatusOK {
			return nil, nil, nil, c.apiErr(opPayStatus, res)
		}
		var pj paymentJSON
		if json.Unmarshal(res.body, &pj) != nil || pj.Status == "" {
			return nil, nil, nil, fmt.Errorf("op: unreadable payment (HTTP %d)", res.status)
		}
		all, raws, last = append(all, pj), append(raws, res.body), res
	}
	return all, rawList(raws), last, nil
}

// PaymentStatus reads the payment (each transfer of a bundle) with a client token.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	ps, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	all, raw, last, err := c.readPayments(ctx, ps, o.PSU)
	if err != nil {
		return nil, err
	}
	p, err := c.toPayment(ps, all, raw)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *p, Raw: raw, Meta: meta(last)}, nil
}

// ---- cancellation ----

// CancelPayment cancels a payment that is not executed yet. An unapproved
// bundle is revoked at once; an approved payment (in practice a scheduled
// one waiting for its date) needs the user's approval on OP's page, one
// payment at a time.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	ps, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	all, _, _, err := c.readPayments(ctx, ps, o.PSU)
	if err != nil {
		return nil, err
	}
	var open []string
	unapproved := true
	for i, p := range all {
		switch p.Status {
		case "Unauthorized":
		case "Authorized", "Accepted", "AwaitingDueDate", "AwaitingFunds":
			unapproved = false
			open = append(open, ps.IDs[i])
		default:
			unapproved = false
		}
	}
	if unapproved {
		cc, err := c.clientToken(ctx, "payments")
		if err != nil {
			return nil, err
		}
		res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodDelete, path: pisBase + "/authorizations/" + url.PathEscape(ps.AuthorizationID), bearer: cc, psu: o.PSU})
		if err != nil {
			return nil, err
		}
		if res.status >= 300 {
			return nil, c.apiErr(opPayCancel, res)
		}
		return c.cancelDone(ctx, ps, o.PSU)
	}
	switch len(open) {
	case 0:
		return nil, fmt.Errorf("%w: the payment can no longer be cancelled (status %s)", obsdk.ErrInvalidRequest, all[0].Status)
	case 1:
	default:
		return nil, fmt.Errorf("%w: OP cancels one payment per approval; this bundle has %d cancellable transfers", obsdk.ErrUnsupported, len(open))
	}
	redirectURL, err := c.redirectURL(o.RedirectURL)
	if err != nil {
		return nil, err
	}
	cps := *ps
	cps.Cancel = open[0]
	f := &flow{Phase: phCancel, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Pay: &cps}
	if o.PSU != nil {
		f.PSU = *o.PSU
	}
	if err := c.authorizeURL(f, ps.AuthorizationID, cps.Cancel, "payments:delete"); err != nil {
		return nil, err
	}
	pay, err := c.toPayment(ps, all, nil)
	if err != nil {
		return nil, err
	}
	st := redirectStep(f, "Send the user to OP to approve the cancellation, then pass the callback URL to Resume.")
	st.Payment = pay
	return c.pause(f, st)
}

// resumeCancel deletes the payment with the token the user's approval gave.
func (c *client) resumeCancel(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	ps := f.Pay
	if in.Callback == "" {
		return c.pause(f, redirectStep(f, "Send the user to OP to approve the cancellation, then pass the callback URL to Resume."))
	}
	tr, err := c.exchangeCode(ctx, f, in, "cancellation")
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opPayCancel, method: http.MethodDelete, path: pisBase + "/" + ps.Kind + "/" + url.PathEscape(ps.Cancel), bearer: tr.AccessToken, psu: psuOrNil(f.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status >= 300 {
		return nil, c.apiErr(opPayCancel, res)
	}
	return c.cancelDone(ctx, ps, psuOrNil(f.PSU))
}

func (c *client) cancelDone(ctx context.Context, ps *payState, psu *obsdk.PSUContext) (*obsdk.Step, error) {
	all, raw, _, err := c.readPayments(ctx, ps, psu)
	if err != nil {
		return nil, err
	}
	pay, err := c.toPayment(ps, all, raw)
	if err != nil {
		return nil, err
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: raw}, nil
}
