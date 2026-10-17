package bunq

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation: a draft payment on one of the user's accounts, created
// with the session of an earlier Connect. bunq pushes it to the bunq app,
// where the user accepts or rejects it; the SDK polls its status. An
// accepted draft becomes a regular payment at once.

const (
	phPayWait = "payment_wait"

	// pollEvery is how long a payment Step asks the caller to wait between
	// status reads (bunq allows about one GET per second per endpoint).
	pollEvery = 5 * time.Second

	// Draft payment statuses.
	draftPending  = "PENDING"
	draftAccepted = "ACCEPTED"
	draftRejected = "REJECTED"
	draftExpired  = "EXPIRED"
	// draftAcceptedOld is accepted but not yet turned into a payment (an old status bunq still lists).
	draftAcceptedOld = "DEPRECATED_ACCEPTED_PENDING_PAYMENT"
)

// payFlow is the serialized state of a payment waiting for the user's
// approval. It holds the session token (not the long-lived access token) to
// read the draft's status.
type payFlow struct {
	Phase   string            `json:"phase"`
	Type    obsdk.PaymentType `json:"type"`
	User    string            `json:"user"`
	Account string            `json:"account"`
	Draft   string            `json:"draft"`
	Token   string            `json:"token"`
	Expires int64             `json:"expires,omitempty"`
}

// paymentRef is what Payment.Ref holds: enough to read or cancel the draft
// with the user's session.
type paymentRef struct {
	Integration string            `json:"i"`
	User        string            `json:"u"`
	Account     string            `json:"a"`
	Draft       string            `json:"d"`
	Type        obsdk.PaymentType `json:"t"`
}

// ---- spec ----

func paymentSpecs() []obsdk.PaymentSpec {
	return []obsdk.PaymentSpec{{
		Type: obsdk.PaymentSEPA, Currencies: []string{"EUR"}, MaxTransfers: 1,
		AuthApproaches: []string{"decoupled"}, Cancellable: true, StatusNeedsSession: true,
		FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
		Fields: []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,9}(\.\d{1,2})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Label: "Pay from",
				Note: "One of the accounts the user shared at Connect."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, MaxLength: 34, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 140, Label: "Payee name"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Description"},
		},
		Notes: []string{
			"Needs the session of an earlier Connect (PaymentRequest.Session, and PaymentCallOptions.Session for status and cancel).",
			"The user approves the payment in the bunq app; bunq sends it as a SEPA credit transfer, or within bunq when the payee banks there.",
			"Cancelling withdraws a draft the user has not answered yet; bunq then reports it as REJECTED.",
		},
	}}
}

// ---- initiate ----

type draftEntry struct {
	Amount       amountJSON  `json:"amount"`
	Counterparty pointerJSON `json:"counterparty_alias"`
	Description  string      `json:"description"`
}

type draftBody struct {
	Status   string       `json:"status"`
	Entries  []draftEntry `json:"entries"`
	Accepts  int          `json:"number_of_required_accepts"`
	Previous string       `json:"previous_updated_timestamp,omitempty"`
}

// InitiatePayment creates a draft payment on the debtor account and returns
// a wait Step while the user approves it in the bunq app.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, r.Type)
	if !ok {
		return nil, fmt.Errorf("%w: bunq offers no %q payments", obsdk.ErrUnsupported, r.Type)
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "decoupled" {
		return nil, fmt.Errorf("%w: bunq payments are approved in the bunq app (method decoupled)", obsdk.ErrInvalidRequest)
	}
	s := r.Session
	if s == nil {
		return nil, fmt.Errorf("%w: bunq payments need the session of an earlier Connect (PaymentRequest.Session)", obsdk.ErrInvalidRequest)
	}
	accs, _, err := c.listAccounts(ctx, s)
	if err != nil {
		return nil, err
	}
	debtor := r.Debtor.Account.Value // validated: upper case, no spaces
	var account string
	for _, a := range accs {
		for _, id := range a.Identifiers {
			if id.Value == debtor {
				account = a.ID
			}
		}
	}
	if account == "" {
		return nil, &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: obsdk.FieldDebtorAccount, Index: -1, Code: obsdk.IssueInvalid,
			Message: "is not one of the accounts the user shared"}}}
	}
	t := r.Transfers[0]
	e := draftEntry{
		Amount:       amountJSON{Value: string(t.Amount.Amount), Currency: t.Amount.Currency},
		Counterparty: pointerJSON{Type: "IBAN", Value: t.Creditor.Account.Value, Name: t.Creditor.Name},
	}
	if len(t.Remittance) > 0 {
		e.Description = t.Remittance[0]
	}
	body, err := json.Marshal(draftBody{Status: draftPending, Entries: []draftEntry{e}, Accepts: 1})
	if err != nil {
		return nil, err
	}
	p := userPath(s) + "/monetary-account/" + account + "/draft-payment"
	res, err := c.userCall(ctx, s, req{op: opPayment, method: http.MethodPost, path: p, body: body})
	if err != nil {
		return nil, paymentErr(err)
	}
	id, err := createdID(res.body)
	if err != nil {
		return nil, err
	}
	pf := &payFlow{Phase: phPayWait, Type: r.Type, User: s.Meta[metaUserID], Account: account, Draft: id, Token: s.AccessToken}
	if s.AccessExpiresAt != nil {
		pf.Expires = s.AccessExpiresAt.Unix()
	}
	pay, err := c.toPayment(pf, draftPending, nil, debtor, res.body)
	if err != nil {
		return nil, err
	}
	return c.pausePayment(pf, pay)
}

// paymentErr: bunq refuses a payment it cannot make with a 400 and a
// sentence ("Account doesn't have enough money to complete the payment.").
func paymentErr(err error) error {
	e, ok := err.(*obsdk.APIError)
	if !ok || e.Status != http.StatusBadRequest {
		return err
	}
	t := strings.ToLower(e.Text)
	switch {
	case strings.Contains(t, "enough money"), strings.Contains(t, "insufficient"):
		return &obsdk.PaymentRejectedError{Reason: "insufficient_funds", Err: e}
	case strings.Contains(t, "limit"):
		return &obsdk.PaymentRejectedError{Reason: "limit_exceeded", Err: e}
	}
	return err
}

func (c *client) pausePayment(pf *payFlow, pay *obsdk.Payment) (*obsdk.Step, error) {
	st := &obsdk.Step{Kind: obsdk.StepWait, NeedsUser: true, WaitFor: pollEvery, Payment: pay,
		Message:   "The user approves the payment in the bunq app. Call Resume after WaitFor to check.",
		Challenge: &obsdk.Challenge{Text: "Open the bunq app and accept the payment request."}}
	s, err := flowstate.Encode(pf)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// flowSession is the minimal session a payment flow reads the draft with.
func (c *client) flowSession(pf *payFlow) *obsdk.Session {
	s := &obsdk.Session{Bank: bankKey, Integration: integrationID, Env: c.cfg.Env, AccessToken: pf.Token,
		Meta: map[string]string{metaUserID: pf.User}}
	if pf.Expires > 0 {
		t := time.Unix(pf.Expires, 0).UTC()
		s.AccessExpiresAt = &t
	}
	return s
}

// resumePayment reads the draft: still pending means wait again.
func (c *client) resumePayment(ctx context.Context, pf *payFlow) (*obsdk.Step, error) {
	pay, _, err := c.readDraft(ctx, c.flowSession(pf), pf)
	if err != nil {
		return nil, err
	}
	switch pay.BankStatus {
	case draftPending:
		return c.pausePayment(pf, pay)
	case draftRejected:
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("the user rejected the payment in the bunq app")}
	case draftExpired:
		return nil, &obsdk.FlowError{Payment: pay, Err: authFailed("the payment request expired before the user answered it")}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}

// ---- status and cancel ----

type draftJSON struct {
	ID      json.Number `json:"id"`
	Status  string      `json:"status"`
	Updated string      `json:"updated"`
	Entries []struct {
		Alias labelJSON `json:"alias"`
	} `json:"entries"`
	Object map[string]json.RawMessage `json:"object"` // {"Payment": {...}} once accepted
}

func (c *client) readDraft(ctx context.Context, s *obsdk.Session, pf *payFlow) (*obsdk.Payment, *draftJSON, error) {
	p := "/user/" + url.PathEscape(pf.User) + "/monetary-account/" + url.PathEscape(pf.Account) + "/draft-payment/" + url.PathEscape(pf.Draft)
	res, err := c.userCall(ctx, s, req{op: opPayStatus, path: p})
	if err != nil {
		return nil, nil, err
	}
	e, err := parseEnvelope(res.body)
	if err != nil {
		return nil, nil, err
	}
	var d draftJSON
	if raw := e.first("DraftPayment"); raw == nil || json.Unmarshal(raw, &d) != nil || d.Status == "" {
		return nil, nil, fmt.Errorf("bunq: unreadable draft payment")
	}
	debtor := ""
	if len(d.Entries) > 0 {
		debtor = d.Entries[0].Alias.IBAN
	}
	pay, err := c.toPayment(pf, d.Status, d.Object, debtor, res.body)
	return pay, &d, err
}

// draftStatus maps a draft's status. An accepted draft that already became a
// payment is booked on the account: bunq executes it at once.
func draftStatus(status string, object map[string]json.RawMessage) (obsdk.PaymentStatus, bool, string) {
	switch status {
	case draftPending:
		return obsdk.PaymentReceived, false, ""
	case draftAccepted, draftAcceptedOld:
		if object["Payment"] != nil || object["PaymentBatch"] != nil {
			return obsdk.PaymentCompleted, true, ""
		}
		return obsdk.PaymentAccepted, false, ""
	case draftRejected:
		return obsdk.PaymentRejected, true, "rejected" // by the user in the app, or withdrawn by CancelPayment
	case draftExpired:
		return obsdk.PaymentRejected, true, "expired"
	}
	return obsdk.PaymentReceived, false, ""
}

func (c *client) toPayment(pf *payFlow, status string, object map[string]json.RawMessage, debtor string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, User: pf.User, Account: pf.Account, Draft: pf.Draft, Type: pf.Type})
	if err != nil {
		return nil, err
	}
	st, final, reason := draftStatus(status, object)
	pay := &obsdk.Payment{ID: pf.Draft, Type: pf.Type, Status: st, BankStatus: status, Final: final, Reason: reason, Ref: ref, Raw: raw}
	if debtor != "" {
		pay.Debtor = &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: debtor}
	}
	return pay, nil
}

func decodeRef(ref string, s *obsdk.Session) (*payFlow, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.Draft == "" || r.Account == "" || r.User == "" {
		return nil, fmt.Errorf("%w: not a bunq payment reference", obsdk.ErrInvalidRequest)
	}
	if s == nil {
		return nil, fmt.Errorf("%w: bunq reads payments with the user's session (PaymentCallOptions.Session)", obsdk.ErrInvalidRequest)
	}
	if s.Meta[metaUserID] != r.User {
		return nil, fmt.Errorf("%w: the payment belongs to another bunq user than the session", obsdk.ErrInvalidRequest)
	}
	return &payFlow{Type: r.Type, User: r.User, Account: r.Account, Draft: r.Draft}, nil
}

// PaymentStatus reads the draft payment with the user's session.
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	pf, err := decodeRef(ref, o.Session)
	if err != nil {
		return nil, err
	}
	pay, _, err := c.readDraft(ctx, o.Session, pf)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: pay.Raw}, nil
}

// CancelPayment withdraws a draft the user has not answered yet. bunq has no
// cancelled status: the creator sets it to REJECTED, which is what later
// status reads show.
func (c *client) CancelPayment(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	pf, err := decodeRef(ref, o.Session)
	if err != nil {
		return nil, err
	}
	pay, d, err := c.readDraft(ctx, o.Session, pf)
	if err != nil {
		return nil, err
	}
	if d.Status != draftPending {
		return nil, fmt.Errorf("%w: only a payment the user has not answered can be cancelled (status %s)", obsdk.ErrInvalidRequest, d.Status)
	}
	body, err := json.Marshal(map[string]string{"status": draftRejected, "previous_updated_timestamp": d.Updated})
	if err != nil {
		return nil, err
	}
	p := "/user/" + url.PathEscape(pf.User) + "/monetary-account/" + url.PathEscape(pf.Account) + "/draft-payment/" + url.PathEscape(pf.Draft)
	if _, err := c.userCall(ctx, o.Session, req{op: opPayCancel, method: http.MethodPut, path: p, body: body}); err != nil {
		return nil, err
	}
	pay.Status, pay.BankStatus, pay.Final, pay.Reason = obsdk.PaymentCancelled, draftRejected, true, "withdrawn"
	return &obsdk.Step{Kind: obsdk.StepDone, Payment: pay, Raw: pay.Raw}, nil
}
