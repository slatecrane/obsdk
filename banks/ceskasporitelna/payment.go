package ceskasporitelna

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
	"github.com/slatecrane/obsdk/internal/cbs"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Payment initiation: the user logs in with scope PISP (first redirect), the
// payment is created with that token, ČS hands out a federated signing URL
// for it (second redirect) and a poll id, and after the user comes back the
// poll tells whether the payment was signed. Status calls need the payment
// login's token. ČS's API has no cancellation.
//
// A session from an earlier payment login (scope PISP, token still valid or
// refreshable) can be passed as PaymentRequest.Session to skip the login.

const (
	// paymentKind names a payment login in DisconnectResult.
	paymentKind = "pis"

	pisBase = pisRoot + "/my/payments"

	// defaultPollInterval applies when ČS's signing response gives none.
	defaultPollInterval = 5 * time.Second
)

// payState is the part of a payment flow that is specific to payments.
type payState struct {
	Type   obsdk.PaymentType `json:"type"`
	Body   json.RawMessage   `json:"body"`              // the payment, created after the login
	ID     string            `json:"id,omitempty"`      // ČS's transactionIdentification, once created
	SignID string            `json:"sign_id,omitempty"` // the signature ČS opened; also the payment's key for status calls
	PollID string            `json:"poll_id,omitempty"` // polls the federated signing
	// PollMS is ČS's poll interval in milliseconds.
	PollMS int `json:"poll_ms,omitempty"`
	// Returned is set once the user came back from the signing page; from
	// then on an empty input polls again.
	Returned bool `json:"returned,omitempty"`
	// Session is the payment login, handed back on every step so it can be
	// used for status calls and the next payment.
	Session *obsdk.Session `json:"session,omitempty"`
}

// paymentRef is what Payment.Ref holds. It carries no tokens: status calls
// take the session from PaymentCallOptions.
type paymentRef struct {
	Integration string            `json:"i"`
	ID          string            `json:"id"`
	SignID      string            `json:"s"`
	Type        obsdk.PaymentType `json:"t"`
}

// ---- specs ----

// instructionIDRE is what the SDK sends as the payment's instruction id.
// ČS documents only the length; its examples use letters and digits.
var instructionIDRE = regexp.MustCompile(`^[A-Za-z0-9]{1,35}$`)

func paymentSpecs() []obsdk.PaymentSpec {
	debtor := []obsdk.PaymentField{
		{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Pattern: `^CZ`, Label: "Pay from",
			Note: "The ČS account to pay from (Czech IBAN)."},
		{Path: obsdk.FieldInstructionID, Use: obsdk.FieldOptional, Pattern: instructionIDRE.String(), Label: "Payment id",
			Note: "The payer's id for the payment. Defaults to the idempotency key (letters and digits only)."},
		{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Execution date",
			Note: "Empty: as soon as possible. A dated payment must be signed by that date."},
	}
	base := obsdk.PaymentSpec{
		Countries: []obsdk.Country{"CZ"}, MaxTransfers: 1, AuthApproaches: []string{"redirect"},
		FinalStatuses:      []obsdk.PaymentStatus{obsdk.PaymentCompleted},
		StatusNeedsSession: true,
		Notes: []string{
			"Two redirects: the user logs in to ČS (scope PISP), then signs the payment on ČS's signing page. Pass the session of an earlier payment login as PaymentRequest.Session to skip the first.",
			"PaymentStatus needs the payment login's session (PaymentCallOptions.Session); ČS keeps the status of executed payments for 34 days.",
			"An unsigned payment expires after 30 days. ČS's API cannot cancel payments.",
		},
	}

	domestic := base
	domestic.Type, domestic.Currencies = obsdk.PaymentDomestic, []string{"CZK"}
	domestic.Fields = append(append([]obsdk.PaymentField{}, debtor...),
		obsdk.PaymentField{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,11}(\.\d{1,2})?$`, Label: "Amount"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Pattern: `^CZ`, Label: "Payee account"},
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message for the payee"},
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceCZ}, Label: "Variable symbol",
			Note: "The variable symbol (variabilní symbol), 1 to 10 digits."},
	)

	sepa := base
	sepa.Type, sepa.Currencies = obsdk.PaymentSEPA, []string{"EUR"}
	sepa.Fields = append(append([]obsdk.PaymentField{}, debtor...),
		obsdk.PaymentField{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,12}(\.\d{1,2})?$`, Label: "Amount"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, MaxLength: 34, Label: "Payee account"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAddress, Use: obsdk.FieldRequired, Label: "Payee address",
			Note: "Only the country is sent; ČS requires it on SEPA payments."},
		obsdk.PaymentField{Path: obsdk.FieldCreditorCountry, Use: obsdk.FieldRequired, Pattern: `^[A-Z]{2}$`, Label: "Payee country"},
		obsdk.PaymentField{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35, Label: "End-to-end id"},
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Message for the payee"},
	)
	sepa.Notes = append(append([]string{}, base.Notes...), "SEPA payments are sent with shared charges (SHA), the only option ČS allows within the EEA.")
	return []obsdk.PaymentSpec{domestic, sepa}
}

func (c *client) paymentSpec(t obsdk.PaymentType) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().PaymentSpec(c.target.Country, c.target.Segment, t); ok {
		return s, nil
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: Česká spořitelna offers no %q payments", obsdk.ErrUnsupported, t)
}

// ---- request body ----

type pisAccount struct {
	Identification struct {
		IBAN string `json:"iban"`
	} `json:"identification"`
}

type pisAmount struct {
	Value    json.Number `json:"value"` // a JSON number, written exactly as given
	Currency string      `json:"currency"`
}

type pisCreditor struct {
	Name          string `json:"name"`
	PostalAddress struct {
		Country string `json:"country"`
	} `json:"postalAddress"`
}

type pisRemittance struct {
	Structured *struct {
		CreditorReferenceInformation struct {
			Reference []string `json:"reference"`
		} `json:"creditorReferenceInformation"`
	} `json:"structured,omitempty"`
	Unstructured string `json:"unstructured,omitempty"`
}

// pisBody is the ČBS payment order, in the field order of ČS's examples.
type pisBody struct {
	PaymentIdentification struct {
		InstructionIdentification string `json:"instructionIdentification"`
		EndToEndIdentification    string `json:"endToEndIdentification,omitempty"`
	} `json:"paymentIdentification"`
	PaymentTypeInformation struct {
		InstructionPriority string `json:"instructionPriority"`
	} `json:"paymentTypeInformation"`
	Amount struct {
		InstructedAmount pisAmount `json:"instructedAmount"`
	} `json:"amount"`
	RequestedExecutionDate string         `json:"requestedExecutionDate,omitempty"`
	ChargeBearer           string         `json:"chargeBearer,omitempty"`
	DebtorAccount          pisAccount     `json:"debtorAccount"`
	CreditorAccount        pisAccount     `json:"creditorAccount"`
	Creditor               *pisCreditor   `json:"creditor,omitempty"`
	RemittanceInformation  *pisRemittance `json:"remittanceInformation,omitempty"`
}

func invalid(path, msg string) error {
	return &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: path, Index: 0, Code: obsdk.IssueInvalid, Message: msg}}}
}

// instructionID is the payment's id for the payer: the transfer's
// InstructionID, else the idempotency key, else a new id, reduced to letters
// and digits.
func (c *client) instructionID(r obsdk.PaymentRequest) (string, error) {
	if id := r.Transfers[0].InstructionID; id != "" {
		if !instructionIDRE.MatchString(id) {
			return "", invalid(obsdk.FieldInstructionID, "Česká spořitelna takes 1 to 35 letters and digits")
		}
		return id, nil
	}
	src := r.IdempotencyKey
	if src == "" {
		src = c.cfg.ID(obsdk.IDRequest)
	}
	var b strings.Builder
	for _, ch := range src {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
		}
	}
	id := strings.ToUpper(b.String())
	if id == "" {
		return "", invalid(obsdk.FieldInstructionID, "the idempotency key has no letters or digits")
	}
	return id[:min(len(id), 35)], nil
}

func (c *client) buildBody(r obsdk.PaymentRequest) ([]byte, error) {
	t := r.Transfers[0]
	var b pisBody
	id, err := c.instructionID(r)
	if err != nil {
		return nil, err
	}
	b.PaymentIdentification.InstructionIdentification = id
	b.PaymentTypeInformation.InstructionPriority = "NORM"
	b.Amount.InstructedAmount = pisAmount{Value: json.Number(t.Amount.Amount), Currency: t.Amount.Currency}
	b.RequestedExecutionDate = r.ExecutionDate
	b.DebtorAccount.Identification.IBAN = r.Debtor.Account.Value
	b.CreditorAccount.Identification.IBAN = t.Creditor.Account.Value
	rem := &pisRemittance{}
	if len(t.Remittance) > 0 {
		rem.Unstructured = t.Remittance[0]
	}
	if r.Type == obsdk.PaymentSEPA {
		b.PaymentIdentification.EndToEndIdentification = t.EndToEndID
		b.ChargeBearer = "SHA"
		b.Creditor = &pisCreditor{Name: t.Creditor.Name}
		if a := t.Creditor.Address; a != nil {
			b.Creditor.PostalAddress.Country = a.Country
		}
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		// Domestic payments only: the payment symbols go in the
		// structured reference ("VS:123").
		rem.Structured = &struct {
			CreditorReferenceInformation struct {
				Reference []string `json:"reference"`
			} `json:"creditorReferenceInformation"`
		}{}
		rem.Structured.CreditorReferenceInformation.Reference = []string{"VS:" + ref.Value}
	}
	if rem.Unstructured != "" || rem.Structured != nil {
		b.RemittanceInformation = rem
	}
	return json.Marshal(b)
}

// ---- initiate ----

type pisResponse struct {
	PaymentIdentification struct {
		TransactionIdentification string `json:"transactionIdentification"`
	} `json:"paymentIdentification"`
	DebtorAccount struct {
		Identification struct {
			IBAN string `json:"iban"`
		} `json:"identification"`
	} `json:"debtorAccount"`
	SignInfo struct {
		SignID string `json:"signId"`
		Hash   string `json:"hash"`
		State  string `json:"state"`
	} `json:"signInfo"`
	InstructionStatus string `json:"instructionStatus"`
}

// InitiatePayment validates the payment and returns the redirect to ČS's
// login (scope PISP), or straight to the signing page when r.Session holds a
// usable payment login.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r.Type)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: Česká spořitelna only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	body, err := c.buildBody(r)
	if err != nil {
		return nil, err
	}
	f := &flow{RedirectURL: redirectURL, Pay: &payState{Type: r.Type, Body: body}}
	if s, err := c.paymentSession(ctx, r.Session); err != nil {
		return nil, err
	} else if s != nil {
		return c.createAndSign(ctx, f, s)
	}
	f.Phase, f.OAuthState = phPayLogin, c.cfg.ID(obsdk.IDState)
	f.AuthURL = c.authorizeURL(scopePIS, redirectURL, f.OAuthState)
	return c.pause(f, loginStep(f, "Send the user to Česká spořitelna to log in for the payment, then pass the callback URL to Resume."))
}

// paymentSession returns s when it is a payment login that can still be
// used, refreshing its token if needed, and nil when there is none.
func (c *client) paymentSession(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if s == nil {
		return nil, nil
	}
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if !hasScope(s, scopePIS) || s.AccessToken == "" {
		return nil, nil
	}
	if !s.AccessExpired(c.now()) {
		return s, nil
	}
	ns, err := c.refresh(ctx, s)
	if err != nil {
		// A new login fixes it; the payment does not fail for that.
		return nil, nil
	}
	return ns, nil
}

// resumePayment continues a payment after the login or the signature.
func (c *client) resumePayment(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	if f.Pay == nil {
		return nil, fmt.Errorf("%w: payment flow without payment", obsdk.ErrInvalidRequest)
	}
	if f.Phase == phPaySign {
		return c.finishSign(ctx, f, in)
	}
	if in.Callback == "" {
		return c.pause(f, loginStep(f, "Send the user to Česká spořitelna to log in for the payment, then pass the callback URL to Resume."))
	}
	s, err := c.login(ctx, f, in.Callback, "payment login was not completed")
	if err != nil {
		return nil, err
	}
	return c.createAndSign(ctx, f, s)
}

// createAndSign creates the payment with the payment login's token and asks
// for its signing URL, returning the redirect to ČS's signing page.
func (c *client) createAndSign(ctx context.Context, f *flow, s *obsdk.Session) (*obsdk.Step, error) {
	fail := func(pay *obsdk.Payment, err error) (*obsdk.Step, error) {
		return nil, &obsdk.FlowError{Session: s.Clone(), Payment: pay, Err: err}
	}
	user := &obsdk.PSUContext{}
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: pisBase, body: f.Pay.Body, bearer: s.AccessToken, pis: true, psu: user})
	if err != nil {
		return fail(nil, err)
	}
	if res.status != http.StatusOK && res.status != http.StatusCreated {
		return fail(nil, c.apiErr(opPayment, res))
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil || pr.SignInfo.SignID == "" {
		return fail(nil, fmt.Errorf("ceskasporitelna: unreadable payment response (HTTP %d)", res.status))
	}
	f.Pay.ID, f.Pay.SignID = pr.PaymentIdentification.TransactionIdentification, pr.SignInfo.SignID
	pay, err := c.toPayment(f.Pay, pr.InstructionStatus, "", res.body)
	if err != nil {
		return nil, err
	}
	if iban := pr.DebtorAccount.Identification.IBAN; iban != "" {
		pay.Debtor = &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: iban}
	}
	if pay.Status == obsdk.PaymentRejected {
		return fail(pay, &obsdk.PaymentRejectedError{Reason: pay.Reason, Payment: pay})
	}

	path := pisBase + "/federate/sign/" + url.PathEscape(pr.SignInfo.SignID) + "/hash/" + url.PathEscape(pr.SignInfo.Hash)
	sres, err := c.do(ctx, req{op: opPaySign, method: http.MethodGet, path: path, bearer: s.AccessToken, pis: true, psu: user,
		header: http.Header{"Callback-Uri": {f.RedirectURL}}})
	if err != nil {
		return fail(pay, err)
	}
	if sres.status != http.StatusOK {
		return fail(pay, c.apiErr(opPaySign, sres))
	}
	var sr struct {
		SigningURL string `json:"signingUrl"`
		Poll       struct {
			ID       string      `json:"id"`
			Interval json.Number `json:"interval"`
		} `json:"poll"`
	}
	if err := json.Unmarshal(sres.body, &sr); err != nil || sr.SigningURL == "" || sr.Poll.ID == "" {
		return fail(pay, fmt.Errorf("ceskasporitelna: signing response has no link or poll id (HTTP %d)", sres.status))
	}
	f.Pay.PollID = sr.Poll.ID
	if ms, err := sr.Poll.Interval.Int64(); err == nil && ms > 0 {
		f.Pay.PollMS = int(ms)
	}
	f.Phase, f.AuthURL, f.OAuthState, f.Pay.Session = phPaySign, sr.SigningURL, "", s
	return c.pause(f, signStep(f, pay))
}

func signStep(f *flow, pay *obsdk.Payment) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL}, Session: f.Pay.Session, Payment: pay,
		Message: "Send the user to Česká spořitelna to sign the payment, then pass the callback URL to Resume."}
}

// finishSign polls the signing after the user came back from the signing
// page, then reads the payment's status. ČS's return carries nothing the SDK
// needs (an error, if the user cancelled); the poll tells the outcome.
func (c *client) finishSign(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	pay, err := c.toPayment(f.Pay, "", "", nil)
	if err != nil {
		return nil, err
	}
	s := f.Pay.Session
	fail := func(pay *obsdk.Payment, err error) (*obsdk.Step, error) {
		return nil, &obsdk.FlowError{Session: s, Payment: pay, Err: err}
	}
	if in.Callback == "" && !f.Pay.Returned {
		return c.pause(f, signStep(f, pay))
	}
	if in.Callback != "" {
		if p, err := callback.Parse(in.Callback); err == nil {
			if code, desc, failed := p.Error(); failed {
				return fail(pay, authFailed("payment was not signed (%s: %s)", code, desc))
			}
		}
		f.Pay.Returned = true
	}
	res, err := c.do(ctx, req{op: opPayPoll, method: http.MethodGet, path: pisBase + "/sign/poll/" + url.PathEscape(f.Pay.PollID),
		bearer: s.AccessToken, pis: true, psu: &obsdk.PSUContext{}})
	if err != nil {
		return fail(pay, err)
	}
	if res.status != http.StatusOK {
		return fail(pay, c.apiErr(opPayPoll, res))
	}
	var pb struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(res.body, &pb); err != nil || pb.State == "" {
		return fail(pay, fmt.Errorf("ceskasporitelna: unreadable signing poll (HTTP %d)", res.status))
	}
	switch pb.State {
	case "DONE":
	case "PROCESSING":
		wait := defaultPollInterval
		if f.Pay.PollMS > 0 {
			wait = time.Duration(f.Pay.PollMS) * time.Millisecond
		}
		return c.pause(f, &obsdk.Step{Kind: obsdk.StepWait, WaitFor: wait, Session: s, Payment: pay,
			Message: "Česká spořitelna is processing the signature; call Resume again after WaitFor."})
	case "AUTHORIZATION_NOT_STARTED":
		return fail(pay, authFailed("payment was not signed: the user left the signing page"))
	default: // REJECTED, EXPIRED, ORDER_PROCESSING_FAILED
		return fail(pay, authFailed("payment was not signed (%s)", pb.State))
	}
	got, raw, err := c.status(ctx, f.Pay, s)
	if err != nil {
		return fail(pay, err)
	}
	if got.Status == obsdk.PaymentRejected {
		return fail(got, &obsdk.PaymentRejectedError{Reason: got.Reason, Payment: got})
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Payment: got, Raw: raw}, nil
}

// ---- status ----

func (c *client) toPayment(p *payState, status, reason string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, ID: p.ID, SignID: p.SignID, Type: p.Type})
	if err != nil {
		return nil, err
	}
	id := p.ID
	if id == "" {
		id = p.SignID
	}
	pay := &obsdk.Payment{ID: id, Type: p.Type, Status: obsdk.PaymentReceived, Ref: ref, Raw: raw, Reason: reason}
	if status != "" {
		pay.BankStatus = status
		pay.Status, pay.Final = cbs.PaymentStatus(status)
	}
	return pay, nil
}

func decodeRef(ref string) (*paymentRef, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.SignID == "" {
		return nil, fmt.Errorf("%w: not a Česká spořitelna payment reference", obsdk.ErrInvalidRequest)
	}
	return &r, nil
}

// status reads a payment's status with the payment login's token. ČS keys it
// by the signature id. statusChangeInfo (INSUFFICIENT_FUNDS, CANCELLED, ...)
// becomes the payment's Reason.
func (c *client) status(ctx context.Context, p *payState, s *obsdk.Session) (*obsdk.Payment, []byte, error) {
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: pisBase + "/" + url.PathEscape(p.SignID) + "/status",
		bearer: s.AccessToken, pis: true})
	if err != nil {
		return nil, nil, err
	}
	if res.status != http.StatusOK {
		return nil, nil, c.apiErr(opPayStatus, res)
	}
	var b struct {
		InstructionStatus string `json:"instructionStatus"`
		StatusChangeInfo  string `json:"statusChangeInfo"`
	}
	if err := json.Unmarshal(res.body, &b); err != nil || b.InstructionStatus == "" {
		return nil, nil, fmt.Errorf("ceskasporitelna: unreadable payment status (HTTP %d)", res.status)
	}
	pay, err := c.toPayment(p, b.InstructionStatus, b.StatusChangeInfo, res.body)
	return pay, res.body, err
}

// PaymentStatus reads a payment's status. It needs the session of the
// payment login (refreshed here when its token expired).
func (c *client) PaymentStatus(ctx context.Context, ref string, o obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	r, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	s := o.Session
	if s == nil {
		return nil, fmt.Errorf("%w: Česká spořitelna reads payments with the payment login's session (PaymentCallOptions.Session)", obsdk.ErrInvalidRequest)
	}
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" || s.AccessExpired(c.now()) {
		if s, err = c.refresh(ctx, s); err != nil {
			return nil, err
		}
	}
	pay, raw, err := c.status(ctx, &payState{Type: r.Type, ID: r.ID, SignID: r.SignID}, s)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: raw}, nil
}

// CancelPayment is not offered: ČS's payment API has no cancellation. (An
// unsigned payment expires after 30 days.)
func (c *client) CancelPayment(ctx context.Context, ref string, _ obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	if _, err := decodeRef(ref); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: Česká spořitelna's API cannot cancel payments", obsdk.ErrUnsupported)
}
