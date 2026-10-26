package komercnibanka

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

// Payment initiation: the user logs in with scope pisp (first redirect), the
// payment is created with that token, and KB's signing page (second
// redirect) approves it. The status is read with the certificate alone.
// Signed payments are irrevocable; KB deletes only unsigned ones.
//
// A session from an earlier payment login (scope pisp, token still valid or
// refreshable) can be passed as PaymentRequest.Session to skip the login.
//
// Standing orders (domestic only) take the same steps on KB's PIS v1
// resource /standingorders, which has its own signing and status. KB's
// manual lists their deletion as unsupported.

const (
	// paymentKind names a payment login in DisconnectResult.
	paymentKind = "pis"

	pisBase = "/pisp/v2/my/payments"
	// standingBase is on PIS v1: v2 has no standing orders.
	standingBase = "/pisp/v1/standingorders"

	// authorizationType is the only signing method KB offers to TPPs: a
	// redirect to its signing page.
	authorizationType = "USERAGENT_REDIRECT"
)

// payState is the part of a payment flow that is specific to payments.
type payState struct {
	Type   obsdk.PaymentType `json:"type"`
	Body   json.RawMessage   `json:"body"`              // the payment, created after the login
	ID     string            `json:"id,omitempty"`      // KB's transactionIdentification, once created
	SignID string            `json:"sign_id,omitempty"` // the signature KB opened for it
	// Session is the payment login, handed back on the final step so it can
	// be reused for the next payment.
	Session *obsdk.Session `json:"session,omitempty"`
	// Standing is set for a standing order, Schedule when it is known
	// (not on status reads from a Payment.Ref).
	Standing bool            `json:"standing,omitempty"`
	Schedule *obsdk.Schedule `json:"schedule,omitempty"`
}

// base is the resource the payment is created, signed and read at.
func (p *payState) base() string {
	if p.Standing {
		return standingBase
	}
	return pisBase
}

// paymentRef is what Payment.Ref holds. It carries no tokens: KB answers
// the status to the certificate.
type paymentRef struct {
	Integration string            `json:"i"`
	ID          string            `json:"id"`
	Type        obsdk.PaymentType `json:"t"`
	Standing    bool              `json:"so,omitempty"`
}

// ---- specs ----

// textPattern is KB's character set for the message to the payee (CERTIS
// for domestic payments) plus the space, which KB's published pattern leaves
// out but accepts.
const textPattern = "^[ A-Za-z0-9áäčďéěíĺľňöóôŕřšťüúůýžÄÁČĎÉĚÍĹĽŇÖÓÔŔŘŠŤÜÚŮÝŽ'()+,\\-./:?!#$&*;=@\\[\\]\"_`{}]+$"

// sepaTextPattern is the SWIFT character set KB applies to SEPA payments.
const sepaTextPattern = "^[ A-Za-z0-9/?:().,'+\\-]+$"

const bicPattern = `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`

// instructionIDRE is what KB takes as the payment's instruction id: it
// refuses "-" and other punctuation ("Invalid charset").
var instructionIDRE = regexp.MustCompile(`^[A-Za-z0-9]{1,35}$`)

func paymentSpecs() []obsdk.PaymentSpec {
	debtor := []obsdk.PaymentField{
		{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Pattern: `^CZ`, Label: "Pay from",
			Note: "The KB account to pay from (Czech IBAN); KB's signing page does not let the user pick one."},
		{Path: obsdk.FieldDebtorCurrency, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{3}$`, Label: "Pay from currency",
			Note: "For a multi-currency account: which currency's sub-account pays. Defaults to the amount's currency."},
		{Path: obsdk.FieldInstructionID, Use: obsdk.FieldOptional, Pattern: instructionIDRE.String(), Label: "Payment id",
			Note: "The payer's id for the payment. Defaults to the idempotency key (letters and digits only)."},
	}
	base := obsdk.PaymentSpec{
		Countries: []obsdk.Country{"CZ"}, MaxTransfers: 1, AuthApproaches: []string{"redirect"},
		FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
		Notes: []string{
			"Two redirects: the user logs in to KB (scope pisp), then signs the payment on KB's signing page. Pass the session of an earlier payment login as PaymentRequest.Session to skip the first.",
			"Payments are executed the same business day (before 20:30; later ones the next business day). Signed payments are irrevocable.",
		},
	}

	domestic := base
	domestic.Type, domestic.Currencies = obsdk.PaymentDomestic, []string{"CZK"}
	domestic.Fields = append(append([]obsdk.PaymentField{}, debtor...),
		obsdk.PaymentField{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,13}(\.\d{1,2})?$`, Label: "Amount"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, Pattern: `^CZ`, Label: "Payee account"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorName, Use: obsdk.FieldOptional, MaxLength: 70, Pattern: textPattern, Label: "Payee name"},
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Pattern: textPattern, Label: "Message for the payee"},
		obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceCZ}, Label: "Variable symbol",
			Note: "The variable symbol (variabilní symbol), 1 to 10 digits."},
	)

	sepa := base
	sepa.Type, sepa.Currencies = obsdk.PaymentSEPA, []string{"EUR"}
	sepa.Fields = append(append([]obsdk.PaymentField{}, debtor...),
		obsdk.PaymentField{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,9}(\.\d{1,2})?$`, Label: "Amount"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, MaxLength: 34, Label: "Payee account"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Pattern: sepaTextPattern, Label: "Payee name"},
		obsdk.PaymentField{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: bicPattern, Label: "Payee bank BIC"},
		obsdk.PaymentField{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Pattern: sepaTextPattern, Label: "Message for the payee"},
	)

	// Standing orders: domestic only, from D+2 business days, on the start
	// date's day (KB refuses the month-end and business-day variants of
	// modeDue); KB names the order after the message.
	standing := base
	standing.Type, standing.Currencies = obsdk.PaymentDomestic, []string{"CZK"}
	standing.FinalStatuses = []obsdk.PaymentStatus{obsdk.PaymentAccepted}
	standing.Schedule = &obsdk.ScheduleSpec{StartDateMinDays: 2}
	for _, f := range domestic.Fields {
		if f.Path != obsdk.FieldDebtorCurrency && f.Path != obsdk.FieldCreditorName { // not in KB's standing order
			standing.Fields = append(standing.Fields, f)
		}
	}
	freq := func(f obsdk.Frequency, label string) obsdk.Option {
		return obsdk.Option{Value: string(f), Label: label}
	}
	standing.Fields = append(standing.Fields,
		obsdk.PaymentField{Path: obsdk.FieldScheduleFrequency, Use: obsdk.FieldRequired, Label: "Frequency", Options: []obsdk.Option{
			freq(obsdk.FrequencyDaily, "Daily"), freq(obsdk.FrequencyWeekly, "Weekly"), freq(obsdk.FrequencyEveryTwoWeeks, "Every two weeks"),
			freq(obsdk.FrequencyMonthly, "Monthly"),
			freq(obsdk.FrequencyEveryTwoMonths, "Every two months"), freq(obsdk.FrequencyQuarterly, "Quarterly"),
			freq(obsdk.FrequencySemiannual, "Every six months"), freq(obsdk.FrequencyAnnual, "Yearly")}},
		obsdk.PaymentField{Path: obsdk.FieldScheduleStartDate, Use: obsdk.FieldRequired, Label: "First payment",
			Note: "At least two business days ahead (D+2). Sets the day of the later payments."},
		obsdk.PaymentField{Path: obsdk.FieldScheduleEndDate, Use: obsdk.FieldOptional, Label: "Last payment",
			Note: "Empty (and no count): until the user cancels it."},
		obsdk.PaymentField{Path: obsdk.FieldScheduleCount, Use: obsdk.FieldOptional, Label: "Number of payments",
			Note: "Sent as the date of the last payment, which the SDK works out."},
	)
	standing.Notes = []string{
		"Two redirects, as for payments: the user logs in to KB (scope pisp), then signs the standing order on KB's signing page. Pass the session of an earlier payment login as PaymentRequest.Session to skip the first.",
		"A signed standing order is accepted (ACSP); PaymentStatus reads it with the certificate alone. KB's API cannot cancel it; the user ends it in KB's online banking.",
		"KB uses the message for the payee as the standing order's name.",
	}
	return []obsdk.PaymentSpec{domestic, sepa, standing}
}

func (c *client) paymentSpec(r obsdk.PaymentRequest) (obsdk.PaymentSpec, error) {
	if s, ok := c.Info().SpecFor(c.target.Country, c.target.Segment, r); ok {
		return s, nil
	}
	if r.Schedule != nil {
		return obsdk.PaymentSpec{}, fmt.Errorf("%w: Komerční banka offers no %q standing orders", obsdk.ErrUnsupported, r.Type)
	}
	return obsdk.PaymentSpec{}, fmt.Errorf("%w: Komerční banka offers no %q payments", obsdk.ErrUnsupported, r.Type)
}

// ---- request body ----

type pisAccount struct {
	Identification struct {
		IBAN string `json:"iban"`
	} `json:"identification"`
	Currency string `json:"currency,omitempty"`
}

type pisAmount struct {
	Value    json.Number `json:"value"` // a JSON number, written exactly as given
	Currency string      `json:"currency"`
}

type pisAgent struct {
	// KB's PIS schema spells this key in lower case (its AIS schema does not).
	FinancialInstitution struct {
		BIC string `json:"bic"`
	} `json:"financialinstitutionidentification"`
}

type pisRemittance struct {
	Unstructured string `json:"unstructured,omitempty"`
	Structured   *struct {
		CreditorReferenceInformation struct {
			Reference []string `json:"reference"`
		} `json:"creditorReferenceInformation"`
	} `json:"structured,omitempty"`
}

// pisBody is the ČBS payment order, in the field order of KB's examples.
type pisBody struct {
	PaymentIdentification struct {
		InstructionIdentification string `json:"instructionIdentification"`
	} `json:"paymentIdentification"`
	Amount struct {
		InstructedAmount pisAmount `json:"instructedAmount"`
	} `json:"amount"`
	DebtorAccount pisAccount `json:"debtorAccount"`
	CreditorAgent *pisAgent  `json:"creditorAgent,omitempty"`
	Creditor      *struct {
		Name string `json:"name"`
	} `json:"creditor,omitempty"`
	CreditorAccount       pisAccount     `json:"creditorAccount"`
	RemittanceInformation *pisRemittance `json:"remittanceInformation,omitempty"`
}

func invalid(path, msg string) error {
	return &obsdk.PaymentValidationError{Issues: []obsdk.FieldIssue{{Path: path, Index: 0, Code: obsdk.IssueInvalid, Message: msg}}}
}

// instructionID is the payment's id for the payer: the transfer's
// InstructionID, else the idempotency key, else a new id, reduced to the
// letters and digits KB accepts.
func (c *client) instructionID(r obsdk.PaymentRequest) (string, error) {
	if id := r.Transfers[0].InstructionID; id != "" {
		if !instructionIDRE.MatchString(id) {
			return "", invalid(obsdk.FieldInstructionID, "Komerční banka takes 1 to 35 letters and digits")
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
	b.Amount.InstructedAmount = pisAmount{Value: json.Number(t.Amount.Amount), Currency: t.Amount.Currency}
	b.DebtorAccount.Identification.IBAN = r.Debtor.Account.Value
	b.DebtorAccount.Currency = t.Amount.Currency
	if r.Debtor.Currency != "" {
		b.DebtorAccount.Currency = r.Debtor.Currency
	}
	b.CreditorAccount.Identification.IBAN = t.Creditor.Account.Value
	if t.Creditor.Name != "" {
		b.Creditor = &struct {
			Name string `json:"name"`
		}{t.Creditor.Name}
	}
	if ag := t.Creditor.Agent; ag != nil && ag.BIC != "" {
		b.CreditorAgent = &pisAgent{}
		b.CreditorAgent.FinancialInstitution.BIC = ag.BIC
	}
	rem := &pisRemittance{}
	if len(t.Remittance) > 0 {
		rem.Unstructured = t.Remittance[0]
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
		// Domestic payments only: KB reads the symbols of a domestic
		// payment from the structured reference ("VS:123").
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

// standingBody is KB's standing order (StandingOrdersCreateRequest).
type standingBody struct {
	StandingOrderIdentification struct {
		InstructionIdentification string `json:"instructionIdentification"`
	} `json:"standingOrderIdentification"`
	Amount struct {
		InstructedAmount pisAmount `json:"instructedAmount"`
	} `json:"amount"`
	StandingOrder struct {
		Execution struct {
			Mode     string `json:"mode"`
			ModeDue  string `json:"modeDue"`
			Interval string `json:"interval"`
		} `json:"execution"`
		Validity *standingValidity `json:"validity,omitempty"`
	} `json:"standingOrder"`
	RequestedExecutionDate string         `json:"requestedExecutionDate"`
	DebtorAccount          pisAccount     `json:"debtorAccount"`
	CreditorAccount        pisAccount     `json:"creditorAccount"`
	RemittanceInformation  *pisRemittance `json:"remittanceInformation,omitempty"`
}

type standingValidity struct {
	LastExecutionDate string `json:"lastExecutionDate"`
}

var standingMonths = map[obsdk.Frequency]int{
	obsdk.FrequencyMonthly: 1, obsdk.FrequencyEveryTwoMonths: 2, obsdk.FrequencyQuarterly: 3,
	obsdk.FrequencySemiannual: 6, obsdk.FrequencyAnnual: 12,
}

// lastExecution is the date of a schedule's Count-th payment: StartDate
// plus Count-1 intervals, on the start's day of the month (or the month's
// last day when it is shorter).
func lastExecution(sc *obsdk.Schedule) string {
	start, _ := time.Parse("2006-01-02", sc.StartDate)
	n := sc.Count - 1
	switch sc.Frequency {
	case obsdk.FrequencyDaily:
		return start.AddDate(0, 0, n).Format("2006-01-02")
	case obsdk.FrequencyWeekly:
		return start.AddDate(0, 0, 7*n).Format("2006-01-02")
	case obsdk.FrequencyEveryTwoWeeks:
		return start.AddDate(0, 0, 14*n).Format("2006-01-02")
	}
	first := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, standingMonths[sc.Frequency]*n, 0)
	last := first.AddDate(0, 1, -1).Day()
	day := start.Day()
	if day > last {
		day = last
	}
	return first.AddDate(0, 0, day-1).Format("2006-01-02")
}

var standingIntervals = map[obsdk.Frequency]string{
	obsdk.FrequencyDaily: "DAILY", obsdk.FrequencyWeekly: "WEEKLY", obsdk.FrequencyEveryTwoWeeks: "BI_WEEKLY", obsdk.FrequencyMonthly: "MONTHLY",
	obsdk.FrequencyEveryTwoMonths: "BI_MONTHLY", obsdk.FrequencyQuarterly: "QUARTERLY",
	obsdk.FrequencySemiannual: "HALFYEARLY", obsdk.FrequencyAnnual: "YEARLY",
}

// buildStandingBody turns a validated standing-order request into KB's
// body. The start date is the first execution and sets the day of the
// later ones.
func (c *client) buildStandingBody(r obsdk.PaymentRequest) ([]byte, error) {
	sc, t := r.Schedule, r.Transfers[0]
	interval, ok := standingIntervals[sc.Frequency]
	if !ok { // the spec's options keep this from happening
		return nil, invalid(obsdk.FieldScheduleFrequency, "Komerční banka has no such standing order interval")
	}
	var b standingBody
	id, err := c.instructionID(r)
	if err != nil {
		return nil, err
	}
	b.StandingOrderIdentification.InstructionIdentification = id
	b.Amount.InstructedAmount = pisAmount{Value: json.Number(t.Amount.Amount), Currency: t.Amount.Currency}
	ex := &b.StandingOrder.Execution
	ex.Mode, ex.ModeDue, ex.Interval = "UNTIL_CANCELLATION", "DUE_DAY_OF_MONTH", interval
	end := sc.EndDate
	if sc.Count > 0 {
		// KB turns AFTER_MAX_ITERATION_EXCEEDED into an end date one
		// interval too late (12 monthly payments from 5 Nov end on 5 Nov a
		// year later), so the SDK sends the last payment's date itself.
		end = lastExecution(sc)
	}
	if end != "" {
		ex.Mode, b.StandingOrder.Validity = "UNTIL_DATE", &standingValidity{LastExecutionDate: end}
	}
	b.RequestedExecutionDate = sc.StartDate
	b.DebtorAccount.Identification.IBAN, b.DebtorAccount.Currency = r.Debtor.Account.Value, t.Amount.Currency
	b.CreditorAccount.Identification.IBAN = t.Creditor.Account.Value
	rem := &pisRemittance{}
	if len(t.Remittance) > 0 {
		rem.Unstructured = t.Remittance[0]
	}
	if ref := t.Reference; ref != nil && ref.Value != "" {
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
	PaymentRequest struct {
		PaymentIdentification struct {
			TransactionIdentification string `json:"transactionIdentification"`
		} `json:"paymentIdentification"`
		DebtorAccount struct {
			Identification struct {
				IBAN string `json:"iban"`
			} `json:"identification"`
		} `json:"debtorAccount"`
	} `json:"paymentRequest"`
	// StandingOrderIdentification and DebtorAccount answer a standing order.
	StandingOrderIdentification struct {
		TransactionIdentification string `json:"transactionIdentification"`
	} `json:"standingOrderIdentification"`
	DebtorAccount struct {
		Identification struct {
			IBAN string `json:"iban"`
		} `json:"identification"`
	} `json:"debtorAccount"`
	SignInfo struct {
		State  string `json:"state"`
		SignID string `json:"signId"`
	} `json:"signInfo"`
	InstructionStatus string `json:"instructionStatus"`
	StatusChangeInfo  string `json:"statusChangeInfo"`
}

// id and debtor read either answer: KB nests a payment in paymentRequest
// and returns a standing order flat.
func (p *pisResponse) id() string {
	if id := p.PaymentRequest.PaymentIdentification.TransactionIdentification; id != "" {
		return id
	}
	return p.StandingOrderIdentification.TransactionIdentification
}

func (p *pisResponse) debtor() string {
	if iban := p.PaymentRequest.DebtorAccount.Identification.IBAN; iban != "" {
		return iban
	}
	return p.DebtorAccount.Identification.IBAN
}

// InitiatePayment validates the payment and returns the redirect to KB's
// login (scope pisp), or straight to the signing page when r.Session holds a
// usable payment login.
func (c *client) InitiatePayment(ctx context.Context, r obsdk.PaymentRequest) (*obsdk.Step, error) {
	spec, err := c.paymentSpec(r)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(r, c.now()); err != nil {
		return nil, err
	}
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: Komerční banka only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	build := c.buildBody
	if r.Schedule != nil {
		build = c.buildStandingBody
	}
	body, err := build(r)
	if err != nil {
		return nil, err
	}
	f := &flow{RedirectURL: redirectURL, Pay: &payState{Type: r.Type, Body: body, Standing: r.Schedule != nil, Schedule: r.Schedule}}
	if s, err := c.paymentSession(ctx, r.Session); err != nil {
		return nil, err
	} else if s != nil {
		return c.createAndSign(ctx, f, s)
	}
	f.Phase, f.OAuthState = phPayLogin, c.cfg.ID(obsdk.IDState)
	f.AuthURL = c.authorizeURL(scopePIS, redirectURL, f.OAuthState)
	return c.pause(f, loginStep(f, "Send the user to Komerční banka to log in for the payment, then pass the callback URL to Resume."))
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
		return c.pause(f, loginStep(f, "Send the user to Komerční banka to log in for the payment, then pass the callback URL to Resume."))
	}
	s, err := c.login(ctx, f, in.Callback, scopePIS, "payment login was not completed")
	if err != nil {
		return nil, err
	}
	return c.createAndSign(ctx, f, s)
}

// createAndSign creates the payment with the payment login's token and
// opens its signature, returning the redirect to KB's signing page.
func (c *client) createAndSign(ctx context.Context, f *flow, s *obsdk.Session) (*obsdk.Step, error) {
	fail := func(pay *obsdk.Payment, err error) (*obsdk.Step, error) {
		return nil, &obsdk.FlowError{Session: s.Clone(), Payment: pay, Err: err}
	}
	res, err := c.do(ctx, req{op: opPayment, method: http.MethodPost, path: f.Pay.base(), body: f.Pay.Body, bearer: s.AccessToken, payment: true, user: true})
	if err != nil {
		return fail(nil, err)
	}
	if res.status != http.StatusOK && res.status != http.StatusCreated {
		return fail(nil, c.apiErr(opPayment, res))
	}
	var pr pisResponse
	if err := json.Unmarshal(res.body, &pr); err != nil || pr.id() == "" {
		return fail(nil, fmt.Errorf("komercnibanka: unreadable payment response (HTTP %d)", res.status))
	}
	f.Pay.ID = pr.id()
	f.Pay.SignID = pr.SignInfo.SignID
	pay, err := c.toPayment(f.Pay, pr.InstructionStatus, res.body)
	if err != nil {
		return nil, err
	}
	pay.Reason = pr.StatusChangeInfo
	if iban := pr.debtor(); iban != "" {
		pay.Debtor = &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: iban}
	}
	if pay.Status == obsdk.PaymentRejected {
		return fail(pay, &obsdk.PaymentRejectedError{Reason: pay.Reason, Payment: pay})
	}
	if f.Pay.SignID == "" {
		return fail(pay, fmt.Errorf("komercnibanka: payment %s came back without a signature to open", f.Pay.ID))
	}

	sb, _ := json.Marshal(map[string]string{"authorizationType": authorizationType, "redirectUrl": f.RedirectURL})
	path := f.Pay.base() + "/" + url.PathEscape(f.Pay.ID) + "/sign/" + url.PathEscape(f.Pay.SignID)
	sres, err := c.do(ctx, req{op: opPaySign, method: http.MethodPost, path: path, body: sb, bearer: s.AccessToken, payment: true, user: true})
	if err != nil {
		return fail(pay, err)
	}
	if sres.status != http.StatusOK {
		return fail(pay, c.apiErr(opPaySign, sres))
	}
	var sr struct {
		Href struct {
			URL string `json:"url"`
		} `json:"href"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(sres.body, &sr); err != nil || sr.Href.URL == "" {
		return fail(pay, fmt.Errorf("komercnibanka: signing response has no link (HTTP %d)", sres.status))
	}
	if sr.Method != "" && !strings.EqualFold(sr.Method, http.MethodGet) {
		// The standard allows a SAML POST to the signing page; KB has only
		// been seen to use GET, and a Step can only redirect.
		return fail(pay, fmt.Errorf("%w: Komerční banka asked for a %s to its signing page", obsdk.ErrUnsupported, sr.Method))
	}
	f.Phase, f.AuthURL, f.OAuthState, f.Pay.Session = phPaySign, sr.Href.URL, "", s
	st := &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL}, Session: s, Payment: pay,
		Message: "Send the user to Komerční banka to sign the payment, then pass the callback URL to Resume."}
	return c.pause(f, st)
}

// finishSign reads the payment's status after the user came back from the
// signing page. KB's return carries no code or state (it may carry
// changeInfo, a changed due date); the status tells whether it was signed.
func (c *client) finishSign(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	pay, err := c.toPayment(f.Pay, "", nil)
	if err != nil {
		return nil, err
	}
	s := f.Pay.Session
	if in.Callback == "" {
		st := &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL}, Payment: pay, Session: s,
			Message: "Send the user to Komerční banka to sign the payment, then pass the callback URL to Resume."}
		return c.pause(f, st)
	}
	if p, err := callback.Parse(in.Callback); err == nil {
		if code, desc, failed := p.Error(); failed {
			return nil, &obsdk.FlowError{Session: s, Payment: pay, Err: authFailed("payment was not signed (%s: %s)", code, desc)}
		}
	}
	got, raw, err := c.status(ctx, f.Pay)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s, Payment: pay, Err: err}
	}
	switch {
	case got.Status == obsdk.PaymentRejected:
		return nil, &obsdk.FlowError{Session: s, Payment: got, Err: &obsdk.PaymentRejectedError{Reason: got.Reason, Payment: got}}
	case got.Status == obsdk.PaymentReceived:
		// Still waiting for the signature: the user left the signing page.
		return nil, &obsdk.FlowError{Session: s, Payment: got, Err: authFailed("payment was not signed")}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Payment: got, Raw: raw}, nil
}

// ---- status and cancel ----

func (c *client) toPayment(p *payState, status string, raw []byte) (*obsdk.Payment, error) {
	ref, err := flowstate.Encode(paymentRef{Integration: integrationID, ID: p.ID, Type: p.Type, Standing: p.Standing})
	if err != nil {
		return nil, err
	}
	pay := &obsdk.Payment{ID: p.ID, Type: p.Type, Status: obsdk.PaymentReceived, Ref: ref, Raw: raw, Schedule: p.Schedule}
	switch {
	case status == "":
	case p.Standing:
		pay.BankStatus = status
		pay.Status, pay.Final = standingStatus(status)
	default:
		pay.BankStatus = status
		pay.Status, pay.Final = cbs.PaymentStatus(status)
	}
	return pay, nil
}

// standingStatus maps a standing order's status. ACWC (accepted with a
// change, e.g. a moved date) still waits for the signature; ACSP means
// signed and set up, which KB says may still turn into RJCT.
func standingStatus(code string) (obsdk.PaymentStatus, bool) {
	switch code {
	case "ACSP":
		return obsdk.PaymentAccepted, false
	case "ACSC":
		return obsdk.PaymentAccepted, true
	case "RJCT", "RJCR":
		return obsdk.PaymentRejected, true
	}
	return obsdk.PaymentReceived, false // ACTC, ACWC, RCVD
}

func decodeRef(ref string) (*paymentRef, error) {
	var r paymentRef
	if err := flowstate.Decode(ref, &r); err != nil || r.Integration != integrationID || r.ID == "" {
		return nil, fmt.Errorf("%w: not a Komerční banka payment reference", obsdk.ErrInvalidRequest)
	}
	return &r, nil
}

// status reads a payment's status with the certificate alone.
func (c *client) status(ctx context.Context, p *payState) (*obsdk.Payment, []byte, error) {
	res, err := c.do(ctx, req{op: opPayStatus, method: http.MethodGet, path: p.base() + "/" + url.PathEscape(p.ID) + "/status", payment: true})
	if err != nil {
		return nil, nil, err
	}
	if res.status != http.StatusOK {
		return nil, nil, c.apiErr(opPayStatus, res)
	}
	var b struct {
		InstructionStatus string `json:"instructionStatus"`
	}
	if err := json.Unmarshal(res.body, &b); err != nil || b.InstructionStatus == "" {
		return nil, nil, fmt.Errorf("komercnibanka: unreadable payment status (HTTP %d)", res.status)
	}
	pay, err := c.toPayment(p, b.InstructionStatus, res.body)
	return pay, res.body, err
}

// PaymentStatus reads a payment's status. No session is needed.
func (c *client) PaymentStatus(ctx context.Context, ref string, _ obsdk.PaymentCallOptions) (*obsdk.Result[obsdk.Payment], error) {
	r, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	pay, raw, err := c.status(ctx, &payState{Type: r.Type, ID: r.ID, Standing: r.Standing})
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[obsdk.Payment]{Data: *pay, Raw: raw}, nil
}

// CancelPayment is not offered: KB executes signed payments the same day
// and they are irrevocable. (An unsigned payment expires on its own.)
func (c *client) CancelPayment(ctx context.Context, ref string, _ obsdk.PaymentCallOptions) (*obsdk.Step, error) {
	r, err := decodeRef(ref)
	if err != nil {
		return nil, err
	}
	if r.Standing {
		return nil, fmt.Errorf("%w: Komerční banka's API cannot cancel standing orders", obsdk.ErrUnsupported)
	}
	return nil, fmt.Errorf("%w: Komerční banka payments are irrevocable once signed", obsdk.ErrUnsupported)
}
