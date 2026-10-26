package obsdk

import "context"

// Client is the stateless per-bank client. It is safe for concurrent use.
type Client interface {
	// Info describes this client's bank, resolved for its country and environment.
	Info() Info

	// Connect starts authorization: login, consents and account discovery as
	// the bank requires. It returns the first Step; drive the rest with Resume.
	Connect(ctx context.Context, req ConnectRequest) (*Step, error)

	// Resume continues any resumable operation (Connect, a payment, or a
	// transaction export that needed approval) from Step.State.
	//
	// Connect and Resume save the session on every Step that has one; when they
	// fail after the bank issued a session, the error is a *FlowError carrying it.
	Resume(ctx context.Context, state string, in StepInput) (*Step, error)

	// Accounts lists the accounts covered by the session's consent.
	Accounts(ctx context.Context, s *Session, opts CallOptions) (*Result[[]Account], error)

	// Balances returns the balances of one account (Account.ID).
	Balances(ctx context.Context, s *Session, accountID string, opts CallOptions) (*Result[[]Balance], error)

	// Transactions returns a page of transactions, or a Step when the bank
	// needs the user to approve access to older history.
	Transactions(ctx context.Context, s *Session, q TxQuery) (*TxResult, error)

	// Refresh renews the access token. It returns ErrReauthRequired inside a
	// RefreshError when the user has to log in again.
	Refresh(ctx context.Context, s *Session) (*Session, error)

	// Disconnect ends the bank-side consents where the bank allows it. The
	// returned session is updated; failures to close are reported, not fatal.
	Disconnect(ctx context.Context, s *Session) (*DisconnectResult, error)

	// InitiatePayment validates the request against the bank's PaymentSpec,
	// creates the payment and returns the first Step (login and/or the user's
	// approval). StepDone carries Step.Payment; drive the rest with Resume.
	// Once the bank has created the payment, every Step carries it, so its id
	// can be recorded even if the user abandons the approval.
	InitiatePayment(ctx context.Context, req PaymentRequest) (*Step, error)

	// PaymentStatus reads a payment's current status from Payment.Ref.
	PaymentStatus(ctx context.Context, ref string, opts PaymentCallOptions) (*Result[Payment], error)

	// CancelPayment cancels a payment that has not been executed yet (usually
	// a future-dated one). The bank may want the user's approval, so it
	// returns a Step; StepDone carries the updated Payment.
	CancelPayment(ctx context.Context, ref string, opts PaymentCallOptions) (*Step, error)
}

// ConnectRequest starts authorization.
type ConnectRequest struct {
	// Method picks the login approach when the bank offers several, e.g.
	// "redirect" or "decoupled". Empty lets the integration choose its default.
	Method string

	// Capabilities to request. Empty means all AISP capabilities.
	Capabilities []Capability

	// PSU is the user's device context. Many banks require at least the IP and
	// user agent for consent creation.
	PSU PSUContext

	// RedirectURL overrides Config.Credentials.RedirectURL.
	RedirectURL string

	// Language for bank pages, when supported (ISO 639-1).
	Language string

	// Values pre-fills answers to input steps (auth_method, personal_id, ...)
	// so the user is not asked twice.
	Values map[string]string

	// ConsentValidity is the requested consent lifetime; the integration
	// clamps it to what the bank allows. Zero uses a sensible default.
	ConsentValidityDays int
}

// DisconnectResult reports what happened to each consent.
type DisconnectResult struct {
	Session *Session
	Closed  []string          // consent kinds closed at the bank
	Failed  map[string]string // consent kind -> reason
}

// AuthMethod is a login/SCA method offered by a bank.
type AuthMethod struct {
	ID       string // bank id, e.g. "SMART_ID"
	Name     string // human name, e.g. "Smart-ID"
	Approach string // "redirect" or "decoupled"
}

// StandingOrderLister is implemented by integrations that can read the
// standing orders on the user's accounts (Info lists CapStandingOrders).
// It takes the session of Connect.
type StandingOrderLister interface {
	StandingOrders(ctx context.Context, s *Session, q StandingOrderQuery) (*Result[StandingOrderPage], error)
}

// AuthMethodLister is implemented by integrations that can report, at
// runtime, the login methods currently offered (static ones are in Info).
type AuthMethodLister interface {
	AuthMethods(ctx context.Context) ([]AuthMethod, error)
}
