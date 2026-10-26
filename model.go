package obsdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

// Decimal is an exact decimal amount kept as text ("-425.65"). It never
// passes through floating point. Use Rat for arithmetic.
type Decimal string

func (d Decimal) String() string { return string(d) }

// Rat parses the amount exactly.
func (d Decimal) Rat() (*big.Rat, bool) { return new(big.Rat).SetString(string(d)) }

// Money is an amount in a currency. Amount is signed: negative leaves the account.
type Money struct {
	Amount   Decimal `json:"amount"`
	Currency string  `json:"currency"`
}

// Identifier is an account identifier such as IBAN or BBAN.
type Identifier struct {
	Scheme string `json:"scheme"` // "IBAN", "BBAN", or a bank-specific scheme
	Value  string `json:"value"`
}

// Account is a normalized account. ID is only valid inside the session that
// produced it (banks reissue it on re-authorization); use StableID to match an
// account across sessions.
type Account struct {
	ID          string          `json:"id"`
	StableID    string          `json:"stable_id"` // derived from IBAN (or another identifier) + currency; stable across sessions
	Identifiers []Identifier    `json:"identifiers"`
	Name        string          `json:"name,omitempty"`
	OwnerName   string          `json:"owner_name,omitempty"`
	Currency    string          `json:"currency,omitempty"` // "XXX" for multi-currency accounts
	Product     string          `json:"product,omitempty"`
	Type        string          `json:"type,omitempty"`  // ISO 20022 cash account type, e.g. CACC
	Usage       string          `json:"usage,omitempty"` // PRIV / ORGA when known
	BIC         string          `json:"bic,omitempty"`
	CreditLimit *Money          `json:"credit_limit,omitempty"`
	Balances    []Balance       `json:"balances,omitempty"` // only when the bank returned them inline
	Raw         json.RawMessage `json:"raw,omitempty"`
}

// BalanceKind is the normalized balance type.
type BalanceKind string

const (
	BalanceOpeningBooked    BalanceKind = "opening_booked"
	BalanceClosingBooked    BalanceKind = "closing_booked"
	BalanceInterimBooked    BalanceKind = "interim_booked"
	BalanceInterimAvailable BalanceKind = "interim_available"
	BalanceOther            BalanceKind = "other"
)

// Balance is a normalized balance.
type Balance struct {
	Kind          BalanceKind `json:"kind"`
	BankType      string      `json:"bank_type"` // the bank's own label, kept for fidelity
	Amount        Money       `json:"amount"`
	ReferenceDate string      `json:"reference_date,omitempty"` // YYYY-MM-DD when known
}

// TxStatus is booked or pending.
type TxStatus string

const (
	TxBooked  TxStatus = "booked"
	TxPending TxStatus = "pending"
)

// Direction is the money flow relative to the account holder. Banks disagree
// on sign conventions, so Amount is always normalized to signed and Direction
// is always set.
type Direction string

const (
	Debit  Direction = "debit"
	Credit Direction = "credit"
)

// Party is the other side of a transaction.
type Party struct {
	Name        string       `json:"name,omitempty"`
	Identifiers []Identifier `json:"identifiers,omitempty"`
}

// Transaction is a normalized transaction.
type Transaction struct {
	ID               string          `json:"id,omitempty"` // bank transaction id; may be absent or unstable on pending items
	EntryReference   string          `json:"entry_reference,omitempty"`
	Status           TxStatus        `json:"status"`
	Direction        Direction       `json:"direction"`
	Amount           Money           `json:"amount"`
	BookingDate      string          `json:"booking_date,omitempty"` // YYYY-MM-DD (banks differ on time zones; treat as a date, not an instant)
	ValueDate        string          `json:"value_date,omitempty"`
	TransactionDate  string          `json:"transaction_date,omitempty"`
	Counterparty     Party           `json:"counterparty"`
	Remittance       []string        `json:"remittance,omitempty"`
	ReferenceNumber  string          `json:"reference_number,omitempty"`
	EndToEndID       string          `json:"end_to_end_id,omitempty"`
	BankCode         string          `json:"bank_code,omitempty"`
	BankCodeText     string          `json:"bank_code_text,omitempty"`
	MerchantCategory string          `json:"merchant_category,omitempty"`
	BalanceAfter     *Money          `json:"balance_after,omitempty"`
	Raw              json.RawMessage `json:"raw,omitempty"`
}

// TxQuery selects transactions.
type TxQuery struct {
	AccountID string // Account.ID
	From, To  time.Time
	Status    []TxStatus // empty means booked only
	PageSize  int        // 0 lets the integration choose
	Cursor    string     // from TxPage.NextCursor; cursors can be short-lived and single-use
	Options   CallOptions
}

// TxPage is one page of transactions.
type TxPage struct {
	Transactions []Transaction   `json:"transactions"`
	NextCursor   string          `json:"next_cursor,omitempty"` // empty when there are no more pages
	Raw          json.RawMessage `json:"raw,omitempty"`         // raw bank response(s)
}

// StandingOrder is a standing order on one of the user's accounts, as read
// by StandingOrderLister. Fields the bank does not send stay empty.
type StandingOrder struct {
	ID        string      `json:"id"`
	Name      string      `json:"name,omitempty"`       // the user's name for it, where the bank keeps one
	Debtor    *Identifier `json:"debtor,omitempty"`     // the account it pays from
	AccountID string      `json:"account_id,omitempty"` // that account's Account.ID, when the bank says
	Creditor  Creditor    `json:"creditor"`
	Amount    Money       `json:"amount"`

	// Schedule is what the bank reports: StartDate is its requested
	// execution date (the first or the next one, depending on the bank).
	// Frequency stays empty when the bank's interval has no equivalent;
	// Interval keeps the bank's own code.
	Schedule Schedule `json:"schedule"`
	Interval string   `json:"interval,omitempty"`

	Remittance []string        `json:"remittance,omitempty"`
	Reference  *Reference      `json:"reference,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// StandingOrderQuery asks for a page of standing orders.
type StandingOrderQuery struct {
	PageSize int    // 0 lets the integration choose
	Cursor   string // from StandingOrderPage.NextCursor
	Options  CallOptions
}

// StandingOrderPage is one page of standing orders.
type StandingOrderPage struct {
	StandingOrders []StandingOrder `json:"standing_orders"`
	NextCursor     string          `json:"next_cursor,omitempty"` // empty when there are no more pages
}

// Meta is response metadata worth surfacing.
type Meta struct {
	RequestID string
	RateLimit *RateLimit
}

// RateLimit mirrors the bank's throttling headers when present.
type RateLimit struct {
	Limit, Remaining int
	ResetIn          time.Duration
}

// Result wraps a call's data. Session is non-nil when the call changed the
// session (for example after an automatic update); persist it when set.
type Result[T any] struct {
	Data    T
	Session *Session
	Raw     json.RawMessage
	Meta    Meta
}

// TxResult is the outcome of Transactions: either a page, or a Step the user
// must complete first (for example Swedbank's extra approval beyond 90 days).
// After the step finishes, Resume returns a StepDone whose Transactions field
// holds the data.
type TxResult struct {
	TxPage
	Step    *Step
	Session *Session
	Meta    Meta
}

// StableAccountID derives an identifier that survives re-authorization from
// the account's IBAN (any other identifier when there is none) plus its
// currency. The currency is part of the key because multi-currency accounts
// list one entry per currency under the same IBAN.
func StableAccountID(ids []Identifier, currency string) string {
	var key string
	for _, id := range ids {
		if id.Scheme == SchemeIBAN && id.Value != "" {
			key = "IBAN:" + strings.ToUpper(strings.ReplaceAll(id.Value, " ", ""))
			break
		}
	}
	if key == "" {
		for _, id := range ids {
			if id.Value != "" {
				key = id.Scheme + ":" + id.Value
				break
			}
		}
	}
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key + ":" + strings.ToUpper(currency)))
	return hex.EncodeToString(sum[:16])
}
