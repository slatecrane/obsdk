package obsdk

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Country is an ISO 3166-1 alpha-2 code, e.g. "SE".
type Country string

// Env selects sandbox or production APIs. It must always be set explicitly.
type Env string

const (
	Sandbox    Env = "sandbox"
	Production Env = "production"
)

// Segment distinguishes personal from business accounts.
type Segment string

const (
	Personal Segment = "personal"
	Business Segment = "business"
)

// Capability is a stable identifier for something an integration can do.
type Capability string

const (
	CapAccounts            Capability = "aisp.accounts"
	CapBalances            Capability = "aisp.balances"
	CapTransactions        Capability = "aisp.transactions"
	CapTransactionsHistory Capability = "aisp.transactions_history" // beyond the bank's default window (e.g. 90 days)
	CapPayments            Capability = "pisp.payments"
)

// AISP lists the account information capabilities.
var AISP = []Capability{CapAccounts, CapBalances, CapTransactions}

// Target says which bank the caller wants. Callers never see integration
// names; the registry resolves the implementation.
type Target struct {
	Bank    string  // stable bank key, e.g. "swedbank"
	Country Country // e.g. "SE"
	Segment Segment // optional; empty means "whatever is available" (personal if unambiguous)
}

// Secret hides a value from fmt, JSON and slog output.
type Secret string

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "obsdk.Secret(\"[redacted]\")" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") }

// Reveal returns the underlying value.
func (s Secret) Reveal() string { return string(s) }

// Credentials are the TPP application credentials most banks need.
type Credentials struct {
	ClientID     string
	ClientSecret Secret
	RedirectURL  string // default redirect; may be overridden per Connect call
}

// Seal is the QSealC key and certificate used to sign requests. The key may
// live in an HSM or KMS: only crypto.Signer is required.
type Seal struct {
	Key         crypto.Signer
	Certificate *x509.Certificate
	KeyID       string // optional; some banks want an explicit keyId
}

// HTTPDoer is the only thing the SDK needs from an HTTP client. *http.Client
// satisfies it; tests can pass a stub or a client whose Transport replays
// recorded exchanges (see package obsdktest).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Purposes passed to Config.NewID.
const (
	IDState   = "state"   // OAuth state values (must be reproducible for replayed callbacks)
	IDRequest = "request" // X-Request-ID style identifiers
)

// Config is everything needed to build a client. It is never serialized.
type Config struct {
	Env         Env // required: Sandbox or Production
	Credentials Credentials

	// Extra holds bank-specific parameters. Integrations declare the names
	// they accept in Info.Requirements.
	Extra map[string]string

	// HTTPClient carries transport concerns, in particular the QWAC client
	// certificate for mTLS. Defaults to a client with a 30s timeout. Anything
	// with a Do method works, which is how tests inject recorded responses.
	HTTPClient HTTPDoer

	// Seal is the optional QSealC signer.
	Seal *Seal

	Logger *slog.Logger
	Now    func() time.Time // for tests; defaults to time.Now

	// NewID produces identifiers (OAuth state, request ids). Defaults to random
	// UUIDs. Tests inject deterministic values so replayed callbacks match.
	NewID func(purpose string) string
}

// ID returns a new identifier for the given purpose.
func (c Config) ID(purpose string) string {
	if c.NewID != nil {
		return c.NewID(purpose)
	}
	return NewUUID()
}

// NewUUID returns a random version-4 UUID.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Clock returns the configured time source.
func (c Config) Clock() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Param returns an Extra value.
func (c Config) Param(name string) string { return c.Extra[name] }

// PSUContext describes the end user's device. Banks treat requests that carry
// it as user-initiated, which affects rate limits and consent usage. Omit it
// for unattended background refreshes.
type PSUContext struct {
	IP          string
	Port        string
	UserAgent   string
	ID          string // bank login id / national id, where the bank asks for it
	CorporateID string
}

// CallOptions are optional per-call inputs.
type CallOptions struct {
	PSU *PSUContext
}
