package obsdk

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors, for use with errors.Is.
var (
	// ErrAccessExpired: the access token is expired. Call Refresh, then retry.
	ErrAccessExpired = errors.New("obsdk: access token expired")
	// ErrReauthRequired: the session or consent is no longer usable and the
	// user must authorize again (Connect). Refreshing will not help.
	ErrReauthRequired = errors.New("obsdk: user must re-authorize")
	// ErrAuthFailed: the user failed or cancelled an authorization step.
	ErrAuthFailed = errors.New("obsdk: authorization failed")
	// ErrRateLimited: the bank throttled the request.
	ErrRateLimited = errors.New("obsdk: rate limited")
	// ErrUnsupported: this integration does not implement the operation.
	ErrUnsupported = errors.New("obsdk: operation not supported")
	// ErrInvalidConfig: Config is missing something the integration needs.
	ErrInvalidConfig = errors.New("obsdk: invalid configuration")
	// ErrInvalidRequest: the caller passed an invalid or incomplete request.
	ErrInvalidRequest = errors.New("obsdk: invalid request")
	// ErrUnknownBank: no integration is registered for the bank.
	ErrUnknownBank = errors.New("obsdk: unknown bank")
	// ErrUnsupportedTarget: the bank exists but not for this country, segment or environment.
	ErrUnsupportedTarget = errors.New("obsdk: unsupported target")
	// ErrAmbiguousTarget: several integrations match; specify Segment.
	ErrAmbiguousTarget = errors.New("obsdk: ambiguous target")
	// ErrRefreshFailed: a token refresh failed; see RefreshError.Temporary.
	ErrRefreshFailed = errors.New("obsdk: token refresh failed")
)

// APIError is a bank error response, classified when possible.
type APIError struct {
	Op        string // SDK operation, e.g. "transactions"
	Status    int
	Code      string // bank error code, e.g. "TOKEN_INVALID"
	Text      string
	RequestID string
	Body      []byte // raw response body for debugging (may contain personal data)
	kind      error  // classification, matched by errors.Is
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "obsdk: %s: HTTP %d", e.Op, e.Status)
	if e.Code != "" {
		fmt.Fprintf(&b, " %s", e.Code)
	}
	if e.Text != "" {
		fmt.Fprintf(&b, ": %s", e.Text)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " (request %s)", e.RequestID)
	}
	return b.String()
}

func (e *APIError) Is(target error) bool { return e.kind != nil && e.kind == target }

// Classify returns a copy of e that matches the given sentinel with errors.Is.
func (e *APIError) Classify(kind error) *APIError { c := *e; c.kind = kind; return &c }

// ReauthError explains why the user must re-authorize.
type ReauthError struct {
	Reason  string // e.g. "consent_expired", "consent_revoked", "refresh_token_invalid"
	Consent string // consent kind, if relevant
	Err     error
}

func (e *ReauthError) Error() string {
	s := "obsdk: user must re-authorize: " + e.Reason
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}
func (e *ReauthError) Unwrap() error   { return e.Err }
func (e *ReauthError) Is(t error) bool { return t == ErrReauthRequired }

// RateLimitedError carries the bank's retry hint when it gave one.
type RateLimitedError struct {
	RetryAfter time.Duration
	Err        error
}

func (e *RateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("obsdk: rate limited, retry after %s", e.RetryAfter)
	}
	return "obsdk: rate limited"
}
func (e *RateLimitedError) Unwrap() error   { return e.Err }
func (e *RateLimitedError) Is(t error) bool { return t == ErrRateLimited }

// RefreshError reports a failed refresh. Temporary errors (network, 5xx,
// throttling) are worth retrying a few times; permanent ones usually mean the
// user must re-authorize (possibly because another instance already rotated
// the refresh token: reload the session before giving up).
type RefreshError struct {
	Temporary bool
	Err       error
}

func (e *RefreshError) Error() string {
	return fmt.Sprintf("obsdk: token refresh failed (temporary=%t): %v", e.Temporary, e.Err)
}
func (e *RefreshError) Unwrap() error   { return e.Err }
func (e *RefreshError) Is(t error) bool { return t == ErrRefreshFailed }

// FlowError is returned by Connect and Resume when an operation fails after
// the bank already issued a session, e.g. login succeeded but consent creation
// failed. Persist Session anyway: at banks that allow one token per user, the
// new login has already invalidated the previous session.
type FlowError struct {
	Session *Session
	Payment *Payment // set when a payment flow fails after the bank created the payment
	Err     error
}

func (e *FlowError) Error() string { return e.Err.Error() }
func (e *FlowError) Unwrap() error { return e.Err }

// ConfigError lists missing or invalid configuration.
type ConfigError struct {
	Bank    string
	Env     Env
	Missing []string
	Invalid []string
}

func (e *ConfigError) Error() string {
	var parts []string
	if len(e.Missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(e.Missing, ", "))
	}
	if len(e.Invalid) > 0 {
		parts = append(parts, "invalid: "+strings.Join(e.Invalid, ", "))
	}
	return fmt.Sprintf("obsdk: %s (%s) configuration: %s", e.Bank, e.Env, strings.Join(parts, "; "))
}
func (e *ConfigError) Is(t error) bool { return t == ErrInvalidConfig }

// AmbiguousTargetError lists the segments that would disambiguate a target.
type AmbiguousTargetError struct {
	Target   Target
	Segments []Segment
}

func (e *AmbiguousTargetError) Error() string {
	return fmt.Sprintf("obsdk: target %s/%s matches several integrations; set Segment to one of %v", e.Target.Bank, e.Target.Country, e.Segments)
}
func (e *AmbiguousTargetError) Is(t error) bool { return t == ErrAmbiguousTarget }
