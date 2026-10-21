// Package stet implements the STET PSD2 API (versions 1.4.x to 1.6.x) once,
// for every bank that runs it: the user's OAuth2 authorization (authorization
// code grant) for account information, the optional forwarding of the user's
// consent (PUT /consents), accounts, balances and transactions, and payment
// requests created with a client token, approved by the user on the bank's
// page and then confirmed.
//
// STET has no consent resources: the access token is the consent. It is not a
// bank. Bank packages describe their bank with a Profile (hosts, OAuth
// details, signing, payment confirmation) and call Register; the bank is then
// discoverable under its own key like any other.
//
// The specification is published by STET under CC BY 3.0 FR:
// https://www.stet.eu/en/psd2/
package stet

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// ClientAuth is how the client authenticates at the token endpoint.
type ClientAuth string

const (
	// TLSClientAuth sends client_id only; the QWAC presented over mTLS
	// authenticates the client (RFC 8705), as the STET framework describes.
	TLSClientAuth ClientAuth = "tls_client_auth"
	// ClientSecretPost sends client_id and client_secret in the form.
	ClientSecretPost ClientAuth = "client_secret_post"
	// ClientSecretBasic sends them as HTTP Basic credentials.
	ClientSecretBasic ClientAuth = "client_secret_basic"
)

// Confirmation is how a payment request is confirmed after the user approved it.
type Confirmation string

const (
	// ConfirmClientToken posts the confirmation with a client-credentials
	// token once the user is back from the approval page.
	ConfirmClientToken Confirmation = "client_token"
	// ConfirmAuthorizationCode is STET's "enforced redirect": the approval
	// link is an authorization endpoint the PISP completes with its own OAuth
	// parameters; the code from the callback is exchanged for a token, and
	// that token posts the confirmation.
	ConfirmAuthorizationCode Confirmation = "authorization_code"
	// ConfirmNone: the bank executes the payment after the approval; there is
	// nothing to confirm, only the status to read.
	ConfirmNone Confirmation = "none"
)

// Scopes are the OAuth2 scope values a bank uses.
type Scopes struct {
	AIS     string // default "aisp"
	PIS     string // default "pisp"
	History string // extra scope for more than 90 days of history; default "extended_transaction_history", "-" for none
}

// Profile describes one bank's STET interface.
type Profile struct {
	// ID is the integration id stored in sessions (e.g. "bnpparibasfortis").
	ID string

	// Info is the discovery record. Spec is set to "stet".
	Info obsdk.Info

	// APIBase is the API root including its base path, e.g.
	// https://api.bank.example/psd2/v1; resource paths (/accounts, ...) are
	// appended to it. Config.Extra "base_url" overrides it.
	APIBase func(env obsdk.Env, t obsdk.Target) string

	// AuthURL is the authorization endpoint. Config.Extra "auth_url" overrides it.
	AuthURL func(env obsdk.Env, t obsdk.Target) string

	// TokenURL is the token endpoint. Config.Extra "token_url" overrides it.
	TokenURL func(env obsdk.Env, t obsdk.Target) string

	// ClientAuth defaults to TLSClientAuth.
	ClientAuth ClientAuth

	// Scopes defaults to the specification's values.
	Scopes Scopes

	// TokenScope also sends the AIS scope when exchanging the user's code and
	// refreshing the token (some banks' token endpoints fail without it).
	TokenScope bool

	// PKCE sends an S256 code challenge (RFC 7636) with the authorization request.
	PKCE bool

	// ForwardConsent: the bank runs STET's "mixed" consent model (A2). After
	// the login the accounts are listed, the user's choice (here: every
	// listed account, for the capabilities requested) is forwarded with
	// PUT /consents, and the accounts are listed again.
	ForwardConsent bool

	// Confirmation defaults to ConfirmClientToken.
	Confirmation Confirmation

	// Signing configures the http-signature on every request. nil: requests
	// are not signed.
	Signing *Signing

	// DateQuery formats dateFrom and dateTo of the transactions query. nil
	// sends RFC 3339 date-times (the specification's format, in UTC).
	DateQuery func(time.Time) string

	// RevokeURL is the token revocation endpoint (RFC 7009), when the bank
	// has one. STET itself has no way to end the user's authorization.
	RevokeURL func(env obsdk.Env, t obsdk.Target) string

	// AuthParams adds bank-specific parameters to the authorization request
	// (e.g. a brand).
	AuthParams func(cfg obsdk.Config, t obsdk.Target, q url.Values)

	// Headers adds bank-specific headers to every resource request; not to
	// the token endpoint.
	Headers func(cfg obsdk.Config, t obsdk.Target, h http.Header)

	// PaymentHeaders adds headers to the requests that create or cancel a
	// payment request only.
	PaymentHeaders func(cfg obsdk.Config, t obsdk.Target, h http.Header)

	// Query adds bank-specific query parameters to every resource request,
	// links followed included; not to the token endpoint.
	Query func(cfg obsdk.Config, t obsdk.Target) url.Values

	// PaymentLevel puts the beneficiary and the requested execution date of
	// a single-transfer payment at payment level, as STET allows and some
	// banks require, instead of in the credit transfer. The execution date
	// is then always sent: the creation time when the request has none.
	PaymentLevel bool

	// AmountString sends payment amounts as JSON strings, as some banks'
	// schemas want, instead of the specification's numbers.
	AmountString bool

	// CancelStatus is the paymentInformationStatus that asks for a
	// cancellation; empty is "CANC". Some banks want "RJCT" (with the
	// reason DS02, which is always sent).
	CancelStatus string

	// RequiredParams are Config.Extra keys the client cannot work without.
	RequiredParams []string

	// AdjustPayment changes the payment request body before it is sent, for
	// a bank's deviations from the specification. Optional.
	AdjustPayment func(r obsdk.PaymentRequest, t obsdk.Target, body *PaymentRequestBody) error
}

func (p *Profile) clientAuth() ClientAuth {
	if p.ClientAuth == "" {
		return TLSClientAuth
	}
	return p.ClientAuth
}

func (p *Profile) confirmation() Confirmation {
	if p.Confirmation == "" {
		return ConfirmClientToken
	}
	return p.Confirmation
}

func (p *Profile) cancelStatus() string { return firstNonEmpty(p.CancelStatus, "CANC") }

func (p *Profile) scopeAIS() string { return firstNonEmpty(p.Scopes.AIS, "aisp") }
func (p *Profile) scopePIS() string { return firstNonEmpty(p.Scopes.PIS, "pisp") }

func (p *Profile) scopeHistory() string {
	if p.Scopes.History == "-" {
		return ""
	}
	return firstNonEmpty(p.Scopes.History, "extended_transaction_history")
}

// Register validates the profile and registers the bank. Bank packages call
// it from init; mistakes panic like obsdk.Register.
func Register(p Profile) {
	obsdk.Register(Integration(p))
}

// Integration builds the obsdk.Integration for a profile without registering it.
func Integration(p Profile) obsdk.Integration {
	if p.ID == "" || p.APIBase == nil || p.AuthURL == nil || p.TokenURL == nil {
		panic(fmt.Sprintf("stet: profile %q needs an ID, APIBase, AuthURL and TokenURL", p.Info.Bank))
	}
	switch p.clientAuth() {
	case TLSClientAuth, ClientSecretPost, ClientSecretBasic:
	default:
		panic(fmt.Sprintf("stet: profile %q: unknown client auth %q", p.ID, p.ClientAuth))
	}
	switch p.confirmation() {
	case ConfirmClientToken, ConfirmAuthorizationCode, ConfirmNone:
	default:
		panic(fmt.Sprintf("stet: profile %q: unknown confirmation %q", p.ID, p.Confirmation))
	}
	p.Info.Spec = "stet"
	if len(p.Info.Auth.Approaches) == 0 {
		p.Info.Auth.Approaches = []string{"redirect"}
	}
	prof := p
	return obsdk.Integration{
		ID:      p.ID,
		Info:    p.Info,
		Factory: func(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) { return newClient(&prof, cfg, t) },
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
