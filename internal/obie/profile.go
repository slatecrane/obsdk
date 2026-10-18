// Package obie implements the UK Open Banking (OBIE) Read/Write API, versions
// 3.1.x, once, for every bank that runs it: account access consents
// authorised through the OIDC hybrid flow with a signed request object,
// accounts, balances and transactions, and payment consents with the
// payment submitted after the user's approval.
//
// It is not a bank. Bank packages describe their bank with a Profile (hosts,
// API paths, client authentication, signing details, payment bodies) and
// call Register; the bank is then discoverable under its own key like any
// other.
package obie

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// ClientAuth is how the client authenticates at the token endpoint.
type ClientAuth string

const (
	// TLSClientAuth sends client_id only; the mTLS certificate authenticates
	// the client (RFC 8705 tls_client_auth).
	TLSClientAuth ClientAuth = "tls_client_auth"
	// PrivateKeyJWT signs a client assertion with the seal key.
	PrivateKeyJWT ClientAuth = "private_key_jwt"
)

// Issuer is what the request object's iss claim holds.
type Issuer string

const (
	IssuerClientID Issuer = "client_id" // the OAuth client id (OIDC default)
	IssuerCertDN   Issuer = "cert_dn"   // the signing certificate's subject DN (RFC 2253)
)

// Consent kinds in openbanking_intent_id (Profile.IntentID).
const (
	KindAccount = "account"
	KindPayment = "payment"
)

// Profile describes one bank's OBIE interface.
type Profile struct {
	// ID is the integration id stored in sessions (e.g. "crosskey-s-pankki").
	ID string

	// Info is the discovery record. Spec is set to "uk".
	Info obsdk.Info

	// APIHost is the host of the token endpoint and the resource APIs, e.g.
	// https://api.bank.example. Config.Extra "base_url" overrides it.
	APIHost func(env obsdk.Env, t obsdk.Target) string

	// AuthURL is the full authorisation endpoint. Config.Extra "auth_url"
	// overrides it.
	AuthURL func(env obsdk.Env, t obsdk.Target) string

	// TokenPath is the token endpoint's path on APIHost.
	TokenPath string

	// AISPath and PISPath are the base paths of the account and payment APIs,
	// e.g. /open-banking/v3.1.6/aisp.
	AISPath, PISPath string

	// ClientAuth defaults to TLSClientAuth.
	ClientAuth ClientAuth

	// RequestObjectIssuer defaults to IssuerClientID.
	RequestObjectIssuer Issuer

	// RequestObjectTTL is how long the request object is valid (exp - nbf);
	// it bounds how long the user may take to open the authorisation link.
	// Zero means 10 minutes. FAPI caps it at 60.
	RequestObjectTTL time.Duration

	// IntentID builds openbanking_intent_id from a consent kind (KindAccount,
	// KindPayment) and the consent id. nil sends the consent id.
	IntentID func(kind, consentID string) string

	// KeyID is the kid of every JWS. nil uses Seal.KeyID.
	KeyID func(seal *obsdk.Seal) string

	// Signature describes x-jws-signature on payment requests.
	Signature Signature

	// RequiredParams are Config.Extra keys the client cannot work without.
	RequiredParams []string

	// Headers adds bank-specific headers to every resource request (e.g. an
	// API key); not to the token endpoint.
	Headers func(cfg obsdk.Config, t obsdk.Target, h http.Header)

	// Payments builds the bank's payment bodies. nil: no payments.
	Payments PaymentBuilder
}

// Signature is the shape of the detached JWS sent as x-jws-signature.
type Signature struct {
	// Unencoded signs the body as is (RFC 7797, "b64": false in crit), as
	// OBIE before v3.1.4. The default signs the base64url-encoded body.
	Unencoded bool

	// TAN is the trust anchor (http://openbanking.org.uk/tan). apiHost is the
	// host name without scheme. nil means "openbanking.org.uk".
	TAN func(cfg obsdk.Config, apiHost string) string

	// Typ and Cty are the typ and cty header values; empty leaves them out.
	Typ, Cty string
}

// PaymentBuilder turns a validated request into the bank's payment family
// (the path prefix: "domestic", "international-scheduled", ...) and the
// Initiation and Risk objects. newID returns a fresh identifier.
type PaymentBuilder func(r obsdk.PaymentRequest, t obsdk.Target, newID func() string) (family string, initiation, risk any, err error)

func (p *Profile) clientAuth() ClientAuth {
	if p.ClientAuth == "" {
		return TLSClientAuth
	}
	return p.ClientAuth
}

func (p *Profile) intentID(kind, id string) string {
	if p.IntentID == nil {
		return id
	}
	return p.IntentID(kind, id)
}

// Register validates the profile and registers the bank. Bank packages call
// it from init; mistakes panic like obsdk.Register.
func Register(p Profile) {
	obsdk.Register(Integration(p))
}

// Integration builds the obsdk.Integration for a profile without registering it.
func Integration(p Profile) obsdk.Integration {
	switch {
	case p.ID == "" || p.APIHost == nil || p.AuthURL == nil:
		panic(fmt.Sprintf("obie: profile %q needs an ID, APIHost and AuthURL", p.Info.Bank))
	case p.TokenPath == "" || !strings.HasPrefix(p.AISPath, "/"):
		panic(fmt.Sprintf("obie: profile %q needs a TokenPath and an AISPath", p.ID))
	case len(p.Info.Payments) > 0 && (p.Payments == nil || p.PISPath == ""):
		panic(fmt.Sprintf("obie: profile %q has payment specs but no PISPath or Payments builder", p.ID))
	}
	switch p.clientAuth() {
	case TLSClientAuth, PrivateKeyJWT:
	default:
		panic(fmt.Sprintf("obie: profile %q: unknown client auth %q", p.ID, p.ClientAuth))
	}
	p.Info.Spec = "uk"
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
