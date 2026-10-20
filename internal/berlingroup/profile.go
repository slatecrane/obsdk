// Package berlingroup implements the Berlin Group NextGenPSD2 XS2A interface
// (versions 1.3.x) once, for every bank that runs it: AIS consents, accounts,
// balances and transactions; single payments with status and cancellation;
// and the SCA approaches the standard defines (redirect, decoupled and
// embedded), driven by the steering links the bank returns.
//
// It is not a bank. Bank packages describe their bank with a Profile (hosts,
// supported approaches, payment products, consent model, quirks) and call
// Register; the bank is then discoverable under its own key like any other.
package berlingroup

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
)

// SCA approaches (ConnectRequest.Method, PaymentRequest.Method).
const (
	Redirect  = "redirect"
	Decoupled = "decoupled"
	Embedded  = "embedded"
)

// ConsentModel is the kind of AIS consent Connect asks for when the caller
// names no accounts (ConnectRequest.Values["iban"] always gives a dedicated
// consent for those accounts).
type ConsentModel string

const (
	// ConsentGlobal asks for all accounts with allPsd2: allAccounts.
	ConsentGlobal ConsentModel = "global"
	// ConsentBankOffered sends empty account lists; the user picks the
	// accounts on the bank's pages (redirect approach only, at most banks).
	ConsentBankOffered ConsentModel = "bank_offered"
)

// PSUIDUse says whether the bank needs the user's login id (PSU-ID) on the
// request that creates a consent or payment.
type PSUIDUse string

const (
	PSUIDNone     PSUIDUse = ""         // sent when the caller has one, never asked for
	PSUIDRequired PSUIDUse = "required" // asked for (field psu_id) before the consent or payment is created, and needed to cancel
)

// Profile describes one bank's Berlin Group interface.
type Profile struct {
	// ID is the integration id stored in sessions (e.g. "unicredit-bg-de").
	ID string

	// Info is the discovery record. Spec is set to "berlin-group"; Payments
	// should be built with the helpers in specs.go.
	Info obsdk.Info

	// BaseURL returns the API root for a target, without the "/v1" that every
	// path starts with, e.g. https://api.bank.example/xs2a. institution is
	// the value of Institution.Param (empty for banks without one). Config.Extra
	// "base_url" overrides it (tests, proxies, local sandboxes).
	BaseURL func(env obsdk.Env, t obsdk.Target, institution string) string

	// Institution is set for hubs that serve many banks under one API
	// (Sparkassen, Volksbanken), where a parameter such as the bank code picks
	// the bank. It is read from Config.Extra when a consent or payment is
	// created and then kept in the session, the flow state and the payment
	// reference, so later calls reach the same bank.
	Institution *Institution

	// Approaches the bank offers, in order of preference; the first is the
	// default. Empty means redirect only.
	Approaches []string

	// Consent is the consent asked for when the caller names no accounts.
	// Empty means ConsentGlobal.
	Consent ConsentModel

	// MaxConsentDays caps validUntil; DefaultConsentDays applies when the
	// caller asks for none. Zero means 90 and 90.
	MaxConsentDays, DefaultConsentDays int

	// FrequencyPerDay is the consent's frequencyPerDay. Zero means 4.
	FrequencyPerDay int

	// BookingStatuses the bank accepts in bookingStatus: "booked", "pending",
	// "both". Empty means booked only.
	BookingStatuses []string

	// Products maps payment types to the bank's payment-product path segment
	// (e.g. PaymentSEPA -> "sepa-credit-transfers").
	Products map[obsdk.PaymentType]string

	// PSUID tells whether the bank wants PSU-ID when a consent or payment is
	// created.
	PSUID PSUIDUse

	// NoNokRedirect leaves out TPP-Nok-Redirect-URI. By default it is sent as
	// the redirect URL with error=access_denied added, so a refusal at the
	// bank reaches Resume as an error.
	NoNokRedirect bool

	// Signing is the request signature, for banks that require or accept one.
	Signing *Signing

	// StructuredRemittanceString sends remittanceInformationStructured as a
	// plain string (the reference), as before version 1.3.8; the default is
	// the object {reference, referenceType, referenceIssuer}.
	StructuredRemittanceString bool

	// ReferenceInEndToEnd sends the creditor reference (Transfer.Reference) as
	// endToEndIdentification, for banks that read the reference from there
	// (Samlink) instead of remittanceInformationStructured.
	ReferenceInEndToEnd bool

	// LegacyAddress sends creditorAddress with the field names before 1.3.8
	// (street, city, postalCode); the default is streetName, townName,
	// postCode. Banks mix versions, so the two are separate.
	LegacyAddress bool

	// NoWithBalance leaves out withBalance=true when listing accounts, for
	// banks that refuse it.
	NoWithBalance bool

	// EntryReferencePaging pages booked transactions by entry reference
	// (Samlink): the response names the entry reference to continue from
	// (relevantEntryReference), which the next request sends as
	// entryReferenceFrom without dates. A date range is always sent with both
	// ends, and pending transactions without dates.
	EntryReferencePaging bool

	// XMLTransactions asks for transactions with Accept: application/xml, for
	// banks that report them only as camt.052 (camt.053 and camt.054 are read
	// the same way). The response is parsed by its content, so a bank that
	// answers JSON anyway still works.
	XMLTransactions bool

	// PaymentXML sends payments as pain.001 XML (pain.001.001.09 in the German
	// GBIC_5 profile) and reads pain.002 status reports, for banks whose
	// payment products are "pain.001-…" only. Products must then name those.
	PaymentXML bool

	// OAuthNoRedirectURI leaves redirect_uri out of the OAuth authorisation
	// and token requests of the OAuth SCA approach, for banks that take the
	// redirect URI from TPP-Redirect-URI and document no such parameter.
	OAuthNoRedirectURI bool

	// OAuthClientAuth authenticates the client at the OAuth token endpoint
	// (code exchange and refresh). It may add to the form (a private_key_jwt
	// client assertion) or set headers (HTTP Basic with a client secret, an
	// API key). Nil sends client_id only, as a public client with PKCE.
	OAuthClientAuth func(cfg obsdk.Config, tokenURL string, form url.Values, h http.Header) error

	// PathVersion replaces the "v1" path segment of every request, for banks
	// that put a finer version there (SIBS: "v1-0-4"). Links the bank returns
	// may use either form.
	PathVersion string

	// AISPathVersion replaces the "v1" segment of account information paths
	// (consents, accounts, card accounts, funds confirmations), for banks that
	// serve those on a later version than payments (Samlink: "v2").
	AISPathVersion string

	// CreatePathVersion replaces the "v1" segment of the two requests that
	// create a resource (POST /v1/consents, POST /v1/payments/{product}), for
	// banks that versioned only those (Redsys: "v1.1"); every other path,
	// and the links the bank returns, stay on "v1".
	CreatePathVersion string

	// PreStep is an OAuth2 authorisation the bank wants before any XS2A
	// request (Redsys): the user logs in at the bank first, and every later
	// request carries the access token. See PreStep.
	PreStep *PreStep

	// AllAccountsValue is the value of allPsd2 in a global consent. Empty is
	// the standard's "allAccounts"; some banks spell it "all-accounts".
	AllAccountsValue string

	// ValidUntilLayout is the time layout of the consent's validUntil. Empty
	// is a date (2006-01-02); some banks want a date-time.
	ValidUntilLayout string

	// DateLayout sends a Date header on every request in this time layout
	// (UTC), for banks that require one outside of request signing or want it
	// in ISO 8601 instead of the HTTP date. A signature includes it.
	DateLayout string

	// BodyDigest sends a Digest of the body on requests that have one, also
	// when they are not signed (SIBS's sandbox checks it, and refuses one on
	// requests without a body).
	BodyDigest bool

	// Headers adds bank-specific headers to every request (e.g. an API key).
	Headers func(cfg obsdk.Config, h http.Header)
}

func (p *Profile) pathVersion() string {
	if p.PathVersion == "" {
		return "v1"
	}
	return p.PathVersion
}

// aisPrefixes are the canonical paths AISPathVersion applies to.
var aisPrefixes = []string{"/v1/consents", "/v1/accounts", "/v1/card-accounts", "/v1/funds-confirmations"}

// versionFor is the version segment a canonical "/v1/..." path is sent with.
func (p *Profile) versionFor(path string) string {
	if p.AISPathVersion != "" {
		for _, pre := range aisPrefixes {
			if path == pre || strings.HasPrefix(path, pre+"/") || strings.HasPrefix(path, pre+"?") {
				return p.AISPathVersion
			}
		}
	}
	return p.pathVersion()
}

// linkVersions are the version segments links from the bank may use instead
// of "v1".
func (p *Profile) linkVersions() []string {
	return []string{p.PathVersion, p.AISPathVersion, p.CreatePathVersion}
}

// isCreate reports the requests CreatePathVersion applies to.
func isCreate(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	return path == "/v1/consents" || strings.HasPrefix(path, "/v1/payments/") && strings.Count(path, "/") == 3
}

// Institution describes the parameter that picks one bank of a hub.
type Institution struct {
	// Param is the Config.Extra key, e.g. "bank_code".
	Param string
	// Label names it in messages, e.g. "bank code (BLZ)".
	Label string
	// Normalize cleans and checks a value; nil accepts any non-empty value.
	Normalize func(string) (string, error)
}

func (p *Profile) approaches() []string {
	if len(p.Approaches) == 0 {
		return []string{Redirect}
	}
	return p.Approaches
}

func (p *Profile) supports(approach string) bool {
	for _, a := range p.approaches() {
		if a == approach {
			return true
		}
	}
	return false
}

func (p *Profile) consentDays(n int) int {
	max, def := p.MaxConsentDays, p.DefaultConsentDays
	if max <= 0 {
		max = 90
	}
	if def <= 0 || def > max {
		def = max
	}
	switch {
	case n <= 0:
		return def
	case n > max:
		return max
	}
	return n
}

func (p *Profile) frequency() int {
	if p.FrequencyPerDay > 0 {
		return p.FrequencyPerDay
	}
	return 4
}

func (p *Profile) bookingStatus(s string) bool {
	if len(p.BookingStatuses) == 0 {
		return s == "booked"
	}
	for _, x := range p.BookingStatuses {
		if x == s {
			return true
		}
	}
	return false
}

// Register validates the profile and registers the bank. Bank packages call
// it from init; mistakes panic like obsdk.Register.
func Register(p Profile) {
	obsdk.Register(Integration(p))
}

// Integration builds the obsdk.Integration for a profile without registering
// it (tests use it with their own registry).
func Integration(p Profile) obsdk.Integration {
	if p.ID == "" || p.BaseURL == nil {
		panic(fmt.Sprintf("berlingroup: profile %q needs an ID and a BaseURL", p.Info.Bank))
	}
	if p.Institution != nil && p.Institution.Param == "" {
		panic(fmt.Sprintf("berlingroup: profile %q: Institution needs a Param", p.ID))
	}
	for _, a := range p.approaches() {
		if a != Redirect && a != Decoupled && a != Embedded {
			panic(fmt.Sprintf("berlingroup: profile %q: unknown approach %q", p.ID, a))
		}
	}
	if p.PreStep != nil && p.PreStep.URL == nil {
		panic(fmt.Sprintf("berlingroup: profile %q: PreStep needs a URL", p.ID))
	}
	for _, s := range p.Info.Payments {
		if p.Products[s.Type] == "" {
			panic(fmt.Sprintf("berlingroup: profile %q has a %s payment spec but no payment product for it", p.ID, s.Type))
		}
		if p.PaymentXML && !strings.HasPrefix(p.Products[s.Type], "pain.001-") {
			panic(fmt.Sprintf("berlingroup: profile %q sends pain.001 bodies, but its %s product %q is not a pain.001 product", p.ID, s.Type, p.Products[s.Type]))
		}
	}
	p.Info.Spec = "berlin-group"
	if len(p.Info.Auth.Approaches) == 0 {
		p.Info.Auth.Approaches = p.approaches()
	}
	if p.Info.Limits.MaxConsentDays == 0 {
		p.Info.Limits.MaxConsentDays = p.consentDays(1 << 20)
	}
	if p.Info.Limits.MaxRequestsPerDay == 0 {
		p.Info.Limits.MaxRequestsPerDay = p.frequency()
	}
	prof := p
	return obsdk.Integration{
		ID:      p.ID,
		Info:    p.Info,
		Factory: func(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) { return newClient(&prof, cfg, t) },
	}
}
