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

	// LegacyAddress sends creditorAddress with the field names before 1.3.8
	// (street, city, postalCode); the default is streetName, townName,
	// postCode. Banks mix versions, so the two are separate.
	LegacyAddress bool

	// NoWithBalance leaves out withBalance=true when listing accounts, for
	// banks that refuse it.
	NoWithBalance bool

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

	// Headers adds bank-specific headers to every request (e.g. an API key).
	Headers func(cfg obsdk.Config, h http.Header)
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
