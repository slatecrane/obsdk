// Package cooppank registers Coop Pank (Estonia) on its PSD2 interface, which
// Tietoevry built and runs for the bank: Berlin Group NextGenPSD2 1.3 served
// under "/xs2a/v1.3", with the user approving consents and payments by
// redirect to the bank's pages.
//
// Every request carries the API key of the application registered on the
// developer portal (X-API-Key). Requests are not signed; production also
// needs an eIDAS QWAC for mTLS, which the bank checks against the portal
// registration.
//
// The sandbox is free: an account on openbanking.cooppank.ee, a sandbox
// application (the certificate step can be skipped) and its API key. The test
// users are listed under "My Sandbox". Connect, accounts, balances,
// transactions, refresh, disconnect, payments, payment status and
// cancellation were run against the sandbox on 2026-10-20. See
// docs/cooppank.md.
package cooppank

import (
	"net/http"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Bank is the registry key.
const Bank = "cooppank"

// ParamAPIKey is the Config.Extra key of the application's API key from the
// developer portal, sent as X-API-Key on every request.
const ParamAPIKey = "api_key"

// verifiedOn is the date of the last obdev run against the sandbox.
const verifiedOn = "2026-10-20"

const host = "https://openbanking.cooppank.ee"

func baseURL(env obsdk.Env, _ obsdk.Target, _ string) string {
	if env == obsdk.Production {
		return host + "/live/xs2a"
	}
	return host + "/sandbox/xs2a"
}

func headers(cfg obsdk.Config, h http.Header) { h.Set("X-API-Key", cfg.Param(ParamAPIKey)) }

var approaches = []string{berlingroup.Redirect}

func specs() []obsdk.PaymentSpec {
	notes := []string{
		"The payee's address is required, with at least the town and the country.",
		"Use either a description or a reference; both are accepted only for payments within Estonia.",
		"A future-dated payment cannot be dated today.",
	}
	s := berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{ExecutionDate: true, Address: true,
		Cancellable: true, Approaches: approaches, Notes: notes})
	for i, f := range s.Fields {
		if f.Path == obsdk.FieldCreditorAddress || f.Path == obsdk.FieldCreditorCountry {
			s.Fields[i].Use = obsdk.FieldRequired
		}
	}
	return []obsdk.PaymentSpec{s}
}

// Profile is Coop Pank's Berlin Group profile.
var Profile = berlingroup.Profile{
	ID: "cooppank-bg-ee",
	Info: obsdk.Info{
		Bank:  Bank,
		Name:  "Coop Pank",
		Group: "Coop Pank AS (Estonia); the PSD2 interface is Tietoevry's Open Banking platform",
		Variants: []obsdk.Variant{
			{Country: "EE", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturitySandboxVerified, VerifiedOn: verifiedOn},
			{Country: "EE", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "EE", Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			{Country: "EE", Segment: obsdk.Business, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		},
		Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
		Requirements: []obsdk.Requirement{
			{Name: ParamAPIKey, Required: true, Note: "API key of the application on openbanking.cooppank.ee (My Apps), sent as X-API-Key"},
			{Name: "tls_client_cert", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "eIDAS QWAC for mTLS, uploaded to the production application on the portal. The sandbox needs none"},
		},
		Docs: []string{
			"https://openbanking.cooppank.ee/documentation",
			"https://openbanking.cooppank.ee/api-catalog",
		},
		Notes: []string{
			"The user picks the accounts at the bank.",
			"Transactions can be read up to 180 days back with a recurring consent.",
		},
		Payments: specs(),
	},
	BaseURL:            baseURL,
	Approaches:         approaches,
	Consent:            berlingroup.ConsentBankOffered,
	MaxConsentDays:     180,
	DefaultConsentDays: 90,
	BookingStatuses:    []string{"booked", "pending", "both"},
	// The how-to also names instant-sepa-credit-transfers, but the API
	// specification does not, and the sandbox answers PRODUCT_UNKNOWN.
	Products:    map[obsdk.PaymentType]string{obsdk.PaymentSEPA: "sepa-credit-transfers"},
	PathVersion: "v1.3",
	Headers:     headers,
}

func init() { berlingroup.Register(Profile) }
