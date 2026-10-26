// Package modelbank registers adorsys' open-source XS2A ModelBank, run
// locally with Docker, as the development and test target of the generic
// Berlin Group adapter. It is not a bank: it lives under internal/, banks/all
// does not import it, and only cmd/obdev and the adapter's tests do.
//
// See docs/berlin-group.md for running the sandbox and creating test users.
package modelbank

import (
	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Bank is the registry key.
const Bank = "modelbank"

// DefaultBaseURL is the XS2A interface of a local ModelBank.
const DefaultBaseURL = "http://localhost:8089"

var sepa = berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{ExecutionDate: true, Cancellable: true, Address: true,
	EndToEndRequired: true, NoReference: true, Approaches: []string{berlingroup.Redirect, berlingroup.Embedded, berlingroup.Decoupled}})

// Profile describes the ModelBank as configured by bank_profile_ledgers.yml
// in adorsys' XS2A-Sandbox 5.14.
var Profile = berlingroup.Profile{
	ID: "modelbank-bg",
	Info: obsdk.Info{
		Bank:  Bank,
		Name:  "adorsys ModelBank",
		Group: "adorsys XS2A-Sandbox (local)",
		Variants: []obsdk.Variant{
			{Country: "DE", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "DE", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
		},
		Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
		Requirements: []obsdk.Requirement{
			{Name: "redirect_url", Note: "any URL; the ModelBank sends the user back to it after the redirect approval"},
			{Name: "base_url", Note: "the XS2A interface, default " + DefaultBaseURL},
		},
		Payments: []obsdk.PaymentSpec{
			sepa,
			berlingroup.CreditTransferSpec(obsdk.PaymentSEPAInstant, berlingroup.SpecOptions{Address: true, EndToEndRequired: true, NoReference: true,
				Approaches: []string{berlingroup.Redirect, berlingroup.Embedded, berlingroup.Decoupled}}),
			berlingroup.CreditTransferSpec(obsdk.PaymentCrossBorder, berlingroup.SpecOptions{ExecutionDate: true, Cancellable: true, Address: true, EndToEndRequired: true, NoReference: true,
				ChargeBearer: true, Currencies: []string{"EUR", "USD", "GBP", "CHF"},
				Approaches: []string{berlingroup.Redirect, berlingroup.Embedded, berlingroup.Decoupled}}),
			// Its ledger needs dayOfExecution, which the adapter sends for
			// monthly or longer frequencies only, and fails on "31" (the
			// month's last day) in shorter months.
			berlingroup.PeriodicSpec(sepa, berlingroup.PeriodicOptions{ExecutionRule: true, Frequencies: []obsdk.Frequency{
				obsdk.FrequencyMonthly, obsdk.FrequencyEveryTwoMonths, obsdk.FrequencyQuarterly, obsdk.FrequencySemiannual, obsdk.FrequencyAnnual}}),
		},
		Docs: []string{"https://github.com/adorsys/XS2A-Sandbox/tree/5.14"},
		Notes: []string{
			"Development target for the Berlin Group adapter, not a bank.",
			"A payment without an end-to-end id fails at the password step with PSU_CREDENTIALS_INVALID, so the spec requires one.",
			"A structured reference is accepted on creation but makes the authorisation fail with FORMAT_ERROR, so the spec leaves it out.",
			"Periodic payments: monthly or longer only (dayOfExecution is required), and no month-end option (dayOfExecution 31 fails in shorter months with PSU_CREDENTIALS_INVALID).",
		},
	},
	BaseURL:    func(obsdk.Env, obsdk.Target, string) string { return DefaultBaseURL },
	Approaches: []string{berlingroup.Redirect, berlingroup.Embedded, berlingroup.Decoupled},
	Consent:    berlingroup.ConsentGlobal,
	Products: map[obsdk.PaymentType]string{
		obsdk.PaymentSEPA:        "sepa-credit-transfers",
		obsdk.PaymentSEPAInstant: "instant-sepa-credit-transfers",
		obsdk.PaymentCrossBorder: "cross-border-credit-transfers",
	},
	// Addresses use the 1.3.8 names, but a structured reference is only
	// accepted as a string, and then fails the authorisation (see Notes).
	StructuredRemittanceString: true,
	// Its periodic payments take dayOfExecution "1" to "31" ("05" is refused
	// as null).
	DayOfExecutionUnpadded: true,
	Signing:                &berlingroup.Signing{},
}

func init() { berlingroup.Register(Profile) }
