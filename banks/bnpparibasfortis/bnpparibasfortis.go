// Package bnpparibasfortis registers BNP Paribas Fortis (Belgium) and its
// brands Hello bank! and Fintro on the bank's PSD2 API, STET 1.6 served as
// "psd2/v4". Each brand is its own bank key: in production every brand has
// its own hosts, and an authorization given through one brand's page only
// works on that brand's API (Fortis and Hello bank! accounts can be picked
// together on either page; Fintro is separate).
//
// The user's authorization is an OAuth2 authorization code (scope aisp); the
// user picks the accounts at the bank, and the token is the consent.
// Payments are created with a client-credentials token (scope pisp) and
// approved by the user on the bank's page; the bank executes them without a
// confirmation call. A cancellation is the payment request sent back with
// status RJCT and reason DS02, approved by the user the same way.
//
// Production needs an eIDAS QWAC (mTLS through Config.HTTPClient), the client
// id and secret the bank's onboarding endpoint returns, and a QSealC to sign
// every request (draft-cavage http-signature; Seal.KeyID is the public URL of
// the certificate's PEM). The sandbox is free: an app on
// developer.bnpparibasfortis.com gives the client id and secret, and its test
// users log in with a user name and password. The sandbox serves every brand
// from one host, picked with a brand parameter. See docs/bnpparibasfortis.md.
package bnpparibasfortis

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/stet"
)

// Registry keys, one per brand.
const (
	BankFortis = "bnpparibasfortis"
	BankHello  = "hellobank"
	BankFintro = "fintro"
)

const (
	sandboxAPI  = "https://sandbox.api.bnpparibasfortis.com/psd2/v4"
	sandboxAuth = "https://sandbox.auth.bnpparibasfortis.com"
)

type brand struct {
	bank, name string
	domain     string // production domain, e.g. "bnpparibasfortis.be"
	sandbox    string // the sandbox's brand parameter
	business   bool   // Easy Banking Business is offered under this brand
	verifiedOn string // last obdev run against the sandbox (personal; the sandbox has no business users)
}

var brands = []brand{
	{bank: BankFortis, name: "BNP Paribas Fortis", domain: "bnpparibasfortis.be", sandbox: "bnppf", business: true, verifiedOn: "2026-10-21"},
	{bank: BankHello, name: "Hello bank!", domain: "hellobank.be", sandbox: "hb"},
	{bank: BankFintro, name: "Fintro", domain: "fintro.be", sandbox: "fintro", business: true},
}

func init() {
	for _, b := range brands {
		stet.Register(profile(b))
	}
}

// userType is the production authorization path's user type: IND for Easy
// Banking (personal), ENT for Easy Banking Business.
func userType(t obsdk.Target) string {
	if t.Segment == obsdk.Business {
		return "ENT"
	}
	return "IND"
}

// businessLine is the businessLineName header of payment requests: RPB for
// Easy Banking, CPB for Easy Banking Business. It also picks the bank's app
// for the approval on a mobile device.
func businessLine(t obsdk.Target) string {
	if t.Segment == obsdk.Business {
		return "CPB"
	}
	return "RPB"
}

func profile(b brand) stet.Profile {
	segments := []obsdk.Segment{obsdk.Personal}
	if b.business {
		segments = append(segments, obsdk.Business)
	}
	var variants []obsdk.Variant
	for _, seg := range segments {
		sandbox := obsdk.Variant{Country: "BE", Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
		if seg == obsdk.Personal && b.verifiedOn != "" {
			sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, b.verifiedOn
		}
		variants = append(variants, sandbox,
			obsdk.Variant{Country: "BE", Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified})
	}
	regulatory := "https://regulatory.api." + b.domain
	inSandbox := func(cfg obsdk.Config) bool { return cfg.Env != obsdk.Production }
	return stet.Profile{
		ID: b.bank + "-stet-be",
		Info: obsdk.Info{
			Bank: b.bank, Name: b.name, Group: "BNP Paribas Fortis",
			Variants:     variants,
			Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapTransactionsHistory, obsdk.CapPayments},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "sandbox: the app's Client ID on developer.bnpparibasfortis.com; production: returned by the bank's onboarding endpoint"},
				{Name: "client_secret", Secret: true, Required: true, Note: "the app's client secret (sandbox: app details on the portal; production: from the onboarding)"},
				{Name: "redirect_url", Required: true, Note: "a redirect URI registered for the app; payment report URLs must be https"},
				{Name: stet.ParamInitiatingParty, Note: "the PISP's name, sent as initiatingParty; required for payments"},
				{Name: "tls_client_cert", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "eIDAS QWAC for mTLS. The sandbox needs none"},
				{Name: "seal", Secret: true, Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "QSealC RSA key; Seal.KeyID is the public https URL of the certificate's PEM. The sandbox does not check signatures"},
			},
			Docs: []string{
				"https://developer.bnpparibasfortis.com/docs",
				"https://developer.bnpparibasfortis.com/api-detail/576/api-documentation",
				"https://developer.bnpparibasfortis.com/api-detail/578/api-documentation",
				"https://github.com/OpenBanking-BNPPF/resources-stet",
			},
			Notes: []string{
				"The user picks the accounts at the bank. The authorization lasts 180 days in production; there is no consent resource and no API to end it.",
				"Transactions go back 4 years for Easy Banking users (all history for Easy Banking Business), at most 2 years per request.",
				"Without the user present, the bank allows 4 account reads a day.",
			},
			Payments: specs(),
		},
		APIBase: func(env obsdk.Env, _ obsdk.Target) string {
			if env == obsdk.Production {
				return regulatory + "/psd2/v4"
			}
			return sandboxAPI
		},
		AuthURL: func(env obsdk.Env, t obsdk.Target) string {
			if env == obsdk.Production {
				return "https://services." + b.domain + "/SEPL/PSD2/" + userType(t) + "/authorize"
			}
			return sandboxAuth + "/authorize"
		},
		TokenURL: func(env obsdk.Env, _ obsdk.Target) string {
			if env == obsdk.Production {
				return regulatory + "/token"
			}
			return sandboxAuth + "/token"
		},
		ClientAuth:   stet.ClientSecretPost,
		TokenScope:   true, // the sandbox answers 500 to a code exchange without it
		Scopes:       stet.Scopes{History: "-"},
		Confirmation: stet.ConfirmNone,
		Signing: &stet.Signing{
			Required:     true,
			Headers:      []string{"(request-target)", "(created)", "(expires)", "host", "x-request-id", "digest"},
			Expires:      30 * time.Second, // the bank accepts at most 60
			SandboxValue: "unsigned-sandbox-request",
		},
		// dateFrom and dateTo are dates (dateTo exclusive).
		DateQuery: func(t time.Time) string { return t.Format(time.DateOnly) },
		AuthParams: func(cfg obsdk.Config, _ obsdk.Target, q url.Values) {
			if inSandbox(cfg) {
				q.Set("brand", b.sandbox)
			}
		},
		Query: func(cfg obsdk.Config, _ obsdk.Target) url.Values {
			if inSandbox(cfg) {
				return url.Values{"brand": {b.sandbox}}
			}
			return nil
		},
		PaymentHeaders: func(_ obsdk.Config, t obsdk.Target, h http.Header) { h.Set("businessLineName", businessLine(t)) },
		PaymentLevel:   true,
		AmountString:   true,
		CancelStatus:   "RJCT",
		AdjustPayment:  adjustPayment,
	}
}

// adjustPayment applies the bank's payment rules: category purposes are
// limited to a few corporate codes (not the STET defaults), and a debtor
// account currency, when given, must be EUR.
func adjustPayment(_ obsdk.PaymentRequest, _ obsdk.Target, b *stet.PaymentRequestBody) error {
	b.PaymentTypeInformation.CategoryPurpose = ""
	if a := b.DebtorAccount; a != nil && a.Currency != "" && !strings.EqualFold(a.Currency, "EUR") {
		a.Currency = ""
	}
	return nil
}

func specs() []obsdk.PaymentSpec {
	fields := func(instant bool) []obsdk.PaymentField {
		f := []obsdk.PaymentField{
			{Path: obsdk.FieldAmount, Use: obsdk.FieldRequired, Pattern: `^\d{1,15}(\.\d{1,2})?$`, Label: "Amount"},
			{Path: obsdk.FieldDebtorAccount, Use: obsdk.FieldOptional, Ask: true, Schemes: []string{obsdk.SchemeIBAN}, Label: "Pay from",
				Note: "Leave empty to let the user pick the account at the bank."},
			{Path: obsdk.FieldCreditorAccount, Use: obsdk.FieldRequired, Schemes: []string{obsdk.SchemeIBAN}, MaxLength: 34, Label: "Payee account"},
			{Path: obsdk.FieldCreditorName, Use: obsdk.FieldRequired, MaxLength: 70, Label: "Payee name"},
			{Path: obsdk.FieldCreditorBIC, Use: obsdk.FieldOptional, Pattern: `^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`, Label: "Payee bank BIC"},
			{Path: obsdk.FieldRemittance, Use: obsdk.FieldOptional, MaxItems: 1, MaxLength: 140, Label: "Description"},
			{Path: obsdk.FieldEndToEndID, Use: obsdk.FieldOptional, MaxLength: 35},
		}
		if !instant {
			f = append(f,
				obsdk.PaymentField{Path: obsdk.FieldReference, Use: obsdk.FieldOptional, Schemes: []string{obsdk.ReferenceRF}, MaxLength: 35, Label: "Payment reference"},
				obsdk.PaymentField{Path: obsdk.FieldExecutionDate, Use: obsdk.FieldOptional, Label: "Payment date", Note: "Empty means today."})
		}
		return f
	}
	return []obsdk.PaymentSpec{
		{
			Type: obsdk.PaymentSEPA, Currencies: []string{"EUR"}, MaxTransfers: 1, ExecutionDateMaxDays: 364,
			AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted}, Cancellable: true,
			Fields: fields(false),
			Notes: []string{
				"Only payments dated in the future can be cancelled, and only before they are executed.",
				"A payment above the available balance stays pending (PDNG) until the balance covers it.",
				"The user has 60 minutes to approve the payment.",
			},
		},
		{
			Type: obsdk.PaymentSEPAInstant, Currencies: []string{"EUR"}, MaxTransfers: 1,
			AuthApproaches: []string{"redirect"}, FinalStatuses: []obsdk.PaymentStatus{obsdk.PaymentCompleted},
			Fields: fields(true),
			Notes:  []string{"Instant payments are executed today and cannot be cancelled."},
		},
	}
}
