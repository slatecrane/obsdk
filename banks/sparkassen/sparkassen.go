// Package sparkassen registers the XS2A interface of the German
// Sparkassen-Finanzgruppe, run by Finanz Informatik for about 345 Sparkassen,
// the Landesbanken and Weberbank. It is a Berlin Group NextGenPSD2 interface
// built on the generic adapter: one API for all of them, with the bank picked
// by its bank code (BLZ) in the URL.
//
// Approval runs either as a redirect to the Sparkasse's online banking, which
// at Finanz Informatik is the OAuth SCA approach (authorisation code with
// PKCE; account calls then carry a bearer token), or embedded, with the
// online banking login and TAN passing through the app. pushTAN 2.0 users
// approve embedded flows in the S-pushTAN app (decoupled).
//
// Built from Finanz Informatik's documentation package (2026-10-18): no test
// eIDAS certificate yet, so nothing has run against the sandbox. See
// docs/sparkassen.md.
package sparkassen

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Bank is the registry key.
const Bank = "sparkassen"

// ParamBankCode is the Config.Extra key of the Sparkasse's bank code (BLZ).
const ParamBankCode = "bank_code"

const (
	sandboxRoot    = "https://xs2a-sandbox.f-i-apim.de:8444/fixs2a-env/xs2a-api/"
	productionRoot = "https://xs2a.f-i-apim.de:8443/fixs2aop-env/xs2a-api/"
)

// HTTPClient returns an HTTP client that presents the QWAC (sandbox: a PSD2
// test QWAC from a trust centre Finanz Informatik lists, e.g. Bundesdruckerei).
func HTTPClient(qwac tls.Certificate) *http.Client { return berlingroup.QWACClient(qwac) }

// ClientID returns the QWAC's organizationIdentifier (e.g. PSDDE-BAFIN-123456),
// the OAuth client id of the redirect approach.
func ClientID(qwac *x509.Certificate) (string, error) {
	return berlingroup.OrganizationIdentifier(qwac)
}

// BankCode normalizes a bank code: eight digits, spaces allowed, or a German
// IBAN, from which the code is taken.
func BankCode(s string) (string, error) {
	v := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if strings.HasPrefix(v, "DE") {
		if err := obsdk.ValidateIdentifier(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: v}); err != nil || len(v) != 22 {
			return "", fmt.Errorf("%q is not a German IBAN", s)
		}
		v = v[4:12]
	}
	if len(v) != 8 || strings.Trim(v, "0123456789") != "" {
		return "", fmt.Errorf("%q is not a bank code (BLZ): eight digits", s)
	}
	return v, nil
}

func baseURL(env obsdk.Env, _ obsdk.Target, bankCode string) string {
	if bankCode == "" {
		return ""
	}
	if env == obsdk.Production {
		return productionRoot + bankCode
	}
	return sandboxRoot + bankCode
}

var approaches = []string{berlingroup.Redirect, berlingroup.Embedded}

func specs() []obsdk.PaymentSpec {
	notes := []string{
		"A payment can be cancelled only before it is approved: Finanz Informatik cancels approved payments only for pain.001, so a future-dated payment stays.",
	}
	return []obsdk.PaymentSpec{
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{ExecutionDate: true, NoReference: true,
			Approaches: approaches, Notes: notes}),
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPAInstant, berlingroup.SpecOptions{NoReference: true,
			Approaches: approaches, Notes: notes}),
	}
}

// Profile describes Finanz Informatik's XS2A interface as documented in its
// care package (implementer options v3.2, redirect handbook v1.4, pushTAN 2.0
// handbook v1.3, transactions handbook v1.0).
var Profile = berlingroup.Profile{
	ID: "sparkassen-bg",
	Info: obsdk.Info{
		Bank:  Bank,
		Name:  "Sparkasse",
		Group: "Sparkassen-Finanzgruppe (Finanz Informatik)",
		Variants: []obsdk.Variant{
			{Country: "DE", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "DE", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "DE", Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			{Country: "DE", Segment: obsdk.Business, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		},
		Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
		Requirements: []obsdk.Requirement{
			{Name: ParamBankCode, Note: "the Sparkasse's bank code (BLZ), or one of its IBANs; needed to connect or pay, then kept in the session and payment reference. About 345 codes, listed in Finanz Informatik's bankcodelist"},
			{Name: "tls_client_cert", Required: true, Note: "eIDAS QWAC for mTLS (sandbox: a PSD2 test QWAC from a listed trust centre); build the client with sparkassen.HTTPClient"},
			{Name: "client_id", Note: "redirect approach only: the QWAC's organizationIdentifier, e.g. PSDDE-BAFIN-123456 (sparkassen.ClientID reads it)"},
			{Name: "redirect_url", Note: "redirect approach only: sent as TPP-Redirect-URI; the user comes back to it with the OAuth code"},
		},
		Docs: []string{
			"https://www.starfinanz.de/services/xs2a/",
			"https://www.starfinanz.de/services/xs2a-faq/",
			"https://www.starfinanz.de/wp-content/uploads/2026/10/xs2a-documentation.zip",
		},
		Notes: []string{
			"One interface for about 345 Sparkassen, the Landesbanken and Weberbank; the bank code picks the bank.",
			"Redirect is OAuth2 with PKCE: account calls need the access token (one hour); Refresh renews it with the refresh token (180 days).",
			"Embedded asks for the online banking login and PIN, then a TAN. pushTAN 2.0 users can pick the decoupled variant and approve in the S-pushTAN app (up to 12 minutes).",
			"chipTAN optical and QR challenges arrive as challenge data (flicker code or image) that the app has to show.",
			"There is no all-accounts consent: on the redirect the user picks the accounts at the bank; embedded connects need the IBANs in Values[\"iban\"].",
			"Transactions are only available as camt.052 (XML); pending ones only for the current day.",
			"Booked transactions older than 90 days are only available on the first transactions call after the consent was granted.",
		},
		Payments: specs(),
	},
	BaseURL: baseURL,
	Institution: &berlingroup.Institution{Param: ParamBankCode, Label: "the Sparkasse's bank code (BLZ)",
		Normalize: BankCode},
	Approaches:      approaches,
	Consent:         berlingroup.ConsentBankOffered,
	BookingStatuses: []string{"booked", "pending", "both"},
	Products: map[obsdk.PaymentType]string{
		obsdk.PaymentSEPA:        "sepa-credit-transfers",
		obsdk.PaymentSEPAInstant: "instant-sepa-credit-transfers",
	},
	XMLTransactions:    true,
	OAuthNoRedirectURI: true,
}

func init() { berlingroup.Register(Profile) }
