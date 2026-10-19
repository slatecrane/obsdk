// Package sibs registers SIBS API Market, the Portuguese PSD2 hub run by
// SIBS: one Berlin Group NextGenPSD2 interface (1.3.12, "release 4") for
// 25 banks, among them Caixa Geral de Depósitos, Millennium bcp,
// Novo Banco, Santander Totta, BPI, Crédito Agrícola, Montepio and Bankinter,
// together about 95% of the payment accounts in Portugal. The bank is picked
// by its ASPSP code in the URL (e.g. BST, BBPI, BNKI).
//
// Every bank approves by redirect to its own pages. The interface puts
// "v1-0-4" where the standard has "v1", spells allPsd2 "all-accounts", wants
// validUntil as a date-time and a Date header in ISO 8601 on every request,
// and identifies the application with an X-IBM-Client-Id header. Production
// requests are signed with the QSealC and sent over mTLS with the QWAC; the
// sandbox needs neither.
//
// Built from SIBS's TPP user guide (v01.51, 2026-01-06) and its OpenAPI
// files; payments run against the sandbox on 2026-10-19, whose account
// information stub refuses every bank. See docs/sibs.md.
package sibs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Bank is the registry key.
const Bank = "sibs"

// ParamASPSP is the Config.Extra key of the bank's ASPSP code.
const ParamASPSP = "aspsp"

// SIBS runs two active/active sites; resources created on one can be read on
// the other. Config.Extra "base_url" (with the ASPSP code) switches sites.
const (
	sandboxRoot    = "https://site1.sibsapimarket.com:8445/sibs/apimarket-sb"
	productionRoot = "https://site1.sibsapimarket.com/sibs/apimarket"
	// TestRoot is the Test (QLY) environment of SIBS's Test & Production
	// portal, for end-to-end tests with the banks' test users; pass it, with
	// the ASPSP code appended, as Config.Extra "base_url" with a production
	// configuration.
	TestRoot = "https://site1.sibsapimarket.com:8444/sibs/apimarket"
)

func baseURL(env obsdk.Env, _ obsdk.Target, code string) string {
	if code == "" {
		return ""
	}
	if env == obsdk.Production {
		return productionRoot + "/" + code
	}
	return sandboxRoot + "/" + code
}

// HTTPClient returns an HTTP client that presents the QWAC (production).
// SIBS's gateway renegotiates TLS after the handshake (to ask for the client
// certificate), which Go refuses unless allowed; this client allows it once
// per connection.
func HTTPClient(qwac tls.Certificate) *http.Client {
	return newHTTPClient(&tls.Config{Certificates: []tls.Certificate{qwac}})
}

// SandboxHTTPClient returns an HTTP client for the sandbox: no client
// certificate, but the same TLS renegotiation as production.
func SandboxHTTPClient() *http.Client { return newHTTPClient(&tls.Config{}) }

func newHTTPClient(tc *tls.Config) *http.Client {
	tc.MinVersion, tc.Renegotiation = tls.VersionTLS12, tls.RenegotiateOnceAsClient
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tc
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

// KeyID is the signature's keyId as SIBS wants it: the QSealC's serial
// number in lowercase hexadecimal.
func KeyID(cert *x509.Certificate) string { return fmt.Sprintf("%x", cert.SerialNumber) }

// textPattern is SIBS's character set: requests with other characters
// (accented letters among them) are declined.
const textPattern = `^[A-Za-z0-9/?:().,'+<=>&%_*# -]*$`

const textNote = "Only A-Z, a-z, 0-9, space and / - ? : ( ) . , ' + < = > & % _ * #: no accented letters."

func headers(cfg obsdk.Config, h http.Header) {
	h.Set("X-IBM-Client-Id", cfg.Credentials.ClientID)
	if cfg.Env != obsdk.Production && cfg.Seal == nil {
		// The sandbox's OpenAPI files mark Signature and the certificate as
		// required, but the sandbox checks neither.
		h.Set("Signature", "sandbox")
		h.Set("TPP-Signature-Certificate", "sandbox")
	}
}

var approaches = []string{berlingroup.Redirect}

func specs() []obsdk.PaymentSpec {
	notes := []string{
		"The bank may book a payment to an account at the same bank as an internal transfer.",
		"A payment can be cancelled until it is executed; a future-dated one may need the user's approval to cancel.",
		"Names and descriptions use SIBS's restricted character set: " + textNote,
	}
	out := []obsdk.PaymentSpec{
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{DebtorOptional: true, ExecutionDate: true,
			Cancellable: true, Address: true, NoReference: true, Approaches: approaches, Notes: notes}),
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPAInstant, berlingroup.SpecOptions{DebtorOptional: true, Address: true,
			NoReference: true, Approaches: approaches,
			Notes: append([]string{"Instant credit transfers are offered by most, not all, banks (List of Banks API)."}, notes...)}),
	}
	for i := range out {
		for j, f := range out[i].Fields {
			if f.Path == obsdk.FieldCreditorName || f.Path == obsdk.FieldRemittance || f.Path == obsdk.FieldEndToEndID {
				out[i].Fields[j].Pattern, out[i].Fields[j].Note = textPattern, strings.TrimSpace(f.Note+" "+textNote)
			}
		}
	}
	return out
}

// Profile describes SIBS API Market as documented in its TPP user guide
// (v01.51) and the OpenAPI files of its Test & Production portal (Accounts
// 4.0.14, Consents 4.0.16, Payments 4.0.11).
var Profile = berlingroup.Profile{
	ID: "sibs-bg",
	Info: obsdk.Info{
		Bank:  Bank,
		Name:  "SIBS API Market",
		Group: "SIBS API Market (Caixa Geral de Depósitos, Millennium bcp, Novo Banco, Santander, BPI, Crédito Agrícola, Montepio, Bankinter and others)",
		Variants: []obsdk.Variant{
			{Country: "PT", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "PT", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "PT", Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			{Country: "PT", Segment: obsdk.Business, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		},
		Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
		Requirements: []obsdk.Requirement{
			{Name: ParamASPSP, Note: "the bank's ASPSP code from SIBS's List of Banks API (e.g. BST for Santander Totta; sibs.Institutions), its BIC or one of its Portuguese IBANs; needed to connect or pay, then kept in the session and payment reference"},
			{Name: "client_id", Required: true, Note: "the application's client id on the SIBS API Market developer portal (sent as X-IBM-Client-Id)"},
			{Name: "seal", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "QSealC (RSA): every production request is signed (Digest, Signature, TPP-Signature-Certificate). The sandbox needs none"},
			{Name: "tls_client_cert", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "eIDAS QWAC for mTLS; build the client with sibs.HTTPClient (it allows the TLS renegotiation SIBS's gateway does; use sibs.SandboxHTTPClient in the sandbox). The sandbox does not use mTLS"},
		},
		Docs: []string{
			"https://developer.sibsapimarket.com/sandbox/start",
			"https://developer.sibsapimarket.com/sandbox/product",
			"https://developer.sibsapimarket.com/live/product",
			"https://www.pay.sibs.com/en/solutions/api-market/api-providers/",
		},
		Notes: []string{
			"One interface for 25 banks (23 Portuguese, CGD France, BIG España); the ASPSP code, BIC or an IBAN picks the bank. The sandbox serves payments only: its AIS stub refuses every bank code.",
			"Every bank approves by redirect to its own pages.",
			"Consents last up to 180 days; the bank may end them earlier. Transactions older than 90 days are only readable in the first 30 minutes after approval.",
			"The account list has no balances; there are no transaction details or delta queries.",
			"A new long-lasting consent replaces the previous one of the same user at the same bank.",
		},
		Payments: specs(),
	},
	BaseURL:            baseURL,
	Institution:        &berlingroup.Institution{Param: ParamASPSP, Label: "the bank's ASPSP code, BIC or IBAN", Normalize: ASPSPCode},
	Approaches:         approaches,
	Consent:            berlingroup.ConsentGlobal,
	MaxConsentDays:     180,
	DefaultConsentDays: 180,
	BookingStatuses:    []string{"booked", "pending", "both"},
	NoWithBalance:      true,
	LegacyAddress:      true,
	Products: map[obsdk.PaymentType]string{
		obsdk.PaymentSEPA:        "sepa-credit-transfers",
		obsdk.PaymentSEPAInstant: "instant-sepa-credit-transfers",
	},
	PathVersion:      "v1-0-4",
	AllAccountsValue: "all-accounts",
	// The guide's example: "2019-12-01T13:20:00".
	ValidUntilLayout: "2006-01-02T15:04:05",
	// The guide's example: "2019-08-19T17:44:25.918+01:00".
	DateLayout: "2006-01-02T15:04:05.000Z07:00",
	BodyDigest: true,
	Signing:    &berlingroup.Signing{Algorithm: "rsa-sha256", KeyID: KeyID},
	Headers:    headers,
}

func init() { berlingroup.Register(Profile) }
