// Package atruvia registers the XS2A interface that Atruvia AG runs for the
// German cooperative banks (about 600 Volksbanken and Raiffeisenbanken), the
// Sparda-Banken, PSD Banken, DZ BANK and a number of private banks: about 670
// institutions on one Berlin Group NextGenPSD2 1.3 implementation. Each bank
// has its own host, listed in Atruvia's Xs2aApiDirectory and embedded here
// (directory.json); the bank is picked by its bank code (BLZ).
//
// Approval is embedded only, with the online banking login (VR-NetKey or
// alias) and PIN passing through the app, then a TAN: Smart-TAN (chipTAN),
// Smart-TAN photo, or SecureGo plus, where the user approves in the app
// (decoupled; the SDK polls). Payments are pain.001 XML only. Every request
// is signed with the QSealC.
//
// Built from Atruvia's documentation (2026-10-19): the sandbox refuses
// self-signed certificates, so nothing has run against it yet. See
// docs/atruvia.md.
package atruvia

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Bank is the registry key.
const Bank = "atruvia"

// ParamBankCode is the Config.Extra key of the bank's code (BLZ).
const ParamBankCode = "bank_code"

const (
	sandboxRoot = "https://p1.xs2a-doc.atruvia.de/sandbox/psd2"
	// SandboxFallbackRoot is Atruvia's second sandbox host (Config.Extra
	// "base_url"); it already answers with pain.002.001.10.
	SandboxFallbackRoot = "https://p2.xs2a-doc.atruvia.de/sandbox/psd2"
	// SandboxBankCode is the bank code of the sandbox's test IBANs
	// (DE..4999 9960 ...). The sandbox has one host for every bank code.
	SandboxBankCode = "49999960"
)

// Institution is one bank of the directory.
type Institution struct {
	Code string `json:"code"` // bank code (BLZ)
	BIC  string `json:"bic"`
	Name string `json:"name"`
	URL  string `json:"url"` // API root, without /v1
}

//go:embed directory.json
var directoryJSON []byte

var directory, byBIC = func() (map[string]Institution, map[string]string) {
	var list []Institution
	if err := json.Unmarshal(directoryJSON, &list); err != nil {
		panic("atruvia: directory.json: " + err.Error())
	}
	codes, bics := map[string]Institution{}, map[string]string{}
	for _, in := range list {
		codes[in.Code] = in
		if _, dup := bics[in.BIC]; !dup {
			bics[in.BIC] = in.Code
		}
	}
	return codes, bics
}()

// Lookup returns the bank with a bank code from the embedded directory.
func Lookup(code string) (Institution, bool) {
	in, ok := directory[code]
	return in, ok
}

// Institutions lists the banks of the embedded directory, by bank code.
func Institutions() []Institution {
	var list []Institution
	if err := json.Unmarshal(directoryJSON, &list); err != nil {
		panic(err)
	}
	return list
}

// BankCode normalizes the bank parameter: a bank code (eight digits, spaces
// allowed), a German IBAN, from which the code is taken, or a BIC. The code
// must be one of Atruvia's banks, or the sandbox's.
func BankCode(s string) (string, error) {
	v := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	switch {
	case strings.HasPrefix(v, "DE") && len(v) == 22:
		if err := obsdk.ValidateIdentifier(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: v}); err != nil {
			return "", fmt.Errorf("%q is not a German IBAN", s)
		}
		v = v[4:12]
	case len(v) == 8 || len(v) == 11:
		if strings.Trim(v, "0123456789") != "" {
			code, ok := byBIC[v]
			if !ok && len(v) == 8 {
				code, ok = byBIC[v+"XXX"]
			}
			if !ok {
				return "", fmt.Errorf("BIC %s is not a bank on Atruvia's XS2A interface", v)
			}
			v = code
		}
	}
	if len(v) != 8 || strings.Trim(v, "0123456789") != "" {
		return "", fmt.Errorf("%q is not a bank code (BLZ: eight digits), German IBAN or BIC", s)
	}
	if _, ok := directory[v]; !ok && v != SandboxBankCode {
		return "", fmt.Errorf("bank code %s is not a bank on Atruvia's XS2A interface", v)
	}
	return v, nil
}

func baseURL(env obsdk.Env, _ obsdk.Target, bankCode string) string {
	if env != obsdk.Production {
		if bankCode == "" {
			return ""
		}
		return sandboxRoot
	}
	return directory[bankCode].URL
}

// HTTPClient returns an HTTP client that presents the QWAC (production; the
// sandbox does not use mTLS).
func HTTPClient(qwac tls.Certificate) *http.Client { return berlingroup.QWACClient(qwac) }

// KeyID is the signature's keyId as Atruvia wants it: the QSealC's serial
// number in hexadecimal and its issuer, the issuer fully URL-encoded.
func KeyID(cert *x509.Certificate) string {
	ca := strings.ReplaceAll(url.QueryEscape(cert.Issuer.String()), "+", "%20")
	return fmt.Sprintf("SN=%X,CA=%s", cert.SerialNumber, ca)
}

var approaches = []string{berlingroup.Embedded, berlingroup.Decoupled}

func specs() []obsdk.PaymentSpec {
	notes := []string{
		"Sent as pain.001.001.09 (GBIC_5). The payer's name may be left out (NOTPROVIDED).",
		"A payment can be cancelled without approval until it is approved; after that only a future-dated SEPA credit transfer can be cancelled, with a TAN.",
		"DZ BANK offers no payments.",
	}
	return []obsdk.PaymentSpec{
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{ExecutionDate: true, Cancellable: true,
			Approaches: approaches, Notes: notes}),
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPAInstant, berlingroup.SpecOptions{Approaches: approaches,
			Notes: append([]string{"Instant credit transfers are offered only by some of the banks."}, notes...)}),
	}
}

// Profile describes Atruvia's XS2A interface as documented in its OpenAPI
// file ("1.3 + additional errata"), implementer options, sandbox guide
// (2026-04-27) and release notes (2026-10-16).
var Profile = berlingroup.Profile{
	ID: "atruvia-bg",
	Info: obsdk.Info{
		Bank:  Bank,
		Name:  "Volksbank Raiffeisenbank",
		Group: "Atruvia (Volksbanken Raiffeisenbanken, Sparda-Banken, PSD Banken, DZ BANK and others)",
		Variants: []obsdk.Variant{
			{Country: "DE", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "DE", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "DE", Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			{Country: "DE", Segment: obsdk.Business, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		},
		Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
		Requirements: []obsdk.Requirement{
			{Name: ParamBankCode, Note: "the bank's code (BLZ), one of its IBANs or its BIC; needed to connect or pay, then kept in the session and payment reference. About 670 banks, listed in Atruvia's Xs2aApiDirectory (atruvia.Institutions)"},
			{Name: "seal", Required: true, Note: "QSealC (RSA): every request is signed (Digest, Signature, TPP-Signature-Certificate). Sandbox: a PSD2 test certificate; self-signed ones are refused"},
			{Name: "tls_client_cert", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "eIDAS QWAC for mTLS; build the client with atruvia.HTTPClient. The sandbox does not use mTLS"},
		},
		Docs: []string{
			"https://atruvia.de/drittanbieter-schnittstelle-xs2a",
			"https://p1.xs2a-doc.atruvia.de",
			"https://atruvia.de/uploads/files/sandbox-nextgen/TPP-Sandbox-Documentation.zip",
			"https://atruvia.de/uploads/files/XS2A-Releasenotes.pdf",
			"https://atruvia.de/uploads/files/Xs2aApiDirectory.json",
		},
		Notes: []string{
			"One interface for about 670 banks, each on its own host; the bank code picks it.",
			"Embedded approval only: the online banking login (PSU-ID) and PIN, then a TAN. SecureGo plus users approve in the app (decoupled); the SDK polls.",
			"Consents cover all accounts; Values[\"iban\"] asks for named accounts instead.",
			"Transactions are booked only (no pending); the account list has no balances.",
			"Payments are pain.001 XML, their status pain.002.",
			"The PSU-ID is needed to cancel a payment too (PaymentCallOptions.PSU.ID).",
		},
		Payments: specs(),
	},
	BaseURL: baseURL,
	Institution: &berlingroup.Institution{Param: ParamBankCode, Label: "the bank's code (BLZ), IBAN or BIC",
		Normalize: BankCode},
	Approaches:    approaches,
	Consent:       berlingroup.ConsentGlobal,
	PSUID:         berlingroup.PSUIDRequired,
	NoWithBalance: true,
	Products: map[obsdk.PaymentType]string{
		obsdk.PaymentSEPA:        "pain.001-sepa-credit-transfers",
		obsdk.PaymentSEPAInstant: "pain.001-instant-sepa-credit-transfers",
	},
	PaymentXML: true,
	// Atruvia's example signs Date too, but the sandbox refuses a signed date
	// ("The header 'date' is not allowed for signature specification").
	Signing: &berlingroup.Signing{Required: true, Algorithm: "rsa-sha256", KeyID: KeyID},
}

func init() { berlingroup.Register(Profile) }
