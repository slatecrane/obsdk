// Package redsys registers the Redsys PSD2 hub ("HUB PSD2"), through which
// most Spanish banks publish their PSD2 interface: one Berlin Group
// NextGenPSD2 1.3 interface for BBVA, CaixaBank, Banco Santander, Sabadell,
// Bankinter, Unicaja, Kutxabank, Ibercaja, Openbank, the Caja Rural group and
// others. The bank is picked by its code in the URL (e.g. BBVA, caixabank,
// BancSabadell).
//
// The hub wants an OAuth2 authorisation as a pre-step: the user logs in at
// the bank first (authorisation code with PKCE; the client id is the
// organizationIdentifier of the TPP's eIDAS certificate), and every request
// afterwards carries the access token, next to the Consent-ID for account
// reads. The consent or payment is then approved by a second redirect. Every
// request is signed with the QSealC. Consents and payments are created on
// path version "v1.1"; everything else stays on "v1".
//
// Built from the hub's TPP technical design (v1.9.4, September 2025) and its
// per-bank pages on market.apis-i.redsys.es (2026-10-19); not yet run against
// the sandbox. See docs/redsys.md.
package redsys

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Bank is the registry key.
const Bank = "redsys"

// ParamASPSP is the Config.Extra key of the bank's code on the hub.
const ParamASPSP = "aspsp"

const (
	sandboxAPI      = "https://apis-i.redsys.es:20443/psd2/xs2a/api-entrada-xs2a/services/"
	sandboxOAuth    = "https://apis-i.redsys.es:20443/psd2/xs2a/api-oauth-xs2a/services/rest/"
	productionAPI   = "https://psd2.redsys.es/api-entrada-xs2a/services/"
	productionOAuth = "https://hubpsd2.redsys.es/api-oauth-xs2a/services/rest/"
)

// ASPSPs are the bank codes found on the hub's public bank pages
// (2026-10-19), by code; the hub serves more. Codes are case-sensitive on
// the hub, so ASPSPCode maps any spelling of these to the hub's.
var ASPSPs = map[string]string{
	"BBVA":                 "BBVA",
	"caixabank":            "CaixaBank",
	"imagin":               "imagin (CaixaBank)",
	"bancosantander":       "Banco Santander",
	"bancosantanderglobal": "Santander Corporate & Investment Banking",
	"openbank":             "Openbank",
	"BancSabadell":         "Banco Sabadell",
	"bankinter":            "Bankinter",
	"unicajabanco":         "Unicaja Banco",
	"kutxabank":            "Kutxabank",
	"ibercaja":             "Ibercaja",
	"laboralkutxa":         "Laboral Kutxa",
	"grupocajamar":         "Grupo Cajamar",
	"BCE":                  "Caja Rural (Banco Cooperativo Español)",
	"EUROCAJARURAL":        "Eurocaja Rural",
	"bancamarch":           "Banca March",
	"BancoMediolanum":      "Banco Mediolanum",
	"renta4":               "Renta 4 Banco",
	"selfbank":             "Self Bank",
	"triodos":              "Triodos Bank",
	"COLONYA":              "Colonya Caixa Pollença",
	"PICHINCHA":            "Banco Pichincha España",
	"inversis":             "Banco Inversis",
	"creandes":             "Banco Alcalá (Creand)",
	"wizink":               "WiZink",
	"CETELEM":              "Cetelem",
}

var codePattern = regexp.MustCompile(`^[A-Za-z0-9]{2,40}$`)

// ASPSPCode returns the hub's spelling of a bank code: a known code in any
// case, or an unknown one as given.
func ASPSPCode(v string) (string, error) {
	v = strings.TrimSpace(v)
	for code := range ASPSPs {
		if strings.EqualFold(code, v) {
			return code, nil
		}
	}
	if !codePattern.MatchString(v) {
		return "", fmt.Errorf("%q is not a Redsys bank code (e.g. BBVA, caixabank, BancSabadell)", v)
	}
	return v, nil
}

// codes lists the known codes for messages and docs.
func codes() string {
	out := make([]string, 0, len(ASPSPs))
	for c := range ASPSPs {
		out = append(out, c)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func baseURL(env obsdk.Env, _ obsdk.Target, code string) string {
	if code == "" {
		return ""
	}
	if env == obsdk.Production {
		return productionAPI + code
	}
	return sandboxAPI + code
}

func oauthURL(env obsdk.Env, _ obsdk.Target, code string) string {
	if code == "" {
		return ""
	}
	if env == obsdk.Production {
		return productionOAuth + code
	}
	return sandboxOAuth + code
}

// clientID is Credentials.ClientID, or else the organizationIdentifier of the
// QSealC: the hub requires the two to match.
func clientID(cfg obsdk.Config) string {
	if cfg.Credentials.ClientID != "" {
		return cfg.Credentials.ClientID
	}
	if cfg.Seal != nil && cfg.Seal.Certificate != nil {
		id, _ := berlingroup.OrganizationIdentifier(cfg.Seal.Certificate)
		return id
	}
	return ""
}

var approaches = []string{berlingroup.Redirect}

func specs() []obsdk.PaymentSpec {
	notes := []string{
		"The account to pay from is required.",
		"Reading or cancelling the payment needs the session the payment's steps return (PaymentCallOptions.Session).",
	}
	out := []obsdk.PaymentSpec{
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{ExecutionDate: true, Cancellable: true,
			Address: true, NoReference: true, Approaches: approaches,
			Notes: append([]string{"A future-dated payment (payment date) can be cancelled until it is executed."}, notes...)}),
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPAInstant, berlingroup.SpecOptions{Address: true, NoReference: true,
			Approaches: approaches,
			Notes:      append([]string{"Some banks (BBVA) require the payee's town (creditor address) for instant transfers."}, notes...)}),
	}
	for i := range out {
		out[i].StatusNeedsSession = true
		// The hub's single payment has no endToEndIdentification.
		kept := out[i].Fields[:0]
		for _, f := range out[i].Fields {
			if f.Path != obsdk.FieldEndToEndID {
				kept = append(kept, f)
			}
		}
		out[i].Fields = kept
	}
	return out
}

// Profile describes the Redsys hub as documented in its TPP technical design
// (v1.9.4) and per-bank pages.
var Profile = berlingroup.Profile{
	ID: "redsys-bg",
	Info: obsdk.Info{
		Bank:  Bank,
		Name:  "Redsys PSD2 hub",
		Group: "Redsys HUB PSD2 (BBVA, CaixaBank, Banco Santander, Sabadell, Bankinter, Unicaja, Kutxabank, Ibercaja, Openbank, Caja Rural and others)",
		Variants: []obsdk.Variant{
			{Country: "ES", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "ES", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
			{Country: "ES", Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			{Country: "ES", Segment: obsdk.Business, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		},
		Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
		Requirements: []obsdk.Requirement{
			{Name: ParamASPSP, Note: "the bank's code on the hub (case as the hub spells it, e.g. BBVA, caixabank, BancSabadell; redsys.ASPSPs lists known ones: " + codes() + "); needed to connect or pay, then kept in the session and payment reference"},
			{Name: "seal", Required: true, Note: "QSealC (RSA): every request is signed (Digest, Signature, TPP-Signature-Certificate). In the sandbox, the generic certificate from the portal's Certificates tab, or the TPP's own"},
			{Name: "client_id", Note: "the organizationIdentifier of the QSealC (e.g. PSDES-BDE-3DFD21), used as the OAuth client id; read from the certificate when empty"},
			{Name: "redirect_url", Required: true, Note: "receives both the OAuth callback (code, state) and the return from the consent or payment approval"},
		},
		Docs: []string{
			"https://market.apis-i.redsys.es/psd2/xs2a/guia",
			"https://market.apis-i.redsys.es/psd2/xs2a/nodos/bbva",
			"https://hub-i.redsys.es:16443/psd2-doc/DOC_TPP_v.1.9.4_BBVA_vIngles.pdf",
			"https://hub-i.redsys.es:16443/psd2-doc/documentacionswagger_v1.1.yaml",
		},
		Notes: []string{
			"One interface for most Spanish banks; the aspsp code picks the bank.",
			"The user is sent to the bank twice: first to log in (OAuth pre-step, which gives the session's token), then to approve the consent or payment.",
			"Payment steps return a session with the token; keep it to read or cancel the payment. A session from an earlier payment can start the next one without a new login (PaymentRequest.Session).",
			"Only one long-lasting consent per TPP, user and bank: a new one replaces the previous.",
			"Pending transactions and a few payment products (TARGET2, cross-border, periodic, bulk) depend on the bank and are not offered here.",
		},
		Payments: specs(),
	},
	BaseURL:            baseURL,
	Institution:        &berlingroup.Institution{Param: ParamASPSP, Label: "the bank's code on the Redsys hub, e.g. BBVA", Normalize: ASPSPCode},
	Approaches:         approaches,
	Consent:            berlingroup.ConsentGlobal,
	MaxConsentDays:     180,
	DefaultConsentDays: 180,
	Products: map[obsdk.PaymentType]string{
		obsdk.PaymentSEPA:        "sepa-credit-transfers",
		obsdk.PaymentSEPAInstant: "instant-sepa-credit-transfers",
	},
	CreatePathVersion: "v1.1",
	PreStep:           &berlingroup.PreStep{URL: oauthURL, ClientID: clientID},
	// TPP-Nok-Redirect-URI may be at most 50 characters at the hub; without
	// it a refusal comes back to the redirect URL and the status tells.
	NoNokRedirect: true,
	Signing:       &berlingroup.Signing{Required: true},
}

func init() { berlingroup.Register(Profile) }
