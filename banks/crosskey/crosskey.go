// Package crosskey implements the Open Banking APIs of the banks on Crosskey's
// platform (crosskey.io): S-Pankki, Aktia, POP Pankki, Ålandsbanken (Finland
// and Sweden), Morrow Bank and Resurs Bank. Every bank runs the same UK OBIE
// v3.1.6 APIs on its own hosts, so each is an internal/obie profile here.
//
// Every call is mutual TLS: Config.HTTPClient must present the TLS client
// certificate (see HTTPClient). Resource calls also carry the application's
// API key (Extra "api_key"). The request object and payment signatures are
// signed with Config.Seal (PS256); the kid is the signing certificate's
// serial number in decimal, taken from Seal.Certificate unless Seal.KeyID is
// set. In the sandbox the crosskey.io portal generates both certificates.
//
// See docs/crosskey.md for what was verified against the sandbox.
package crosskey

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/obie"
)

const paramAPIKey = "api_key" // the application's X-API-Key from crosskey.io

// store is one bank on the platform.
type store struct {
	id        string // crosskey.io store id; also the tenant in openbanking_intent_id
	bank      string // SDK bank key
	name      string
	countries []obsdk.Country
	segments  []obsdk.Segment
	prodAPI   string // production API host
	prodAuth  string // production host of the authorisation page
	pis       string // payment API version ("" = no payments)
	payments  []obsdk.PaymentSpec
	builder   obie.PaymentBuilder
	notes     []string
	// financialID: the store needs x-fapi-financial-id = "<store>/<country>".
	financialID bool
	// verified: the date the obdev loop passed in the sandbox, per segment,
	// for every country of the store (scenarios testdata/live-*).
	verified map[obsdk.Segment]string
}

var personal = []obsdk.Segment{obsdk.Personal}

var verifiedPersonal = map[obsdk.Segment]string{obsdk.Personal: "2026-10-18"}

var stores = []store{
	{id: "s-pankki", bank: "spankki", name: "S-Pankki", countries: []obsdk.Country{"FI"},
		segments: []obsdk.Segment{obsdk.Personal, obsdk.Business},
		prodAPI:  "https://api.s-pankki.fi", prodAuth: "https://openbanking.s-pankki.fi",
		pis: "v3.1.7", payments: sepaSpecs(), builder: buildSEPA, verified: verifiedPersonal,
		notes: []string{"Credit cards use the account scheme FI.S-Pankki.CreditCard."}},
	{id: "aktia", bank: "aktia", name: "Aktia", countries: []obsdk.Country{"FI"},
		segments: []obsdk.Segment{obsdk.Personal, obsdk.Business},
		prodAPI:  "https://api.openbanking.aktia.fi", prodAuth: "https://openbanking.aktia.fi",
		pis: "v3.1.7", payments: sepaSpecs(), builder: buildSEPA,
		verified: map[obsdk.Segment]string{obsdk.Personal: "2026-10-18", obsdk.Business: "2026-10-18"}},
	{id: "pop", bank: "poppankki", name: "POP Pankki", countries: []obsdk.Country{"FI"}, segments: personal,
		prodAPI: "https://api.openbanking.poppankki.fi", prodAuth: "https://openbanking.poppankki.fi",
		pis: "v3.1.7", payments: sepaSpecs(), builder: buildSEPA, verified: verifiedPersonal},
	{id: "alandsbanken-fi", bank: "alandsbanken", name: "Ålandsbanken", countries: []obsdk.Country{"FI"}, segments: personal,
		prodAPI: "https://api.alandsbanken.fi", prodAuth: "https://open.alandsbanken.fi",
		pis: "v3.1.7", payments: sepaSpecs(), builder: buildSEPA, verified: verifiedPersonal},
	{id: "alandsbanken-se", bank: "alandsbanken", name: "Ålandsbanken", countries: []obsdk.Country{"SE"}, segments: personal,
		prodAPI: "https://api.alandsbanken.se", prodAuth: "https://open.alandsbanken.se",
		pis: "v3.1.6", payments: swedishSpecs(), builder: buildSwedish, verified: verifiedPersonal},
	{id: "morrowbank", bank: "morrowbank", name: "Morrow Bank", countries: []obsdk.Country{"FI", "NO", "SE"}, segments: personal,
		prodAPI: "https://psd2api.morrowbank.com", prodAuth: "https://sca.morrowbank.com",
		pis: "v3.1.6", payments: morrowSpecs(), builder: buildMorrow, verified: verifiedPersonal},
	{id: "resursbank", bank: "resursbank", name: "Resurs Bank", countries: []obsdk.Country{"DK", "FI", "NO", "SE"}, segments: personal,
		prodAPI: "https://open-banking.resurs.com", prodAuth: "https://open-banking-identification.resurs.com",
		financialID: true, verified: verifiedPersonal,
		notes: []string{"Credit card accounts only; their balance is of type Expected."}},
}

func (s store) apiHost(env obsdk.Env) string {
	if env == obsdk.Sandbox {
		return "https://" + s.id + "-api-sandbox.crosskey.io"
	}
	return s.prodAPI
}

func (s store) authURL(env obsdk.Env) string {
	host := s.prodAuth
	if env == obsdk.Sandbox {
		host = "https://" + s.id + "-sandbox.crosskey.io"
	}
	return host + "/open-banking/v4.0/oidc/auth"
}

// HTTPClient returns an HTTP client that presents the TLS client
// certificate. Crosskey's servers use public-CA certificates.
func HTTPClient(transport tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{transport}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

func init() {
	for _, s := range stores {
		obie.Register(profile(s))
	}
}

func profile(s store) obie.Profile {
	var variants []obsdk.Variant
	for _, c := range s.countries {
		for _, seg := range s.segments {
			sandbox := obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
			if d := s.verified[seg]; d != "" {
				// Connect, accounts, balances, transactions and, where the
				// store has payments, a payment; see docs/crosskey.md.
				sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, d
			}
			variants = append(variants, sandbox,
				obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			)
		}
	}
	caps := []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions}
	if s.pis != "" {
		caps = append(caps, obsdk.CapPayments)
	}
	reqs := []obsdk.Requirement{
		{Name: "client_id", Required: true, Note: "the application's Client ID on crosskey.io"},
		{Name: paramAPIKey, Secret: true, Required: true, Note: "the application's X-API-Key on crosskey.io, sent on every API call"},
		{Name: "redirect_url", Required: true, Note: "one of the application's redirect URLs (exact match)"},
		{Name: "tls_client_cert", Required: true, Note: "TLS client certificate (sandbox: generated on the team page; production: QWAC); build the client with crosskey.HTTPClient"},
		{Name: "seal", Secret: true, Required: true, Note: "RSA key of the digital signature certificate (sandbox: generated; production: QSealC) with its Certificate: the kid is its serial number, its subject DN is signed in"},
	}
	notes := []string{
		"The user's authorisation comes back in the URL fragment (code, id_token, state); exchange it within 30 seconds.",
		"Access tokens last 3 minutes. A token from the user's authorisation reads all transactions the consent covers; a refreshed one only the last 90 days (older ranges answer 403 until the user authorises again).",
		"Refresh tokens are single-use: every refresh returns a new one.",
	}
	if s.pis != "" {
		notes = append(notes, "Payment tokens cannot be refreshed; the payment is submitted right after the user's approval.")
	}
	id := s.id
	p := obie.Profile{
		ID: "crosskey-" + s.id,
		Info: obsdk.Info{
			Bank: s.bank, Name: s.name, Group: "Crosskey", Variants: variants, Capabilities: caps,
			Payments: s.payments, Requirements: reqs,
			Limits: obsdk.Limits{HistoryWithoutStepUpDays: 90},
			Docs:   []string{"https://crosskey.io/tutorial", "https://crosskey.io/api/stores/" + s.id + "/apis"},
			Notes:  append(notes, s.notes...),
		},
		APIHost:             func(env obsdk.Env, _ obsdk.Target) string { return s.apiHost(env) },
		AuthURL:             func(env obsdk.Env, _ obsdk.Target) string { return s.authURL(env) },
		TokenPath:           "/open-banking/v2.0/oidc/token",
		AISPath:             "/open-banking/v3.1.6/aisp",
		ClientAuth:          obie.TLSClientAuth,
		RequestObjectIssuer: obie.IssuerCertDN,
		RequestObjectTTL:    30 * time.Minute, // Crosskey allows 60; the user has this long to open the link
		IntentID:            func(kind, consentID string) string { return "urn:" + id + ":" + kind + ":" + consentID },
		KeyID:               obie.SerialKeyID,
		RequiredParams:      []string{paramAPIKey},
		Signature: obie.Signature{
			Unencoded: true,
			TAN:       func(_ obsdk.Config, apiHost string) string { return apiHost },
		},
		Headers: func(cfg obsdk.Config, t obsdk.Target, h http.Header) {
			if k := cfg.Param(paramAPIKey); k != "" {
				h.Set("x-api-key", k)
			}
			if s.financialID {
				// One store serves several countries; this header picks the
				// market ("resursbank/no"). Missing, the API answers 400.
				h.Set("x-fapi-financial-id", s.id+"/"+strings.ToLower(string(t.Country)))
			}
		},
	}
	if s.pis != "" {
		p.PISPath = "/open-banking/" + s.pis + "/pisp"
		p.Payments = s.builder
	}
	return p
}
