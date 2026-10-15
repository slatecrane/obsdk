// Package revolut implements Revolut's Open Banking API (UK OBIE style, also
// used for EEA customers): redirect consent with a signed request object,
// accounts, balances and transactions.
//
// Every call is mutual TLS: Config.HTTPClient must present the transport
// certificate (see HTTPClient). The request object that starts the user's
// authorisation is signed with Config.Seal, whose public key Revolut fetches
// from the JWKS URL registered in the developer portal.
//
// See docs/revolut.md for what was verified against the sandbox.
package revolut

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "revolut-ob-v3"
	bankKey       = "revolut"

	// financialID is Revolut's ASPSP id, sent as x-fapi-financial-id.
	financialID = "001580000103UAvAAM"

	sandboxAPI    = "https://sandbox-oba-auth.revolut.com"
	sandboxUI     = "https://sandbox-oba.revolut.com/ui/index.html"
	productionAPI = "https://oba-auth.revolut.com"
	productionUI  = "https://oba.revolut.com/ui/index.html"

	// Extra parameters.
	paramBaseURL = "base_url" // override the API host (tests, proxies)
	paramAuthURL = "auth_url" // override the consent page URL
	paramJWSTan  = "jws_tan"  // root domain of the JWKS URL, signed into payment request signatures
)

// openBankingPreprodRoot is the OpenBanking Pre-Production Root CA. Revolut's
// sandbox API presents a chain ending in it, and it is not in system trust
// stores. It is a public certificate (valid until 2037).
//
//go:embed openbanking-preprod-root.crt
var openBankingPreprodRoot []byte

// SandboxRoots returns a pool that trusts the sandbox API's server certificate.
func SandboxRoots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(openBankingPreprodRoot)
	return p
}

// HTTPClient returns an HTTP client that presents the transport certificate
// and, in the sandbox, trusts the sandbox API's root CA. Production uses the
// system roots.
func HTTPClient(env obsdk.Env, transport tls.Certificate) *http.Client {
	tc := &tls.Config{Certificates: []tls.Certificate{transport}, MinVersion: tls.VersionTLS12}
	if env == obsdk.Sandbox {
		tc.RootCAs = SandboxRoots()
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tc
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

// eea lists the countries served by Revolut's EEA entity through the same API.
var eea = []obsdk.Country{
	"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IS",
	"IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK",
}

func init() {
	var variants []obsdk.Variant
	for _, c := range append([]obsdk.Country{"GB"}, eea...) {
		for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
			sandbox := obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
			if c == "GB" && seg == obsdk.Personal {
				// Connect, accounts, balances, transactions (empty in the sandbox),
				// refresh and disconnect (scenarios live-gb-*).
				sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, "2026-10-14"
			}
			variants = append(variants, sandbox,
				obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			)
		}
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     bankKey,
			Name:     "Revolut",
			Group:    "Revolut",
			Spec:     "uk",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "from the Revolut developer portal (one per environment)"},
				{Name: "redirect_url", Required: true, Note: "must be registered in the developer portal, without variable parameters"},
				{Name: "tls_client_cert", Required: true, Note: "transport certificate for mTLS; build the client with revolut.HTTPClient"},
				{Name: "seal", Secret: true, Required: true, Note: "RSA key that signs the request object (PS256); KeyID must match the kid in the JWKS registered in the portal"},
				{Name: paramJWSTan, Note: "payments only: host of the JWKS URL registered in the portal (e.g. raw.githubusercontent.com), signed into x-jws-signature (the JWKS key needs x5c)"},
			},
			Limits: obsdk.Limits{},
			Docs: []string{
				"https://developer.revolut.com/docs/guides/build-banking-apps/tutorials/get-account-and-transaction-information",
				"https://developer.revolut.com/docs/api/open-banking",
			},
			Notes: []string{
				"Access tokens last about an hour; refresh tokens 180 days for EEA eIDAS TPPs, 50 years for UK AISPs.",
				"Refreshing an access token invalidates the previous one.",
				"A consent without an expiry stays valid as long as the refresh token.",
				"Account identifiers (IBAN, sort code) can be shared by several currency accounts; Account.ID is unique per currency.",
			},
		},
		Factory: newClient,
	})
}

type client struct {
	cfg    obsdk.Config
	target obsdk.Target
	http   obsdk.HTTPDoer
	host   string
	ui     string
	log    *slog.Logger
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"tls_client_cert (HTTPClient with the transport certificate)"}}
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, host: productionAPI, ui: productionUI}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.host, c.ui = sandboxAPI, sandboxUI
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if h := cfg.Param(paramBaseURL); h != "" {
		c.host = strings.TrimRight(h, "/")
	}
	if u := cfg.Param(paramAuthURL); u != "" {
		c.ui = u
	}
	return c, nil
}

// isNilDoer catches a typed nil (*http.Client)(nil) stored in the interface.
func isNilDoer(d obsdk.HTTPDoer) bool {
	hc, ok := d.(*http.Client)
	return ok && hc == nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func (c *client) Info() obsdk.Info {
	i, _ := obsdk.Lookup(bankKey)
	var vs []obsdk.Variant
	for _, v := range i.Variants {
		if v.Country == c.target.Country && v.Env == c.cfg.Env && v.Segment == c.target.Segment {
			vs = append(vs, v)
		}
	}
	i.Variants = vs
	return i
}

func (c *client) now() time.Time { return c.cfg.Clock() }

func (c *client) checkSession(s *obsdk.Session) error {
	switch {
	case s == nil:
		return fmt.Errorf("%w: nil session", obsdk.ErrInvalidRequest)
	case s.Integration != integrationID || s.Bank != bankKey:
		return fmt.Errorf("%w: session belongs to %s/%s", obsdk.ErrInvalidRequest, s.Bank, s.Integration)
	case s.Env != c.cfg.Env:
		return fmt.Errorf("%w: session is for %s, client for %s", obsdk.ErrInvalidRequest, s.Env, c.cfg.Env)
	}
	return nil
}
