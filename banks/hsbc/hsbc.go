// Package hsbc implements the Open Banking APIs of HSBC's retail brands: HSBC
// UK (personal and business), first direct, M&S Bank (UK OBIE v4.0) and
// HSBC Malta (OBIE v3.1). Each brand is its own host, registered as its own
// bank key: hsbc, firstdirect, mandsbank.
//
// Every call is mutual TLS (Config.HTTPClient must present the transport
// certificate; see HTTPClient). The client authenticates at the token
// endpoint with private_key_jwt and signs request objects with Config.Seal
// (PS256; Seal.KeyID is the kid HSBC registered for the signing certificate).
//
// See docs/hsbc.md for what was verified against the sandbox.
package hsbc

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationPrefix = "hsbc-ob-"

	paramBaseURL = "base_url" // override the API host (tests, proxies)
	paramAuthURL = "auth_url" // override the authorisation page URL
	paramJWSTan  = "jws_tan"  // trust anchor signed into x-jws-signature (default openbanking.org.uk)
)

// brand is one HSBC Open Banking channel: its own hosts, spec version and customers.
type brand struct {
	bank    string // SDK bank key
	name    string
	country obsdk.Country
	segment obsdk.Segment
	domain  string // api.ob.<domain>, ob.<domain>; sandbox: secure.sandbox.ob.<domain>, sandbox.ob.<domain>
	version string // "v4.0" or "v3.1"
}

var brands = []brand{
	{bank: "hsbc", name: "HSBC UK", country: "GB", segment: obsdk.Personal, domain: "hsbc.co.uk", version: "v4.0"},
	{bank: "hsbc", name: "HSBC UK Business", country: "GB", segment: obsdk.Business, domain: "business.hsbc.co.uk", version: "v4.0"},
	{bank: "hsbc", name: "HSBC Malta", country: "MT", segment: obsdk.Personal, domain: "hsbc.com.mt", version: "v3.1"},
	{bank: "firstdirect", name: "first direct", country: "GB", segment: obsdk.Personal, domain: "firstdirect.com", version: "v4.0"},
	{bank: "mandsbank", name: "M&S Bank", country: "GB", segment: obsdk.Personal, domain: "mandsbank.com", version: "v4.0"},
}

func (b brand) apiHost(env obsdk.Env) string {
	if env == obsdk.Sandbox {
		return "https://secure.sandbox.ob." + b.domain
	}
	return "https://api.ob." + b.domain
}

func (b brand) authURL(env obsdk.Env) string {
	if env == obsdk.Sandbox {
		return "https://sandbox.ob." + b.domain + "/obie/open-banking/v1.1/oauth2/authorize"
	}
	return "https://ob." + b.domain + "/obie/open-banking/v1.1/oauth2/authorize"
}

// HTTPClient returns an HTTP client that presents the transport certificate.
// HSBC's servers use public-CA certificates in the sandbox and production.
func HTTPClient(transport tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{transport}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

var names = map[string]string{"hsbc": "HSBC", "firstdirect": "first direct", "mandsbank": "M&S Bank"}

func init() {
	for _, bank := range []string{"hsbc", "firstdirect", "mandsbank"} {
		var variants []obsdk.Variant
		for _, b := range brands {
			if b.bank != bank {
				continue
			}
			// Every brand: connect, accounts, balances, transactions (scenarios
			// live-<brand>-*). HSBC UK personal also refresh, disconnect and a
			// Faster Payment (live-gb-*).
			variants = append(variants,
				obsdk.Variant{Country: b.country, Segment: b.segment, Env: obsdk.Sandbox, Maturity: obsdk.MaturitySandboxVerified, VerifiedOn: "2026-10-17"},
				obsdk.Variant{Country: b.country, Segment: b.segment, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			)
		}
		obsdk.Register(obsdk.Integration{
			ID: integrationPrefix + bank,
			Info: obsdk.Info{
				Bank: bank, Name: names[bank], Group: "HSBC", Spec: "uk", Variants: variants,
				Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
				Payments:     paymentSpecs(),
				Limits:       obsdk.Limits{HistoryWithoutStepUpDays: 90},
				Auth:         obsdk.AuthInfo{Approaches: []string{"redirect"}},
				Requirements: []obsdk.Requirement{
					{Name: "client_id", Required: true, Note: "from dynamic client registration (sandbox: the project on developer.hsbc.com)"},
					{Name: "redirect_url", Required: true, Note: "one of the redirect URIs in the software statement"},
					{Name: "tls_client_cert", Required: true, Note: "transport certificate for mTLS (sandbox: issued by HSBC from your CSR); build the client with hsbc.HTTPClient"},
					{Name: "seal", Secret: true, Required: true, Note: "RSA signing key (PS256) for client assertions, request objects and payment signatures; KeyID is the kid HSBC registered; payments also need the Certificate (its DN is signed in)"},
					{Name: paramJWSTan, Note: "payments only: trust anchor signed into x-jws-signature (default openbanking.org.uk)"},
				},
				Docs: []string{
					"https://developer.hsbc.com/web-hub/apis?api=account-information-uk-hsbc-personal-v4.0&view=overview",
					"https://developer.hsbc.com/uce-asset/v2/sites/dev-portal/assets/hsbc-uk-open-banking-implementation-guide-v4-0-1-16-10-2026.pdf",
				},
				Notes: []string{
					"Each brand has its own hosts and its own client registration.",
					"The authorisation response comes back in the URL fragment (code, id_token, state).",
					"Within an hour of the user's authorisation every cluster is readable; after that only accounts, balances and the last 90 days of transactions (older ranges answer 403 until the user authorises again).",
					"Payments: UK brands only (Faster Payments, single or future-dated).",
				},
			},
			Factory: newClient,
		})
	}
}

type client struct {
	cfg    obsdk.Config
	target obsdk.Target
	brand  brand
	http   obsdk.HTTPDoer
	host   string
	auth   string
	log    *slog.Logger
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"tls_client_cert (HTTPClient with the transport certificate)"}}
	}
	if cfg.Seal == nil || cfg.Seal.Key == nil || cfg.Seal.KeyID == "" {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"seal (signing key with KeyID)"}}
	}
	if _, ok := cfg.Seal.Key.Public().(*rsa.PublicKey); !ok {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Invalid: []string{"seal: HSBC needs an RSA key (PS256)"}}
	}
	if t.Segment == "" {
		t.Segment = obsdk.Personal
	}
	var b *brand
	for i := range brands {
		if brands[i].bank == t.Bank && brands[i].country == t.Country && brands[i].segment == t.Segment {
			b = &brands[i]
		}
	}
	if b == nil {
		return nil, fmt.Errorf("%w: %s %s %s", obsdk.ErrUnsupportedTarget, t.Bank, t.Country, t.Segment)
	}
	c := &client{cfg: cfg, target: t, brand: *b, http: cfg.HTTPClient, log: cfg.Logger,
		host: b.apiHost(cfg.Env), auth: b.authURL(cfg.Env)}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if h := cfg.Param(paramBaseURL); h != "" {
		c.host = strings.TrimRight(h, "/")
	}
	if u := cfg.Param(paramAuthURL); u != "" {
		c.auth = u
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

func (c *client) integrationID() string { return integrationPrefix + c.brand.bank }

func (c *client) Info() obsdk.Info {
	i, _ := obsdk.Lookup(c.brand.bank)
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

// apiPath is the base path of an API family ("aisp", "pisp") for the brand's version.
func (c *client) apiPath(family string) string {
	return "/obie/open-banking/" + c.brand.version + "/" + family
}

func (c *client) checkSession(s *obsdk.Session) error {
	switch {
	case s == nil:
		return fmt.Errorf("%w: nil session", obsdk.ErrInvalidRequest)
	case s.Integration != c.integrationID() || s.Bank != c.brand.bank:
		return fmt.Errorf("%w: session belongs to %s/%s", obsdk.ErrInvalidRequest, s.Bank, s.Integration)
	case s.Env != c.cfg.Env:
		return fmt.Errorf("%w: session is for %s, client for %s", obsdk.ErrInvalidRequest, s.Env, c.cfg.Env)
	case s.Country != c.target.Country || s.Segment != c.target.Segment:
		return fmt.Errorf("%w: session is for %s %s, client for %s %s", obsdk.ErrInvalidRequest, s.Country, s.Segment, c.target.Country, c.target.Segment)
	}
	return nil
}
