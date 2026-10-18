// Package kbc implements the Berlin Group PSD2 API that KBC Group runs for its
// Belgian brands KBC, CBC and KBC Brussels: account information (one consent
// per connection, approved with an OAuth2 authorisation-code flow with PKCE),
// and single payment initiation (SEPA, SEPA Instant, cross-border) approved on
// a plain redirect.
//
// Every call is mutual TLS with an eIDAS QWAC (Config.HTTPClient, see
// HTTPClient); there is no registration, no client secret and no request
// signing. The OAuth client id is the organizationIdentifier of the QWAC
// (ClientID reads it from the certificate).
//
// The sandbox needs a QWAC too: KBC hands out a shared test certificate and key
// on request (developer@kbc.be). See docs/kbc.md.
package kbc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationPrefix = "kbc-psd2-"

	sandboxHost = "https://be.psd2.sandbox.kbc-group.com"
	apiPath     = "/psd2/v2"

	productionAuthorize = "https://idp.kbc.com/ASK/oauth/authorize/1"
	productionToken     = "https://openapi.kbc-group.com/ASK/oauth/token/1"

	// Extra parameters.
	paramBaseURL  = "base_url"  // override the API base (tests, proxies), e.g. https://host/psd2/v2
	paramTokenURL = "token_url" // override the token endpoint
	paramAuthURL  = "auth_url"  // override the authorisation page
)

// brand is one KBC Group bank on the shared PSD2 platform. The brands share
// the authorisation server; mainCompany and company tell it whose customers
// log in.
type brand struct {
	bank        string // SDK bank key
	name        string
	domain      string // production API host: psd2.api.<domain>
	bic         string
	mainCompany string // 0001 KBC, 0002 CBC
	company     string // 9998 for KBC Brussels; empty otherwise
}

var brands = []brand{
	{bank: "kbc", name: "KBC", domain: "kbc.be", bic: "KREDBEBB", mainCompany: "0001"},
	{bank: "cbc", name: "CBC", domain: "cbc.be", bic: "CREGBEBB", mainCompany: "0002"},
	{bank: "kbcbrussels", name: "KBC Brussels", domain: "kbcbrussels.be", bic: "KREDBEBB", mainCompany: "0001", company: "9998"},
}

func brandOf(bank string) (brand, bool) {
	for _, b := range brands {
		if b.bank == bank {
			return b, true
		}
	}
	return brand{}, false
}

func (b brand) apiBase(env obsdk.Env) string {
	if env == obsdk.Sandbox {
		return sandboxHost + apiPath
	}
	return "https://psd2.api." + b.domain + apiPath
}

func authorizeURL(env obsdk.Env) string {
	if env == obsdk.Sandbox {
		return sandboxHost + "/ASK/oauth/authorize/1"
	}
	return productionAuthorize
}

func tokenURL(env obsdk.Env) string {
	if env == obsdk.Sandbox {
		return sandboxHost + "/ASK/oauth/token/1"
	}
	return productionToken
}

// HTTPClient returns an HTTP client that presents the QWAC. KBC's servers use
// certificates from a public CA, so the system roots apply.
func HTTPClient(qwac tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{qwac}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

// oidOrganizationIdentifier is the X.520 organizationIdentifier (2.5.4.97)
// that carries the PSD2 authorisation number in eIDAS certificates.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

// ClientID returns the QWAC's organizationIdentifier (e.g. PSDBE-NBB-0123456789),
// which KBC expects as the OAuth client id.
func ClientID(qwac *x509.Certificate) (string, error) {
	for _, n := range qwac.Subject.Names {
		if n.Type.Equal(oidOrganizationIdentifier) {
			if s, ok := n.Value.(string); ok && s != "" {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("kbc: certificate %q has no organizationIdentifier", qwac.Subject.CommonName)
}

func init() {
	for _, b := range brands {
		var variants []obsdk.Variant
		for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
			variants = append(variants,
				obsdk.Variant{Country: "BE", Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
				obsdk.Variant{Country: "BE", Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			)
		}
		obsdk.Register(obsdk.Integration{
			ID: integrationPrefix + b.bank,
			Info: obsdk.Info{
				Bank:     b.bank,
				Name:     b.name,
				Group:    "KBC Group",
				Spec:     "berlin-group",
				Variants: variants,
				Capabilities: []obsdk.Capability{
					obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments,
				},
				Payments: paymentSpecs(),
				Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
				Requirements: []obsdk.Requirement{
					{Name: "client_id", Required: true, Note: "the organizationIdentifier of the QWAC, e.g. PSDBE-NBB-0123456789 (kbc.ClientID reads it); there is no registration"},
					{Name: "redirect_url", Required: true, Note: "sent as TPP-Redirect-URI and redirect_uri; KBC asks for HTTPS and matches it exactly on the token call"},
					{Name: "tls_client_cert", Required: true, Note: "eIDAS QWAC for mTLS (sandbox: KBC's shared test QWAC, from developer@kbc.be); build the client with kbc.HTTPClient"},
				},
				Limits: obsdk.Limits{MaxConsentDays: maxConsentDays, MaxRequestsPerDay: frequencyPerDay, RequiresPSUHeaders: []string{"IP"}},
				Docs: []string{
					"https://developer.kbc.be/api-catalog/kbccbckbc-brussels-psd2-api-account-information-services",
					"https://developer.kbc.be/api-catalog/kbccbckbc-brussels-psd2-api-payment-initiation-service",
					"https://multimediafiles.kbcgroup.eu/ng/published/pdf/kbc-user-guide-authorization-api.pdf",
					"https://multimediafiles.kbcgroup.eu/ng/multimedia/published/KBC/Pronovix/KBC-sandbox-user-guide.pdf",
				},
				Notes: []string{
					"KBC, CBC and KBC Brussels share one API; each brand has its own production host and its own customers. The sandbox is shared.",
					"A consent covers one account. Pass its IBAN as ConnectRequest.Values[\"iban\"], or leave it out and the user picks the account on KBC's page.",
					"The user's IP address (PSU.IP) is required to connect and to initiate payments.",
					"Access tokens last 30 minutes. Refresh tokens rotate on every use: always store the session Refresh returns, and never refresh one session from two places at once.",
					"Only booked transactions and only closingBooked balances are available.",
					"Payments are created and read without a user token; the user signs on KBC's page. KBC's API cannot cancel payments.",
				},
			},
			Factory: newClient,
		})
	}
}

type client struct {
	cfg       obsdk.Config
	target    obsdk.Target
	brand     brand
	http      obsdk.HTTPDoer
	api       string // API base including /psd2/v2
	tokenURL  string
	authorize string
	log       *slog.Logger
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	b, ok := brandOf(t.Bank)
	if !ok {
		return nil, fmt.Errorf("%w: %s", obsdk.ErrUnknownBank, t.Bank)
	}
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"tls_client_cert (HTTPClient with the QWAC)"}}
	}
	c := &client{cfg: cfg, target: t, brand: b, http: cfg.HTTPClient, log: cfg.Logger,
		api: b.apiBase(cfg.Env), tokenURL: tokenURL(cfg.Env), authorize: authorizeURL(cfg.Env)}
	if c.target.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if u := cfg.Param(paramBaseURL); u != "" {
		c.api = strings.TrimRight(u, "/")
	}
	if u := cfg.Param(paramTokenURL); u != "" {
		c.tokenURL = u
	}
	if u := cfg.Param(paramAuthURL); u != "" {
		c.authorize = u
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

func (c *client) checkSession(s *obsdk.Session) error {
	switch {
	case s == nil:
		return fmt.Errorf("%w: nil session", obsdk.ErrInvalidRequest)
	case s.Integration != c.integrationID() || s.Bank != c.brand.bank:
		return fmt.Errorf("%w: session belongs to %s/%s", obsdk.ErrInvalidRequest, s.Bank, s.Integration)
	case s.Env != c.cfg.Env:
		return fmt.Errorf("%w: session is for %s, client for %s", obsdk.ErrInvalidRequest, s.Env, c.cfg.Env)
	}
	return nil
}
