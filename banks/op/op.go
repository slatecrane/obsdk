// Package op implements OP Financial Group's PSD2 APIs (Finland): account
// information, SEPA and foreign payments, with OpenID Connect redirects
// signed with the QSealC key.
//
// Every call is mutual TLS: Config.HTTPClient must present the QWAC (see
// HTTPClient). Requests also carry the API key of the OP Developer app
// (Extra "api_key"). The authorisation request object and payment bodies are
// signed with Config.Seal (RS256 or ES256); Seal.KeyID is the key's kid in
// the JWKS given at registration. In the sandbox, OP generates the
// certificates and keys: see banks/op/sandboxsetup.
//
// See docs/op.md for what was verified against the sandbox.
package op

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "op-psd2-v1"
	bankKey       = "op"

	sandboxAPI     = "https://psd2.mtls.sandbox.apis.op.fi"
	sandboxAuth    = "https://authorize.psd2-sandbox.op.fi/oauth/authorize"
	productionAPI  = "https://psd2.mtls.apis.op.fi"
	productionAuth = "https://authorize.op.fi/oauth/authorize"

	// audience is the aud of the request object. OP's docs use the
	// production host for both environments.
	audience = "https://mtls.apis.op.fi"

	// Extra parameters.
	paramAPIKey  = "api_key"  // x-api-key: the OP Developer app's key
	paramBaseURL = "base_url" // override the API host (tests, proxies)
	paramAuthURL = "auth_url" // override the authorisation page URL
	paramAud     = "aud"      // override the request object's audience
)

// HTTPClient returns an HTTP client that presents the QWAC (or, in the
// sandbox, the certificate OP generated) for mutual TLS.
func HTTPClient(qwac tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{qwac}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

func init() {
	var variants []obsdk.Variant
	for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
		sandbox := obsdk.Variant{Country: "FI", Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
		if seg == obsdk.Personal {
			// Connect, accounts, balances, transactions, refresh, SEPA payments
			// (immediate and dated), status and revoke (scenarios live-fi-*).
			sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, "2026-10-17"
		}
		variants = append(variants, sandbox,
			obsdk.Variant{Country: "FI", Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		)
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     bankKey,
			Name:     "OP Financial Group",
			Group:    "OP Pohjola",
			Spec:     "custom",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "from the registration response (POST /tpp-registration/register)"},
				{Name: "client_secret", Secret: true, Required: true, Note: "from the registration response"},
				{Name: "redirect_url", Required: true, Note: "one of the redirect_uris registered for the client"},
				{Name: paramAPIKey, Secret: true, Required: true, Note: "API key of the OP Developer app (sent as x-api-key)"},
				{Name: "tls_client_cert", Required: true, Note: "QWAC for mTLS; build the client with op.HTTPClient"},
				{Name: "seal", Secret: true, Required: true, Note: "QSealC key (RSA or P-256) that signs the request object and payment bodies; KeyID is its kid in the registered JWKS"},
			},
			Limits: obsdk.Limits{
				MaxConsentDays:           180,
				MaxRequestsPerDay:        4,
				HistoryWithoutStepUpDays: 90,
			},
			Docs: []string{
				"https://op-developer.fi/p/psd2-tpp-setup",
				"https://op-developer.fi/p/accountauthorizationflow",
				"https://op-developer.fi/p/workflow-for-op-psd2-payment-initiation-service-api-v2",
			},
			Notes: []string{
				"Access tokens last an hour; refresh tokens 45 days and are renewed on refresh. The authorisation itself lasts up to 180 days.",
				"Without the user present OP allows 4 requests per 24 hours under one authorisation.",
				"The transactions API has no date filter: the SDK filters by date and pages through the bank's continuation tokens.",
				"Cards covered by the authorisation are listed as accounts of type CARD.",
				"Business accounts: the company representative needs an extra access right from the company before they can approve.",
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
	auth   string
	aud    string
	log    *slog.Logger
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"tls_client_cert (HTTPClient with the QWAC)"}}
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, host: productionAPI, auth: productionAuth, aud: audience}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.host, c.auth = sandboxAPI, sandboxAuth
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if h := cfg.Param(paramBaseURL); h != "" {
		c.host = strings.TrimRight(h, "/")
	}
	if u := cfg.Param(paramAuthURL); u != "" {
		c.auth = u
	}
	if a := cfg.Param(paramAud); a != "" {
		c.aud = a
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
