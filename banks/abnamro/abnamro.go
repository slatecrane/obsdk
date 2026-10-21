// Package abnamro implements ABN AMRO's PSD2 APIs (the Netherlands): OAuth2
// consent for one account at a time, account details, balances and
// activities (booked transactions and reservations), and SEPA and
// cross-border payment initiation.
//
// The token endpoint is mutual TLS: Config.HTTPClient must present the QWAC
// (see HTTPClient). API calls carry the application's API key
// (Extra api_key) and the user's bearer token; nothing is signed.
//
// The sandbox is open to anyone with a developer-portal account: the client
// id (TPP_test), the redirect URL (https://localhost/auth) and the mTLS
// certificate are shared and published by ABN AMRO. See docs/abnamro.md.
package abnamro

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "abnamro-psd2"
	bankKey       = "abnamro"
	bic           = "ABNANL2A"

	sandboxAPI     = "https://api-sandbox.abnamro.com"
	sandboxAuth    = "https://auth-sandbox.abnamro.com/as/authorization.oauth2"
	sandboxToken   = "https://auth-mtls-sandbox.abnamro.com/as/token.oauth2"
	sandboxRevoke  = "https://auth-mtls-sandbox.abnamro.com/as/revoke_token.oauth2"
	productionAPI  = "https://api.abnamro.com"
	productionAuth = "https://www.abnamro.nl/consent/v2/authorize"
	// The tutorials give the production token endpoint; the revocation
	// endpoint is assumed at the same place as in the sandbox (PingFederate).
	productionToken  = "https://auth-mtls.abnamro.com/as/token.oauth2"
	productionRevoke = "https://auth-mtls.abnamro.com/as/revoke_token.oauth2"

	// Extra parameters.
	paramAPIKey    = "api_key"    // the application's API key from the developer portal (required)
	paramBaseURL   = "base_url"   // override the API base (tests, proxies)
	paramAuthURL   = "auth_url"   // override the authorization endpoint
	paramTokenURL  = "token_url"  // override the token endpoint
	paramRevokeURL = "revoke_url" // override the revocation endpoint
)

// HTTPClient returns an HTTP client that presents the QWAC (in the sandbox,
// ABN AMRO's published sandbox certificate). ABN AMRO's servers use
// certificates from a public CA, so the system roots apply.
func HTTPClient(qwac tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{qwac}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

func init() {
	var variants []obsdk.Variant
	for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
		// Connect, account details, balances, activities (booked pages and
		// reservations), refresh, disconnect, SEPA (with a CUR reference),
		// cross-border, rejected and cancelled payments (scenarios live-nl-*).
		// The sandbox's test accounts are retail, commercial and corporate
		// behind one API, so both segments count.
		variants = append(variants,
			obsdk.Variant{Country: "NL", Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturitySandboxVerified, VerifiedOn: "2026-10-21"},
			obsdk.Variant{Country: "NL", Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		)
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     bankKey,
			Name:     "ABN AMRO",
			Group:    "ABN AMRO",
			Spec:     "custom",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "the client id ABN AMRO assigns at production onboarding (sandbox: TPP_test)"},
				{Name: "api_key", Secret: true, Required: true, Note: "Extra api_key: the API key of the application on the ABN AMRO developer portal"},
				{Name: "redirect_url", Required: true, Note: "a redirect URL agreed at onboarding (sandbox: https://localhost/auth, nothing else)"},
				{Name: "tls_client_cert", Required: true, Note: "QWAC with Client Authentication usage for the token endpoint (sandbox: ABN AMRO's published certificate); build the client with abnamro.HTTPClient"},
			},
			Limits: obsdk.Limits{MaxConsentDays: consentDays},
			Docs: []string{
				"https://developer.abnamro.com/api-products/account-information-psd2/tutorial",
				"https://developer.abnamro.com/api-products/account-information-psd2/reference-documentation",
				"https://developer.abnamro.com/api-products/payment-initiation-psd2/tutorial",
				"https://developer.abnamro.com/api-products/payment-initiation-psd2/reference-documentation",
			},
			Notes: []string{
				"A consent covers exactly one account, which the user picks on ABN AMRO's page. Connect once per account; each connection is its own session.",
				"Consents last 180 days (7 days in the sandbox). Access tokens last 2 hours; refresh them with the refresh token.",
				"Transactions come 50 per page. Pending items are ABN AMRO's reservations (card holds and similar), which have no booking date.",
				"Payments: ABN AMRO answers the status of a payment only with the token the user's approval produced. The approval's StepDone carries that token as a session: keep it and pass it as PaymentCallOptions.Session.",
			},
		},
		Factory: newClient,
	})
}

type client struct {
	cfg    obsdk.Config
	target obsdk.Target
	http   obsdk.HTTPDoer
	log    *slog.Logger
	apiKey string
	api    string
	auth   string
	token  string
	revoke string
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	var missing []string
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		missing = append(missing, "tls_client_cert (HTTPClient with the QWAC)")
	}
	if cfg.Credentials.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if cfg.Param(paramAPIKey) == "" {
		missing = append(missing, "api_key (Extra)")
	}
	if len(missing) > 0 {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: missing}
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, apiKey: cfg.Param(paramAPIKey),
		api: productionAPI, auth: productionAuth, token: productionToken, revoke: productionRevoke}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.api, c.auth, c.token, c.revoke = sandboxAPI, sandboxAuth, sandboxToken, sandboxRevoke
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	for _, o := range []struct {
		param string
		dst   *string
	}{{paramBaseURL, &c.api}, {paramAuthURL, &c.auth}, {paramTokenURL, &c.token}, {paramRevokeURL, &c.revoke}} {
		if u := cfg.Param(o.param); u != "" {
			*o.dst = strings.TrimRight(u, "/")
		}
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
