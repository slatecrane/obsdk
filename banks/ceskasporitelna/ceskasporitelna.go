// Package ceskasporitelna implements Česká spořitelna's PSD2 APIs (Czech
// Republic, Erste Group), which follow the Czech Banking Association's open
// banking standard (ČBS / ČOBS, see internal/cbs): an OAuth2 login with scope
// AISP or PISP at ČS's identity provider, the client's accounts, balances
// and transaction history, and domestic and SEPA payments approved on ČS's
// federated signing page.
//
// Every call is mutual TLS: Config.HTTPClient must present the QWAC (build
// it with HTTPClient). Every API call also carries the portal application's
// web-api-key (Extra api_key). Payment calls are signed with the QSealC
// (Config.Seal) in production.
//
// The sandbox is open to anyone with an Erste developer-portal account: the
// portal issues the application's keys and a sample PSD2 QWAC, the login
// page only asks to pick a test client, and the data is static. See
// docs/ceskasporitelna.md.
package ceskasporitelna

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "ceskasporitelna-cbs"
	bankKey       = "ceskasporitelna"
	bic           = "GIBACZPX"

	productionAPI = "https://webapi.developers.erstegroup.com/api/csas/production/v4"
	productionIDP = "https://bezpecnost.csas.cz/api/psd2/fl/oidc/v1"
	sandboxAPI    = "https://webapi.developers.erstegroup.com/api/csas/sandbox/v4"
	// The sandbox's identity provider asks to pick a test client and to
	// confirm the scopes; nothing is checked.
	sandboxIDP = "https://webapi.developers.erstegroup.com/api/csas/sandbox/v1/sandbox-idp"

	// Extra parameters.
	paramAPIKey  = "api_key"  // web-api-key header: the portal application's API key (required)
	paramBaseURL = "base_url" // override the API base, up to and excluding /account-information, /payment-initiation (tests, proxies)
	paramIDPURL  = "idp_url"  // override the identity provider, up to and excluding /auth, /token, /revokeext
)

// HTTPClient returns an HTTP client that presents the QWAC (in the sandbox,
// the sample PSD2 QWAC from the developer portal). ČS's servers use
// certificates from a public CA, so the system roots apply. ČS's gateway
// asks for the client certificate by renegotiating TLS 1.2 after the
// request line, which Go refuses unless allowed.
func HTTPClient(cert tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		Renegotiation: tls.RenegotiateOnceAsClient}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

func init() {
	var variants []obsdk.Variant
	for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
		// Connect, accounts, balances, transactions, refresh, disconnect,
		// domestic and SEPA payments signed, status (scenarios live-cz-*,
		// 2026-10-24); domestic standing orders signed (2026-10-25) and listed
		// (2026-10-26).
		// The sandbox's data and payment answers are static, and its one
		// test client stands for both segments.
		variants = append(variants,
			obsdk.Variant{Country: "CZ", Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturitySandboxVerified, VerifiedOn: "2026-10-26"},
			obsdk.Variant{Country: "CZ", Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		)
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     bankKey,
			Name:     "Česká spořitelna",
			Group:    "Erste Group",
			Spec:     "cbs",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapStandingOrders, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "OAuth2 client id of the application on developers.erstegroup.com, per environment"},
				{Name: "client_secret", Required: true, Secret: true, Note: "OAuth2 client secret of the same application"},
				{Name: "redirect_url", Required: true, Note: "one of the redirect URIs registered for the application"},
				{Name: "api_key", Required: true, Secret: true, Note: "Extra api_key: the application's API key (web-api-key header)"},
				{Name: "tls_client_cert", Required: true, Note: "QWAC registered on the developer portal (sandbox: the sample PSD2 QWAC in the application's sandbox credentials); build the client with ceskasporitelna.HTTPClient"},
				{Name: "seal", Note: "QSealC (Config.Seal) to sign payment calls; required in production"},
			},
			Limits: obsdk.Limits{MaxConsentDays: consentDays},
			Docs: []string{
				"https://developers.erstegroup.com/docs/apis/bank.csas",
				"https://developers.erstegroup.com/docs/tutorial/csas-how-to-call-api",
				"https://developers.erstegroup.com/docs/tutorial/how-to-use-certificate-qseal",
			},
			Notes: []string{
				"Access lasts 180 days from the login (the refresh token's lifetime); access tokens last 5 minutes and are renewed with the refresh token.",
				"Payments need their own login (scope PISP) before ČS's signing page: two redirects.",
				"Payment status needs the payment login's session (PaymentCallOptions.Session).",
				"Domestic standing orders (PaymentRequest.Schedule; Info.StandingOrderSpec): monthly to yearly, no status or cancellation through the API.",
				"Existing standing orders are read with StandingOrderLister (the Connect session).",
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
	idp    string
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	var missing []string
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		missing = append(missing, "tls_client_cert (HTTPClient with the QWAC)")
	}
	if cfg.Credentials.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if cfg.Credentials.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if cfg.Param(paramAPIKey) == "" {
		missing = append(missing, "api_key (Extra)")
	}
	if cfg.Env == obsdk.Production && (cfg.Seal == nil || cfg.Seal.Key == nil || cfg.Seal.Certificate == nil) {
		missing = append(missing, "seal (Config.Seal with the QSealC key and certificate)")
	}
	if len(missing) > 0 {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: missing}
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, apiKey: cfg.Param(paramAPIKey),
		api: productionAPI, idp: productionIDP}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.api, c.idp = sandboxAPI, sandboxIDP
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if u := cfg.Param(paramBaseURL); u != "" {
		c.api = strings.TrimRight(u, "/")
	}
	if u := cfg.Param(paramIDPURL); u != "" {
		c.idp = strings.TrimRight(u, "/")
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
