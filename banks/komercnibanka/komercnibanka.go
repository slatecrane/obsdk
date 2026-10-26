// Package komercnibanka implements Komerční banka's PSD2 APIs (Czech
// Republic), which follow the Czech Banking Association's open banking
// standard (ČBS / COBS): OAuth2 login with scope aisp or pisp, the client's
// accounts, balances and transaction history, and domestic and SEPA payment
// initiation approved on KB's signing page.
//
// Every call is mutual TLS: Config.HTTPClient must present the QWAC or
// QSealC registered with KB (see HTTPClient). Production client credentials
// come from KB's dynamic registration (POST /serverapi/oauth2/v1/register,
// see docs/komercnibanka.md). Nothing is signed.
//
// The sandbox is open to anyone with a developer-portal account: the client
// certificate is shared and published on the portal, the client id and
// secret are not checked, and the login page only asks for a test client
// name. See docs/komercnibanka.md.
package komercnibanka

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "komercnibanka-cbs"
	bankKey       = "komercnibanka"
	bic           = "KOMBCZPP"

	productionAPI  = "https://api.kb.cz/serverapi"
	productionAuth = "https://login.kb.cz/autfe/ssologin"
	sandboxAPI     = "https://api.kb.cz/sandbox"
	// The sandbox's login page asks for a test client name and builds the
	// code from it in the browser; nothing is checked.
	sandboxAuth = "https://api-gateway.kb.cz/sandbox/oauth2-authorization-ui/v3/"

	// Extra parameters.
	paramTPPName  = "tpp_name"  // TPP-Name header: the TPP's name, without diacritics (required)
	paramTPPID    = "tpp_id"    // TPP-Identification header: the TPP's licence number (optional)
	paramBaseURL  = "base_url"  // override the API base, up to and excluding /oauth2, /aisp, /pisp (tests, proxies)
	paramAuthURL  = "auth_url"  // override the authorization endpoint
	paramTokenURL = "token_url" // override the token endpoint
)

// HTTPClient returns an HTTP client that presents the QWAC or QSealC (in the
// sandbox, KB's published PSD2 Sandbox Test Certificate). KB's servers use
// certificates from a public CA, so the system roots apply. KB's gateway
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
		// Connect, accounts, balances, transactions (empty in the stub),
		// refresh, disconnect, domestic payments signed, status (scenarios
		// live-cz-*, 2026-10-23); domestic standing orders signed and read,
		// existing ones listed (2026-10-26). SEPA can't be signed in the sandbox. The stub has the
		// same test accounts for any client name, so both segments count.
		variants = append(variants,
			obsdk.Variant{Country: "CZ", Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturitySandboxVerified, VerifiedOn: "2026-10-26"},
			obsdk.Variant{Country: "CZ", Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		)
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     bankKey,
			Name:     "Komerční banka",
			Group:    "Société Générale",
			Spec:     "cbs",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapStandingOrders, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "from KB's dynamic client registration (sandbox: any value)"},
				{Name: "client_secret", Secret: true, Note: "from KB's dynamic client registration; required in production (sandbox: not checked)"},
				{Name: "redirect_url", Required: true, Note: "one of the redirect URIs registered for the client; KB's signing page wants https"},
				{Name: "tpp_name", Required: true, Note: "Extra tpp_name: the TPP's name for the TPP-Name header, without diacritics"},
				{Name: "tpp_id", Note: "Extra tpp_id: the TPP's licence number for the TPP-Identification header"},
				{Name: "tls_client_cert", Required: true, Note: "QWAC or QSealC registered with KB at api@kb.cz (sandbox: the PSD2 Sandbox Test Certificate from developers.kb.cz); build the client with komercnibanka.HTTPClient"},
			},
			Limits: obsdk.Limits{MaxConsentDays: consentDays},
			Docs: []string{
				"https://developers.kb.cz/",
				"https://www.kb.cz/en/kbapi/psd2-services",
				"https://www.kb.cz/getmedia/9a0d88f0-f2ce-48df-842f-8cc747ec59e2/Third-Party-Registering-Authorising-Process-Manual_v6.pdf",
			},
			Notes: []string{
				"Access lasts 180 days from the login; access tokens last an hour and are renewed with the refresh token.",
				"KB gives history older than 90 days only within 5 minutes of the login.",
				"Account ids are encrypted and change on every account listing; older ids keep working. Match accounts across calls with StableID.",
				"A multi-currency account is listed once per currency, with the same IBAN.",
				"Payments need their own login (scope pisp) before KB's signing page: two redirects. Signed payments are irrevocable.",
				"Domestic standing orders (PaymentRequest.Schedule; Info.StandingOrderSpec): daily to yearly, end date or count; status readable, no cancellation through the API.",
				"Existing standing orders are read with StandingOrderLister (the Connect session).",
			},
		},
		Factory: newClient,
	})
}

type client struct {
	cfg     obsdk.Config
	target  obsdk.Target
	http    obsdk.HTTPDoer
	log     *slog.Logger
	tppName string
	tppID   string
	api     string
	auth    string
	token   string
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	var missing []string
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		missing = append(missing, "tls_client_cert (HTTPClient with the QWAC or QSealC)")
	}
	if cfg.Credentials.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if cfg.Env == obsdk.Production && cfg.Credentials.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if cfg.Param(paramTPPName) == "" {
		missing = append(missing, "tpp_name (Extra)")
	}
	if len(missing) > 0 {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: missing}
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, tppName: cfg.Param(paramTPPName), tppID: cfg.Param(paramTPPID),
		api: productionAPI, auth: productionAuth}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.api, c.auth = sandboxAPI, sandboxAuth
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if u := cfg.Param(paramBaseURL); u != "" {
		c.api = strings.TrimRight(u, "/")
	}
	if u := cfg.Param(paramAuthURL); u != "" {
		c.auth = u
	}
	c.token = c.api + "/oauth2/v1/token"
	if u := cfg.Param(paramTokenURL); u != "" {
		c.token = u
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
