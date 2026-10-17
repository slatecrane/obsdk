// Package rabobank implements Rabobank's PSD2 APIs (the Netherlands): OAuth2
// redirect authorisation, accounts, balances and transactions, and single
// payment initiation (SEPA and cross-border).
//
// Every call is mutual TLS: Config.HTTPClient must present the QWAC (see
// HTTPClient). Every API request is signed with Config.Seal following
// draft-cavage-http-signatures (rsa-sha512 over date, digest and
// x-request-id); the Seal's Certificate is required because Rabobank reads
// the key from the TPP-Signature-Certificate header and its serial number.
//
// The sandbox accepts any TLS client certificate and Rabobank's published
// example signing certificate; an application on the Rabobank developer
// portal supplies the client id and secret. See docs/rabobank.md.
package rabobank

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
	integrationID = "rabobank-psd2"
	bankKey       = "rabobank"

	sandboxAPI      = "https://api-sandbox.rabobank.nl/openapi/sandbox"
	sandboxOAuth    = "https://oauth-sandbox.rabobank.nl/openapi/sandbox/oauth2"
	productionAPI   = "https://api.rabobank.nl/openapi"
	productionOAuth = "https://oauth.rabobank.nl/openapi/oauth2"

	// Extra parameters.
	paramBaseURL  = "base_url"  // override the API base (tests, proxies), e.g. https://host/openapi/sandbox
	paramOAuthURL = "oauth_url" // override the OAuth base (authorize and token live under it)
)

// HTTPClient returns an HTTP client that presents the QWAC (in the sandbox,
// any certificate). Rabobank's servers use certificates from a public CA, so
// the system roots apply.
func HTTPClient(qwac tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{qwac}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

func init() {
	var variants []obsdk.Variant
	for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
		sandbox := obsdk.Variant{Country: "NL", Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
		if seg == obsdk.Personal {
			// Connect, accounts, balances, transactions (empty pages and the
			// 8-year error), refresh, disconnect, payment creation (SEPA and
			// cross-border), status and cancel (scenarios live-nl-*).
			sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, "2026-10-17"
		}
		variants = append(variants, sandbox,
			obsdk.Variant{Country: "NL", Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		)
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     bankKey,
			Name:     "Rabobank",
			Group:    "Rabobank",
			Spec:     "custom",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapTransactionsHistory, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "the application's client id on the Rabobank developer portal (sent as X-IBM-Client-Id and in OAuth)"},
				{Name: "client_secret", Secret: true, Required: true, Note: "the application's client secret (HTTP Basic on the token endpoint)"},
				{Name: "redirect_url", Required: true, Note: "must equal an OAuth redirect URI registered on the application; also sent as TPP-Redirect-URI for payments"},
				{Name: "tls_client_cert", Required: true, Note: "QWAC for mTLS (sandbox: any certificate); build the client with rabobank.HTTPClient"},
				{Name: "seal", Secret: true, Required: true, Note: "QSealC RSA key and Certificate for the Signature header (sandbox: Rabobank's example signing certificate)"},
			},
			Limits: obsdk.Limits{MaxConsentDays: 180, MaxRequestsPerDay: 4, HistoryWithoutStepUpDays: 90},
			Docs: []string{
				"https://docs.developer.rabobank.com/psd2/reference/psd2-apis-overview",
				"https://docs.developer.rabobank.com/psd2/reference/oauth-psd2-and-premium-1",
				"https://docs.developer.rabobank.com/psd2/reference/account-information-1",
				"https://docs.developer.rabobank.com/psd2/reference/single-payments",
			},
			Notes: []string{
				"A consent lasts 180 days. Balances and transactions can be read four times a day per account without PSU-IP-Address; calls carrying the user's IP are not limited.",
				"Transactions cover the last 90 days. Older history needs CapTransactionsHistory at Connect (scope ais.transactions.read-history), which Rabobank grants for one read; dateFrom may be at most eight years back.",
				"Only booked transactions are available: Rabobank answers 400 to bookingStatus pending or both. A query for pending alone returns ErrUnsupported.",
				"Without dates Rabobank returns only yesterday's transactions; the SDK always sends dateTo (now when TxQuery.To is zero).",
				"Refresh tokens are single-use: always store the session Refresh returns.",
				"Euro payments go out as SEPA Instant when the payee's bank is reachable, otherwise as SEPA credit transfers; there is no separate instant product.",
				"Payments are created with the application's credentials only; no user login precedes the approval page, and status can be read without a session.",
				"The sandbox returns static responses for the example requests in Rabobank's documentation.",
			},
		},
		Factory: newClient,
	})
}

type client struct {
	cfg    obsdk.Config
	target obsdk.Target
	http   obsdk.HTTPDoer
	api    string
	oauth  string
	log    *slog.Logger
	keyID  string // the seal certificate's serial number in decimal
	cert   string // the seal certificate, base64 DER (TPP-Signature-Certificate)
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"tls_client_cert (HTTPClient with the QWAC)"}}
	}
	if cfg.Seal == nil || cfg.Seal.Key == nil || cfg.Seal.Certificate == nil {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"seal (key and certificate)"}}
	}
	if _, ok := cfg.Seal.Key.Public().(*rsa.PublicKey); !ok {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Invalid: []string{fmt.Sprintf("seal: Rabobank signs with RSA only, got %T", cfg.Seal.Key.Public())}}
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, api: productionAPI, oauth: productionOAuth}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.api, c.oauth = sandboxAPI, sandboxOAuth
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if u := cfg.Param(paramBaseURL); u != "" {
		c.api = strings.TrimRight(u, "/")
	}
	if u := cfg.Param(paramOAuthURL); u != "" {
		c.oauth = strings.TrimRight(u, "/")
	}
	c.keyID = cfg.Seal.Certificate.SerialNumber.String()
	c.cert = certHeader(cfg.Seal.Certificate.Raw)
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
