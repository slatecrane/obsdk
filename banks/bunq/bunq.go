// Package bunq implements bunq's public API (one API for every country bunq
// serves): OAuth authorisation or the user's own API key, monetary accounts,
// balances and payments, and payment initiation through draft payments that
// the user approves in the bunq app.
//
// bunq is not a Berlin Group bank. Every user's access token (or API key) is
// activated as an "API context": an installation registers the client's RSA
// public key, a device-server binds the token to the caller's IP, and a
// session-server call exchanges it for a session token used on every other
// request. Config.Seal.Key is that RSA key; it needs no certificate.
// Request bodies are signed with it (X-Bunq-Client-Signature: RSA PKCS#1
// v1.5 over SHA-256 of the exact body).
//
// The sandbox needs no certificates or portal: test users, their API keys and
// an OAuth client are created through the API. See docs/bunq.md.
package bunq

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "bunq-api"
	bankKey       = "bunq"

	sandboxAPI      = "https://public-api.sandbox.bunq.com/v1"
	sandboxAuth     = "https://oauth.sandbox.bunq.com/auth"
	sandboxToken    = "https://api-oauth.sandbox.bunq.com/v1/token"
	productionAPI   = "https://api.bunq.com/v1"
	productionAuth  = "https://oauth.bunq.com/auth"
	productionToken = "https://api.oauth.bunq.com/v1/token"

	// bunqBIC is the BIC of every bunq account.
	bunqBIC = "BUNQNL2A"

	// Extra parameters.
	paramBaseURL      = "base_url"      // override the API base (tests, proxies), e.g. https://host/v1
	paramAuthURL      = "auth_url"      // override the OAuth authorization page
	paramTokenURL     = "token_url"     // override the OAuth token endpoint
	paramPermittedIPs = "permitted_ips" // comma-separated IPs (or "*") a user's token may be used from
	paramDevice       = "device_name"   // description of the device-server, shown to the user in the app
)

// eea lists the countries bunq serves from its Dutch licence, through the same API.
var eea = []obsdk.Country{
	"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IS",
	"IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK",
}

func init() {
	var variants []obsdk.Variant
	for _, c := range eea {
		for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
			sandbox := obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
			if c == "NL" {
				// Connect (method api_key), accounts, balances, three pages of
				// transactions, refresh, draft payment approved and withdrawn,
				// status, disconnect (scenarios live-nl-*). The OAuth consent
				// needs the sandbox app; its token exchange is covered by
				// unit tests and its error answers were checked live.
				sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, "2026-10-17"
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
			Name:     "bunq",
			Group:    "bunq",
			Spec:     "custom",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapTransactionsHistory, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}, Methods: []string{methodRedirect, methodAPIKey}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Note: "the OAuth client's client_id (needed for the redirect method)"},
				{Name: "client_secret", Secret: true, Note: "the OAuth client's secret (needed for the redirect method)"},
				{Name: "redirect_url", Note: "a callback URL registered on the OAuth client (needed for the redirect method)"},
				{Name: "seal", Secret: true, Required: true, Note: "an RSA key (2048 bits or more) for bunq installations and request signatures; no certificate is needed"},
				{Name: paramPermittedIPs, Note: "comma-separated IPs, or *, each user's token may be used from; empty binds it to the IP that connects"},
				{Name: paramDevice, Note: "name of the device the user sees in the bunq app (default: obsdk)"},
			},
			Docs: []string{
				"https://doc.bunq.com/basics/authentication/oauth",
				"https://doc.bunq.com/tutorials/your-first-payment/creating-the-api-context",
				"https://doc.bunq.com/basics/pagination",
				"https://doc.bunq.com/draft-payment",
			},
			Notes: []string{
				"The user gives consent by scanning a QR code on bunq's page with the bunq app, and picks the accounts to share there.",
				"The OAuth access token does not expire and has no refresh token; it is kept as Session.RefreshToken. Session.AccessToken is a bunq session token, valid for the user's auto-logout time (a week by default); Refresh starts a new one.",
				"Method api_key connects with a user's own API key instead of OAuth. bunq allows API keys only for applications that just their owner uses.",
				"Every connected user gets an installation and a device bound to the connecting IP, unless permitted_ips says otherwise. bunq limits installations to a few per IP per day.",
				"bunq cannot filter payments by date: Transactions pages backwards from the newest payment and drops what lies outside From and To. All payments are booked; there are no pending ones.",
				"Payments are draft payments: the user approves each one in the bunq app. The account to pay from must be one of the session's accounts.",
				"Rate limits are per endpoint and IP, as low as 3 GETs per 3 seconds; 429 is returned as RateLimitedError.",
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
	auth   string
	token  string
	log    *slog.Logger
	pubPEM string // the installation public key, PEM
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.Seal == nil || cfg.Seal.Key == nil {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"seal (RSA key)"}}
	}
	if _, ok := cfg.Seal.Key.Public().(*rsa.PublicKey); !ok {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Invalid: []string{fmt.Sprintf("seal: bunq signs with RSA only, got %T", cfg.Seal.Key.Public())}}
	}
	der, err := x509.MarshalPKIXPublicKey(cfg.Seal.Key.Public())
	if err != nil {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Invalid: []string{"seal: " + err.Error()}}
	}
	c := &client{
		cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger,
		pubPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		api:    productionAPI, auth: productionAuth, token: productionToken,
	}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.api, c.auth, c.token = sandboxAPI, sandboxAuth, sandboxToken
	}
	if c.http == nil || isNilDoer(c.http) {
		c.http = &http.Client{Timeout: 30 * time.Second}
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

func (c *client) checkSession(s *obsdk.Session) error {
	switch {
	case s == nil:
		return fmt.Errorf("%w: nil session", obsdk.ErrInvalidRequest)
	case s.Integration != integrationID || s.Bank != bankKey:
		return fmt.Errorf("%w: session belongs to %s/%s", obsdk.ErrInvalidRequest, s.Bank, s.Integration)
	case s.Env != c.cfg.Env:
		return fmt.Errorf("%w: session is for %s, client for %s", obsdk.ErrInvalidRequest, s.Env, c.cfg.Env)
	case s.Meta[metaUserID] == "":
		return fmt.Errorf("%w: session has no bunq user id", obsdk.ErrInvalidRequest)
	}
	return nil
}
