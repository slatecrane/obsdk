// Package handelsbanken implements Handelsbanken's PSD2 APIs for personal and
// business customers in Sweden, Great Britain, the Netherlands and
// Luxembourg: consent with redirect or (Sweden) Mobile BankID decoupled
// authorisation, accounts with balances, transactions, and payment initiation.
//
// Calls carry the app's client id (X-IBM-Client-Id) and an OAuth token: a
// client credentials token to create consents and payments, then the user's
// token from the authorisation. Production adds the QWAC (mutual TLS, via
// Config.HTTPClient); the sandbox needs no certificate and no login: the
// sandbox user is named in a header (Config.Extra "sandbox_user").
//
// See docs/handelsbanken.md for what was verified against the sandbox.
package handelsbanken

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "handelsbanken-psd2-v1"
	bankKey       = "handelsbanken"

	sandboxAPI      = "https://sandbox.handelsbanken.com/openbanking"
	productionAPI   = "https://api.handelsbanken.com/openbanking"
	sandboxToken    = sandboxAPI + "/oauth2/token/1.0"
	productionToken = "https://api.handelsbanken.com/mlurd/oauth2/token/1.0"

	paramBaseURL     = "base_url"     // override the API base (tests, proxies); the token URL follows it
	paramSandboxUser = "sandbox_user" // X-Sandbox-User, e.g. SANDBOX-INDIVIDUAL-SE-1
)

// segments per country: Luxembourg serves personal customers only.
var segments = map[obsdk.Country][]obsdk.Segment{
	"SE": {obsdk.Personal, obsdk.Business},
	"GB": {obsdk.Personal, obsdk.Business},
	"NL": {obsdk.Personal, obsdk.Business},
	"LU": {obsdk.Personal},
}

func init() {
	var variants []obsdk.Variant
	for _, c := range []obsdk.Country{"SE", "GB", "NL", "LU"} {
		for _, seg := range segments[c] {
			// Every sandbox variant ran connect, accounts, balances and
			// transactions (scenarios live-<country>-<segment>, plus
			// live-se-personal-decoupled); payments: live-*-pay-*.
			variants = append(variants,
				obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturitySandboxVerified, VerifiedOn: "2026-10-17"},
				obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			)
		}
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:         bankKey,
			Name:         "Handelsbanken",
			Group:        "Handelsbanken",
			Spec:         "custom",
			Variants:     variants,
			Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
			Payments:     paymentSpecs(),
			Auth:         obsdk.AuthInfo{Approaches: []string{"redirect", "decoupled"}, Methods: []string{"mobile_bankid"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "from the app on developer.handelsbanken.com (sandbox: 32 hex digits; production: a UUID)"},
				{Name: "redirect_url", Required: false, Note: "the app's one registered redirect URI; needed for the redirect method"},
				{Name: "tls_client_cert", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "QWAC (or UK OBWAC) as an mTLS client certificate"},
				{Name: paramSandboxUser, Required: false, Envs: []obsdk.Env{obsdk.Sandbox}, Note: "sandbox user from Handelsbanken's test data, e.g. SANDBOX-INDIVIDUAL-SE-1; stands in for the login"},
			},
			Limits: obsdk.Limits{MaxConsentDays: 180},
			Docs: []string{
				"https://developer.handelsbanken.com/api/psd2/guidelines",
				"https://developer.handelsbanken.com/api/sandbox/geninfo",
			},
			Notes: []string{
				"Decoupled (Mobile BankID) is offered in Sweden only; the redirect works everywhere.",
				"Business consents need the company id (PSU-Corporate-ID): SE organisation number, NL 6-digit corporate number; GB sends UNKNOWN.",
				"Transactions are not paged: the bank caps a request (SE personal: 1000 items or 24 months) and asks to narrow the dates.",
				"Consents last 180 days (GB: 90) and cannot be revoked through the API; Disconnect only drops the tokens.",
				"Refresh tokens do not rotate; payment approvals give no refresh token.",
				"The sandbox has no login: the user is named in the X-Sandbox-User header (Config.Extra sandbox_user), and BankID always succeeds.",
			},
		},
		Factory: newClient,
	})
}

type client struct {
	cfg      obsdk.Config
	target   obsdk.Target
	http     obsdk.HTTPDoer
	api      string // base URL, ".../openbanking"
	tokenURL string
	log      *slog.Logger
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	c := &client{cfg: cfg, target: t, http: noRedirects(cfg.HTTPClient), log: cfg.Logger, api: productionAPI, tokenURL: productionToken}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.api, c.tokenURL = sandboxAPI, sandboxToken
	}
	if h := cfg.Param(paramBaseURL); h != "" {
		c.api = strings.TrimRight(h, "/")
		c.tokenURL = c.api + "/oauth2/token/1.0"
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return c, nil
}

// noRedirects returns a client that hands 302s back instead of following
// them: the sandbox's authorize call answers with a redirect to the callback.
func noRedirects(d obsdk.HTTPDoer) obsdk.HTTPDoer {
	hc, ok := d.(*http.Client)
	if d != nil && !ok {
		return d // a custom doer (tests, replays) returns responses as they are
	}
	c := &http.Client{Timeout: 30 * time.Second}
	if hc != nil {
		cp := *hc
		c = &cp
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
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

func (c *client) business() bool { return c.target.Segment == obsdk.Business }

// aisBase is where a country's consents and accounts live. Sweden uses the
// general API (country in a header); GB, NL and LU have their own.
func (c *client) aisBase() string {
	switch c.target.Country {
	case "GB":
		return "/psd2/gb/v1"
	case "NL":
		return "/psd2/nl/v1"
	case "LU":
		return "/psd2/lu/individual/v1"
	}
	return "/psd2/v1"
}

func (c *client) consentsPath() string {
	if c.target.Country == "LU" {
		return c.aisBase() + "/accounts/consents"
	}
	return c.aisBase() + "/consents"
}

// accountsPath: the general API serves accounts on v2, consents on v1.
func (c *client) accountsPath() string {
	if c.target.Country == "SE" {
		return "/psd2/v2/accounts"
	}
	return c.aisBase() + "/accounts"
}

// countryHeader: only the general API wants the Country header.
func (c *client) countryHeader() string {
	if c.target.Country == "SE" {
		return "SE"
	}
	return ""
}

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
