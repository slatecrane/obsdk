// Package nordea implements Nordea's PSD2 APIs for personal and business
// customers in Denmark, Finland, Norway and Sweden: redirect authorisation,
// accounts (with balances) and transactions, and Single SCA payment
// initiation for personal customers.
//
// Requests are authenticated with the app's client id and secret
// (X-IBM-Client-Id / X-IBM-Client-Secret) and signed with Config.Seal: an
// HTTP Signature (draft-cavage, rsa-sha256) whose keyId is the client id. No
// mutual TLS is involved. In the sandbox the signing key is the static
// QSealC Nordea publishes on its developer portal.
//
// See docs/nordea.md for what was verified against the sandbox.
package nordea

import (
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "nordea-psd2-v5"
	bankKey       = "nordea"

	sandboxAPI    = "https://api.nordeaopenbanking.com"
	productionAPI = "https://open.nordea.com"

	paramBaseURL = "base_url" // override the API host (tests, proxies)
)

var countries = []obsdk.Country{"DK", "FI", "NO", "SE"}

func init() {
	var variants []obsdk.Variant
	for _, c := range countries {
		for _, seg := range []obsdk.Segment{obsdk.Personal, obsdk.Business} {
			sandbox := obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
			if c == "FI" {
				// Personal: connect, accounts, balances, transactions with paging,
				// refresh, revoke. Business: connect, balances, transactions.
				// Scenarios live-fi-*.
				sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, "2026-10-16"
			}
			variants = append(variants, sandbox,
				obsdk.Variant{Country: c, Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			)
		}
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:         bankKey,
			Name:         "Nordea",
			Group:        "Nordea",
			Spec:         "custom",
			Variants:     variants,
			Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
			Payments:     paymentSpecs(),
			Auth:         obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "from the app on developer.nordeaopenbanking.com (also the signature's keyId)"},
				{Name: "client_secret", Secret: true, Required: true, Note: "from the same app"},
				{Name: "redirect_url", Required: true, Note: "registered on the app"},
				{Name: "seal", Secret: true, Required: true, Note: "RSA QSealC key (at least 2048 bits); sandbox: the static key from Nordea's portal (QSealC-NordeaDevPortal .p12, password 1111)"},
			},
			Limits: obsdk.Limits{MaxConsentDays: 180, HistoryWithoutStepUpDays: 90},
			Docs: []string{
				"https://documentation.nordeaopenbanking.com/compliance/personal/overview",
				"https://documentation.nordeaopenbanking.com/compliance/personal/authorization/authorization-v5",
				"https://documentation.nordeaopenbanking.com/compliance/personal/accounts/accounts-v5",
				"https://documentation.nordeaopenbanking.com/compliance/business/accounts/business-ais-v4",
			},
			Notes: []string{
				"Balances come with the account (available, booked and value-dated); Balances reads the account details.",
				"Access tokens last an hour; refresh tokens are one-time use and rotate on every refresh.",
				"Without dates, transactions cover the last two months. Beyond 90 days the user must authorise again.",
				"The sandbox needs no login: POST /authorize redirects straight back with a code.",
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
	log    *slog.Logger
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.Seal == nil || cfg.Seal.Key == nil {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"seal"}}
	}
	if _, ok := cfg.Seal.Key.Public().(*rsa.PublicKey); !ok {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Invalid: []string{"seal: Nordea only accepts RSA keys (rsa-sha256)"}}
	}
	c := &client{cfg: cfg, target: t, http: noRedirects(cfg.HTTPClient), log: cfg.Logger, host: productionAPI}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if cfg.Env == obsdk.Sandbox {
		c.host = sandboxAPI
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if h := cfg.Param(paramBaseURL); h != "" {
		c.host = strings.TrimRight(h, "/")
	}
	return c, nil
}

// noRedirects returns a client that hands 302s back instead of following
// them: POST /authorize answers with a redirect the user's browser must take.
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

// segment is the path prefix: "personal" or "business".
func (c *client) segment() string { return string(c.target.Segment) }

// aisVersion: personal accounts are on v5, business accounts on v4.
func (c *client) aisVersion() string {
	if c.target.Segment == obsdk.Business {
		return "v4"
	}
	return "v5"
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
