// Package swedbank implements Swedbank's PSD2 API (Sweden, Estonia, Latvia,
// Lithuania): redirect and decoupled login, consents, accounts, balances,
// transactions and the extended-history export.
//
// Everything here is written from Swedbank's published specifications. The
// Swedish sandbox decoupled flow has been run against the real sandbox; see
// docs/swedbank.md for what is verified and what is still assumed.
package swedbank

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "swedbank-psd2-v5"
	defaultHost   = "https://psd2.api.swedbank.com"

	// Extra parameters.
	paramBaseURL    = "base_url"    // override the API host (tests, proxies)
	paramScopeExtra = "scope_extra" // extra OAuth scopes appended to PSD2/PSD2sandbox
)

var countries = map[obsdk.Country]struct{ prod, sandbox string }{
	"SE": {"SWEDSESS", "SANDSESS"},
	"EE": {"HABAEE2X", "SANDEE2X"},
	"LV": {"HABALV22", "SANDLV22"},
	"LT": {"HABALT22", "SANDLT22"},
}

func isBaltic(c obsdk.Country) bool { return c != "SE" }

func init() {
	var variants []obsdk.Variant
	for _, c := range []obsdk.Country{"SE", "EE", "LV", "LT"} {
		sandbox := obsdk.Variant{Country: c, Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
		if c == "SE" {
			// Decoupled and redirect connect, accounts, balances, transactions and
			// extended history (scenarios live-se-*).
			sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, "2026-10-14"
		}
		variants = append(variants, sandbox,
			obsdk.Variant{Country: c, Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		)
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     "swedbank",
			Name:     "Swedbank",
			Group:    "Swedbank",
			Spec:     "custom",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapTransactionsHistory,
			},
			Auth: obsdk.AuthInfo{Approaches: []string{"redirect", "decoupled"}, Dynamic: true},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "API key from the Swedbank developer portal (also sent as app-id/apiKey)"},
				{Name: "client_secret", Secret: true, Required: true},
				{Name: "redirect_url", Required: true, Note: "must be registered in the developer portal"},
			},
			Limits: obsdk.Limits{
				MaxConsentDays:           180,
				MaxRequestsPerDay:        4,
				MaxParallel:              5,
				HistoryWithoutStepUpDays: 90,
				RequiresPSUHeaders:       []string{"ip", "user_agent"},
			},
			Docs: []string{"https://online.swedbank.se/ConditionsEarchive/download?bankid=1111&id=WEBDOC-PRODE24296774"},
			Notes: []string{
				"One consent per type is valid at a time; creating a new one invalidates the previous.",
				"Only one access token is valid per user, bank and app: a new login invalidates the old token.",
				"Pagination links are short-lived (about 5 minutes) and single-use in Sweden.",
				"Transactions older than 90 days need an extra user approval (handled as a Step).",
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
	bic    string
	log    *slog.Logger
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	b, ok := countries[t.Country]
	if !ok {
		return nil, fmt.Errorf("%w: swedbank in %s", obsdk.ErrUnsupportedTarget, t.Country)
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, host: defaultHost}
	if t.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if c.http == nil || isNilDoer(c.http) {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if h := cfg.Param(paramBaseURL); h != "" {
		c.host = strings.TrimRight(h, "/")
	}
	if cfg.Env == obsdk.Sandbox {
		c.bic = b.sandbox
	} else {
		c.bic = b.prod
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
	i, _ := obsdk.Lookup("swedbank")
	var vs []obsdk.Variant
	for _, v := range i.Variants {
		if v.Country == c.target.Country && v.Env == c.cfg.Env {
			vs = append(vs, v)
		}
	}
	i.Variants = vs
	return i
}

func (c *client) now() time.Time { return c.cfg.Clock() }

// aisBase is the path prefix of consent and account APIs.
func (c *client) aisBase() string {
	if c.cfg.Env == obsdk.Sandbox {
		return "/sandbox/v5"
	}
	return "/psd2/v5" // unverified: taken from the "^/psd2/v5/" link pattern in the authorize-decoupled spec
}

func (c *client) scope() string {
	s := "PSD2"
	if c.cfg.Env == obsdk.Sandbox {
		s = "PSD2sandbox"
	}
	if extra := strings.TrimSpace(c.cfg.Param(paramScopeExtra)); extra != "" {
		s += " " + extra
	}
	return s
}
