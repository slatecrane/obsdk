// Package ing implements ING's PSD2 APIs (one API for ING Belgium, Germany,
// Italy, Luxembourg, the Netherlands, Romania and Spain): OAuth2 redirect
// authorisation, accounts, balances and transactions, and payment initiation.
//
// Every call is mutual TLS: Config.HTTPClient must present the QWAC (see
// HTTPClient). Account information requests and payment creation carry an
// X-JWS-Signature made with Config.Seal, whose Certificate is required: ING
// identifies the signing key by the certificate's SHA-256 fingerprint.
//
// The sandbox works with ING's published example certificates and the
// pre-registered client id 5ca1ab1e-c0ca-c01a-cafe-154deadbea75; see
// docs/ing.md for what was verified against it.
package ing

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	integrationID = "ing-psd2-v4"
	bankKey       = "ing"

	sandboxAPI     = "https://api.sandbox.ing.com"
	sandboxAuth    = "https://myaccount.sandbox.ing.com/authorize/v2/"
	productionAPI  = "https://api.ing.com"
	productionAuth = "https://myaccount.ing.com/authorize/v2/"

	// SandboxClientID is the application ING pre-registered for its example certificates.
	SandboxClientID = "5ca1ab1e-c0ca-c01a-cafe-154deadbea75"

	// Extra parameters.
	paramBaseURL = "base_url" // override the API host (tests, proxies)
	paramAuthURL = "auth_url" // override the authorisation page base URL (country code is appended)
)

// HTTPClient returns an HTTP client that presents the QWAC (or, in the
// sandbox, ING's example TLS certificate). ING's servers use certificates
// from a public CA, so the system roots apply.
func HTTPClient(qwac tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{qwac}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

// countries served by the PSD2 API, with the segments ING opens to AISPs
// there. Italy has consumers only; Spain's business segment is sole traders.
var countries = []struct {
	c    obsdk.Country
	segs []obsdk.Segment
}{
	{"BE", []obsdk.Segment{obsdk.Personal, obsdk.Business}},
	{"DE", []obsdk.Segment{obsdk.Personal, obsdk.Business}},
	{"ES", []obsdk.Segment{obsdk.Personal, obsdk.Business}},
	{"IT", []obsdk.Segment{obsdk.Personal}},
	{"LU", []obsdk.Segment{obsdk.Personal, obsdk.Business}},
	{"NL", []obsdk.Segment{obsdk.Personal, obsdk.Business}},
	{"RO", []obsdk.Segment{obsdk.Personal, obsdk.Business}},
}

func init() {
	var variants []obsdk.Variant
	for _, cs := range countries {
		for _, seg := range cs.segs {
			sandbox := obsdk.Variant{Country: cs.c, Segment: seg, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental}
			if cs.c == "NL" && seg == obsdk.Personal {
				// Connect, accounts (incl. a card account), balances, transactions
				// (first page with a next link), refresh, revoke and a blocked
				// grant (scenarios live-nl-*).
				sandbox.Maturity, sandbox.VerifiedOn = obsdk.MaturitySandboxVerified, "2026-10-16"
			}
			variants = append(variants, sandbox,
				obsdk.Variant{Country: cs.c, Segment: seg, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
			)
		}
	}
	obsdk.Register(obsdk.Integration{
		ID: integrationID,
		Info: obsdk.Info{
			Bank:     bankKey,
			Name:     "ING",
			Group:    "ING",
			Spec:     "custom",
			Variants: variants,
			Capabilities: []obsdk.Capability{
				obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments,
			},
			Payments: paymentSpecs(),
			Auth:     obsdk.AuthInfo{Approaches: []string{"redirect"}},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "sandbox: " + SandboxClientID + " (ING's pre-registered app); production: the client_id ING returns when you onboard with your eIDAS certificates (POST /oauth2/applications)"},
				{Name: "redirect_url", Required: true, Note: "production: must be registered on the onboarded application"},
				{Name: "tls_client_cert", Required: true, Note: "QWAC for mTLS (sandbox: example_client_tls); build the client with ing.HTTPClient"},
				{Name: "seal", Secret: true, Required: true, Note: "QSealC key and Certificate for X-JWS-Signature (sandbox: example_client_signing); RSA (PS256) or EC (ES256)"},
			},
			Limits: obsdk.Limits{MaxConsentDays: 180, HistoryWithoutStepUpDays: 90},
			Docs: []string{
				"https://developer.ing.com/openbanking/products/b6d5093d-626e-41e9-b9e8-ff287bbe2c07/versions/3dd27fb2-23a4-489c-b285-aa9467dbf569/documentation",
				"https://developer.ing.com/openbanking/resources/get-started/psd2",
				"https://developer.ing.com/openbanking/resources/get-started/message-signatures",
			},
			Notes: []string{
				"Customer access tokens last 15 minutes; refresh tokens up to a year. A refresh may return no new refresh token: keep the old one.",
				"After authorisation all available history can be read once; later requests are limited to the last 90 days until the user authorises again (403).",
				"Belgian multi-currency accounts share one resourceId across currencies; Account.ID is unique per currency.",
				"Card accounts (IT, LU, RO) have a masked PAN instead of an IBAN and their own transaction format.",
				"INFO transactions (reservations whose final amount is unknown) are returned as pending.",
				"The sandbox is a stub: it only answers the exact requests in ING's test scenarios.",
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
	log    *slog.Logger

	mu       sync.Mutex
	appToken string
	appExp   time.Time
}

func newClient(cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"tls_client_cert (HTTPClient with the QWAC)"}}
	}
	if cfg.Seal == nil || cfg.Seal.Key == nil || cfg.Seal.Certificate == nil {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Missing: []string{"seal (key and certificate)"}}
	}
	if _, err := jwsAlg(cfg.Seal.Key); err != nil {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: cfg.Env, Invalid: []string{"seal: " + err.Error()}}
	}
	c := &client{cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, host: productionAPI, auth: productionAuth}
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
		c.auth = strings.TrimRight(u, "/") + "/"
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
