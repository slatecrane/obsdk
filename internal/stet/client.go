package stet

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	paramBaseURL  = "base_url"  // override Profile.APIBase (tests, proxies)
	paramAuthURL  = "auth_url"  // override Profile.AuthURL
	paramTokenURL = "token_url" // override Profile.TokenURL

	// ParamInitiatingParty is the Config.Extra key with the PISP's name,
	// sent as the payment request's initiatingParty (mandatory in STET).
	ParamInitiatingParty = "initiating_party"
)

type client struct {
	p      *Profile
	cfg    obsdk.Config
	target obsdk.Target
	http   obsdk.HTTPDoer
	base   string // API root with base path, no trailing slash
	auth   string // authorization endpoint
	token  string // token endpoint
	log    *slog.Logger
}

func newClient(p *Profile, cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if t.Segment == "" {
		t.Segment = obsdk.Personal
	}
	c := &client{p: p, cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger,
		base:  strings.TrimRight(firstNonEmpty(cfg.Param(paramBaseURL), p.APIBase(cfg.Env, t)), "/"),
		auth:  firstNonEmpty(cfg.Param(paramAuthURL), p.AuthURL(cfg.Env, t)),
		token: firstNonEmpty(cfg.Param(paramTokenURL), p.TokenURL(cfg.Env, t))}
	if c.http == nil || isNilDoer(c.http) {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	var missing, invalid []string
	if cfg.Credentials.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if p.clientAuth() != TLSClientAuth && cfg.Credentials.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	for _, k := range p.RequiredParams {
		if cfg.Param(k) == "" {
			missing = append(missing, k)
		}
	}
	if s := p.Signing; s != nil {
		if s.Required && (cfg.Seal == nil || cfg.Seal.Key == nil) {
			missing = append(missing, "seal (QSealC key for the request signature)")
		} else if err := s.check(cfg.Seal); err != nil {
			invalid = append(invalid, err.Error())
		}
	}
	for name, u := range map[string]string{"base_url": c.base, "auth_url": c.auth, "token_url": c.token} {
		if pu, err := url.Parse(u); err != nil || pu.Scheme == "" || pu.Host == "" {
			invalid = append(invalid, name+": not an absolute URL")
		}
	}
	if len(missing) > 0 || len(invalid) > 0 {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: missing, Invalid: invalid}
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
	// The profile's own record: a bank key can have one profile per country.
	i := c.p.Info
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

// origin is the API's scheme and host.
func (c *client) origin() string {
	u, err := url.Parse(c.base)
	if err != nil {
		return c.base
	}
	return u.Scheme + "://" + u.Host
}

func (c *client) checkSession(s *obsdk.Session) error {
	switch {
	case s == nil:
		return fmt.Errorf("%w: nil session", obsdk.ErrInvalidRequest)
	case s.Integration != c.p.ID || s.Bank != c.target.Bank:
		return fmt.Errorf("%w: session belongs to %s/%s", obsdk.ErrInvalidRequest, s.Bank, s.Integration)
	case s.Env != c.cfg.Env:
		return fmt.Errorf("%w: session is for %s, client for %s", obsdk.ErrInvalidRequest, s.Env, c.cfg.Env)
	case s.Country != c.target.Country:
		return fmt.Errorf("%w: session is for %s, client for %s", obsdk.ErrInvalidRequest, s.Country, c.target.Country)
	}
	return nil
}

func psuOrNil(p obsdk.PSUContext) *obsdk.PSUContext {
	if p == (obsdk.PSUContext{}) {
		return nil
	}
	return &p
}
