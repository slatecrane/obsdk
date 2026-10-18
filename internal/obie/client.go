package obie

import (
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	paramBaseURL = "base_url" // override Profile.APIHost (tests, proxies)
	paramAuthURL = "auth_url" // override Profile.AuthURL
)

type client struct {
	p      *Profile
	cfg    obsdk.Config
	target obsdk.Target
	http   obsdk.HTTPDoer
	host   string // API host: token endpoint and resources
	auth   string // authorisation endpoint
	log    *slog.Logger
}

func newClient(p *Profile, cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	if cfg.HTTPClient == nil || isNilDoer(cfg.HTTPClient) {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"tls_client_cert (HTTPClient with the transport certificate)"}}
	}
	if cfg.Seal == nil || cfg.Seal.Key == nil {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"seal (request object signing key)"}}
	}
	if _, ok := cfg.Seal.Key.Public().(*rsa.PublicKey); !ok {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Invalid: []string{"seal: an RSA key is needed (PS256)"}}
	}
	if t.Segment == "" {
		t.Segment = obsdk.Personal
	}
	c := &client{p: p, cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger,
		host: strings.TrimRight(p.APIHost(cfg.Env, t), "/"), auth: p.AuthURL(cfg.Env, t)}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if h := cfg.Param(paramBaseURL); h != "" {
		c.host = strings.TrimRight(h, "/")
	}
	if u := cfg.Param(paramAuthURL); u != "" {
		c.auth = u
	}
	var missing []string
	for _, k := range p.RequiredParams {
		if cfg.Param(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: missing}
	}
	if c.kid() == "" {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"seal.KeyID (or seal.Certificate)"}}
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

// hostName is the API host without scheme.
func (c *client) hostName() string {
	if u, err := url.Parse(c.host); err == nil && u.Host != "" {
		return u.Host
	}
	return c.host
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
