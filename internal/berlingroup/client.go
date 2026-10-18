package berlingroup

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// paramBaseURL overrides Profile.BaseURL (tests, proxies, local sandboxes).
const paramBaseURL = "base_url"

type client struct {
	p      *Profile
	cfg    obsdk.Config
	target obsdk.Target
	http   obsdk.HTTPDoer
	base   string // API root; paths start with /v1
	log    *slog.Logger
}

func newClient(p *Profile, cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	c := &client{p: p, cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger, base: p.BaseURL(cfg.Env, t)}
	if c.target.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if c.http == nil || isNilDoer(c.http) {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if u := cfg.Param(paramBaseURL); u != "" {
		c.base = u
	}
	c.base = strings.TrimRight(c.base, "/")
	if c.base == "" {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{paramBaseURL}}
	}
	if p.Signing != nil && p.Signing.Required && cfg.Seal == nil {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"seal"}}
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

func (c *client) bank() string { return c.p.Info.Bank }

// Info returns the discovery record narrowed to this client's variant.
func (c *client) Info() obsdk.Info {
	i := c.p.Info
	i.Spec = "berlin-group"
	if len(i.Auth.Approaches) == 0 {
		i.Auth.Approaches = c.p.approaches()
	}
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
	case s.Integration != c.p.ID || s.Bank != c.bank():
		return fmt.Errorf("%w: session belongs to %s/%s", obsdk.ErrInvalidRequest, s.Bank, s.Integration)
	case s.Env != c.cfg.Env:
		return fmt.Errorf("%w: session is for %s, client for %s", obsdk.ErrInvalidRequest, s.Env, c.cfg.Env)
	}
	return nil
}

func (c *client) redirectURL(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if u := c.cfg.Credentials.RedirectURL; u != "" {
		return u, nil
	}
	return "", fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or the request's RedirectURL)", obsdk.ErrInvalidConfig)
}

// approach resolves the requested SCA approach against the profile.
func (c *client) approach(method string) (string, error) {
	if method == "" {
		return c.p.approaches()[0], nil
	}
	m := strings.ToLower(method)
	if !c.p.supports(m) {
		return "", fmt.Errorf("%w: %s supports %s, not %q", obsdk.ErrInvalidRequest, c.p.Info.Name, strings.Join(c.p.approaches(), ", "), method)
	}
	return m, nil
}
