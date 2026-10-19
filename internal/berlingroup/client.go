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

// metaInstitution records the institution (Profile.Institution) in sessions.
const metaInstitution = "institution"

type client struct {
	p      *Profile
	cfg    obsdk.Config
	target obsdk.Target
	http   obsdk.HTTPDoer
	base   string // API root; paths start with /v1. Empty until an institution is known (see at)
	inst   string // the institution base points at
	bearer string // access token of the OAuth pre-step (Profile.PreStep), sent on every request
	log    *slog.Logger
}

// withBearer returns the client sending an access token on every request.
func (c *client) withBearer(token string) *client {
	cc := *c
	cc.bearer = token
	return &cc
}

func newClient(p *Profile, cfg obsdk.Config, t obsdk.Target) (obsdk.Client, error) {
	c := &client{p: p, cfg: cfg, target: t, http: cfg.HTTPClient, log: cfg.Logger}
	if c.target.Segment == "" {
		c.target.Segment = obsdk.Personal
	}
	if c.http == nil || isNilDoer(c.http) {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if p.Signing != nil && p.Signing.Required && cfg.Seal == nil {
		return nil, &obsdk.ConfigError{Bank: t.Bank, Env: cfg.Env, Missing: []string{"seal"}}
	}
	inst, err := c.configInstitution()
	if err != nil {
		return nil, err
	}
	if p.Institution == nil || inst != "" || cfg.Param(paramBaseURL) != "" {
		if c, err = c.at(inst); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// configInstitution reads and checks the institution from Config.Extra.
func (c *client) configInstitution() (string, error) {
	in := c.p.Institution
	if in == nil {
		return "", nil
	}
	v := strings.TrimSpace(c.cfg.Param(in.Param))
	if v == "" || in.Normalize == nil {
		return v, nil
	}
	n, err := in.Normalize(v)
	if err != nil {
		return "", &obsdk.ConfigError{Bank: c.target.Bank, Env: c.cfg.Env, Invalid: []string{fmt.Sprintf("%s: %v", in.Param, err)}}
	}
	return n, nil
}

// at returns the client pointed at an institution's API root. Banks without
// Profile.Institution have one root, and inst is empty.
func (c *client) at(inst string) (*client, error) {
	if c.base != "" && inst == c.inst {
		return c, nil
	}
	cc := *c
	cc.inst = inst
	cc.base = strings.TrimRight(firstNonEmpty(c.cfg.Param(paramBaseURL), c.p.BaseURL(c.cfg.Env, c.target, inst)), "/")
	if cc.base == "" {
		return nil, &obsdk.ConfigError{Bank: c.target.Bank, Env: c.cfg.Env, Missing: []string{paramBaseURL}}
	}
	return &cc, nil
}

// forNew is the client for creating a consent or payment: the configured
// institution is required for hubs.
func (c *client) forNew() (*client, error) {
	inst, err := c.configInstitution()
	if err != nil {
		return nil, err
	}
	if c.p.Institution != nil && inst == "" {
		in := c.p.Institution
		return nil, &obsdk.ConfigError{Bank: c.target.Bank, Env: c.cfg.Env,
			Missing: []string{fmt.Sprintf("%s (%s)", in.Param, firstNonEmpty(in.Label, "the bank to connect to"))}}
	}
	return c.at(inst)
}

// forInstitution is the client for something created earlier at inst (from
// a session, flow state or payment reference). A configured institution
// that differs is a mistake worth reporting rather than calling the wrong bank.
func (c *client) forInstitution(inst string) (*client, error) {
	if c.p.Institution == nil {
		return c, nil
	}
	conf, err := c.configInstitution()
	if err != nil {
		return nil, err
	}
	if inst == "" {
		inst = conf
	}
	if conf != "" && conf != inst {
		return nil, fmt.Errorf("%w: this was created at %s %s, but the client is configured for %s", obsdk.ErrInvalidRequest,
			c.p.Institution.Param, inst, conf)
	}
	if inst == "" {
		return c.forNew()
	}
	return c.at(inst)
}

// forSession is the client for a session's calls.
func (c *client) forSession(s *obsdk.Session) (*client, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	return c.forInstitution(s.Meta[metaInstitution])
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
