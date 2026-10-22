package berlingroup

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
)

// OAuthServer describes a bank that puts OAuth2 around every XS2A resource
// (LUXHUB): consents and payments are created and read with a
// client-credentials token, and the user approves them in an
// authorisation-code flow with PKCE, scoped to the resource (AIS:<consentId>,
// PIS:<paymentId>), at a fixed authorisation endpoint. Approving a consent
// gives the tokens the account calls carry; Refresh renews them.
//
// The approval runs as in the OAuth SCA approach. A scaRedirect or scaOAuth
// link the bank returns still wins; the fixed endpoints are used when a
// redirect-approach flow has no such link and no authorisation left to start.
type OAuthServer struct {
	// Authorize and Token return the authorisation and token endpoints for
	// a target and institution. Config.Extra "oauth_authorize_url" and
	// "oauth_token_url" override them.
	Authorize, Token func(env obsdk.Env, t obsdk.Target, institution string) string

	// ClientCredentials sends a client-credentials token on every request
	// that carries no user token: one is asked for per request, with scope
	// AISScope on consent and account paths and PISScope on the others.
	ClientCredentials bool

	// AISScope and PISScope are the client-credentials scopes. Empty means
	// "AIS" and "PIS".
	AISScope, PISScope string

	// ExchangeScope repeats the authorisation's scope in the code exchange.
	ExchangeScope bool
}

// Config.Extra keys overriding OAuthServer's endpoints (tests, proxies).
const (
	paramAuthorizeURL = "oauth_authorize_url"
	paramTokenURL     = "oauth_token_url"
)

// aisScopePrefixes are the canonical paths a client-credentials token gets the AIS
// scope for.
var aisScopePrefixes = []string{"/v1/consents", "/v1/accounts", "/v1/card-accounts"}

func (c *client) oauthServerURL(param string, endpoint func(obsdk.Env, obsdk.Target, string) string) string {
	if v := c.cfg.Param(param); v != "" {
		return v
	}
	if endpoint == nil {
		return ""
	}
	return endpoint(c.cfg.Env, c.target, c.inst)
}

// clientToken asks for a client-credentials token for a request path.
func (c *client) clientToken(ctx context.Context, path string) (string, error) {
	o := c.p.OAuth
	if c.oauthClientID() == "" {
		return "", &obsdk.ConfigError{Bank: c.bank(), Env: c.cfg.Env, Missing: []string{"client_id"}}
	}
	scope := firstNonEmpty(o.PISScope, "PIS")
	for _, pre := range aisScopePrefixes {
		if strings.HasPrefix(path, pre) {
			scope = firstNonEmpty(o.AISScope, "AIS")
			break
		}
	}
	tok, err := c.token(ctx, c.oauthServerURL(paramTokenURL, o.Token), url.Values{
		"grant_type": {"client_credentials"}, "scope": {scope}, "client_id": {c.oauthClientID()}})
	if err != nil {
		return "", fmt.Errorf("berlingroup: %s: client token: %w", c.bank(), err)
	}
	return tok.AccessToken, nil
}

// wantsFixedOAuth reports whether a flow's approval should start at the
// fixed authorisation endpoint now: a redirect flow without a redirect link
// and with no authorisation left to start.
func (c *client) wantsFixedOAuth(f *flow) bool {
	if c.p.OAuth == nil || c.p.OAuth.Authorize == nil || f.Approach != Redirect || f.SCARedirect != "" || f.OAuth {
		return false
	}
	n, _ := f.link(linksStart...)
	return n == ""
}

// startFixedOAuth sends the user to the fixed authorisation endpoint.
func (c *client) startFixedOAuth(f *flow) error {
	if c.oauthClientID() == "" {
		return &obsdk.ConfigError{Bank: c.bank(), Env: c.cfg.Env, Missing: []string{"client_id"}}
	}
	o := c.p.OAuth
	return c.beginOAuth(f, c.oauthServerURL(paramAuthorizeURL, o.Authorize), c.oauthServerURL(paramTokenURL, o.Token))
}
