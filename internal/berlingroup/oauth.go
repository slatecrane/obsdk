package berlingroup

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
)

// The OAuth SCA approach: instead of a scaRedirect link, the bank answers a
// redirect-preferred request with a scaOAuth link to its OAuth authorisation
// server metadata (RFC 8414). The user approves at the authorization_endpoint
// in an authorisation-code flow with PKCE, scoped to the resource
// (AIS:<consentId>, PIS:<paymentId>). For consents the code is exchanged for
// tokens, which every later account call carries as a bearer token and
// Refresh renews. For payments the bank's status decides; the code is not
// exchanged, as no later call needs the token.

const (
	// Config.NewID purposes.
	idPKCE  = "pkce"
	idState = "state"

	// metaTokenURL records the token endpoint in sessions, for Refresh.
	metaTokenURL = "token_url"

	opOAuthMeta = "oauth_metadata"
	opToken     = "token"
)

// linksOAuth are the names of the OAuth metadata link. scaOAuth is the
// standard's; Sparkassen's redirect handbook also calls it scaOAuth2.
var linksOAuth = []string{"scaOAuth", "scaOAuth2"}

func isOAuthLink(name string) bool {
	for _, n := range linksOAuth {
		if n == name {
			return true
		}
	}
	return false
}

// pkceChallenge is the S256 code challenge of a verifier (RFC 7636).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newVerifier derives a code verifier from two identifiers (random UUIDs by
// default; Config.NewID keeps it reproducible in replays). Hashing gives the
// 43 characters RFC 7636 asks for, whatever the identifiers look like.
func (c *client) newVerifier() string {
	sum := sha256.Sum256([]byte(c.cfg.ID(idPKCE) + c.cfg.ID(idPKCE)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// external calls a URL outside the XS2A API (the OAuth metadata and token
// endpoints), which the bank names in its responses.
// When auth is set it may change the form and headers (client
// authentication) before the request is sent.
func (c *client) external(ctx context.Context, op, method, rawURL string, form url.Values,
	auth func(url.Values, http.Header) error) (*resp, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("berlingroup: %s: unusable %s URL %q", c.bank(), op, rawURL)
	}
	if u.Scheme != "https" && c.cfg.Env == obsdk.Production {
		return nil, fmt.Errorf("berlingroup: %s: refusing a plain-HTTP %s URL in production", c.bank(), op)
	}
	h := http.Header{}
	if auth != nil {
		if err := auth(form, h); err != nil {
			return nil, err
		}
	}
	var body io.Reader = http.NoBody
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	hr, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	hr.Header = h
	if form != nil {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	hr.Header.Set("Accept", "application/json")
	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("berlingroup request failed", "bank", c.bank(), "op", op, "method", method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("berlingroup request", "bank", c.bank(), "op", op, "method", method, "url", u.Redacted(), "status", res.StatusCode)
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// startOAuth reads the authorisation server metadata behind the scaOAuth link
// and turns it into the redirect the user follows.
func (c *client) startOAuth(ctx context.Context, f *flow, metaURL string) error {
	if c.cfg.Credentials.ClientID == "" {
		return &obsdk.ConfigError{Bank: c.bank(), Env: c.cfg.Env, Missing: []string{"client_id"}}
	}
	res, err := c.external(ctx, opOAuthMeta, http.MethodGet, metaURL, nil, nil)
	if err != nil {
		return err
	}
	if res.status != http.StatusOK {
		return c.apiErr(opOAuthMeta, res)
	}
	var m struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(res.body, &m); err != nil || m.AuthorizationEndpoint == "" {
		return fmt.Errorf("berlingroup: %s: unreadable OAuth server metadata (HTTP %d)", c.bank(), res.status)
	}
	au, err := url.Parse(m.AuthorizationEndpoint)
	if err != nil || au.Host == "" {
		return fmt.Errorf("berlingroup: %s: unusable authorization_endpoint %q", c.bank(), m.AuthorizationEndpoint)
	}
	scope := "AIS:" + f.ConsentID
	if f.Op != flowConnect {
		scope = "PIS:" + f.Pay.ID
	}
	f.Verifier, f.OAuthState, f.TokenURL = c.newVerifier(), c.cfg.ID(idState), m.TokenEndpoint
	q := au.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.Credentials.ClientID)
	q.Set("scope", scope)
	q.Set("state", f.OAuthState)
	q.Set("code_challenge", pkceChallenge(f.Verifier))
	q.Set("code_challenge_method", "S256")
	if !c.p.OAuthNoRedirectURI {
		q.Set("redirect_uri", f.RedirectURL)
	}
	au.RawQuery = q.Encode()
	f.SCARedirect, f.OAuth = au.String(), true
	for _, n := range linksOAuth {
		delete(f.Links, n)
	}
	return nil
}

// afterOAuth handles the callback of an OAuth approval: the code is checked
// against the state, exchanged for tokens when a consent was approved, and
// the resource's status decides the rest.
func (c *client) afterOAuth(ctx context.Context, f *flow, cb string) (*obsdk.Step, error) {
	p, err := callback.Parse(cb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if code, desc, failed := p.Error(); failed {
		return nil, authFailed("%s was not approved at the bank (%s%s)", f.subject(), code, prefixed(": ", desc))
	}
	if st := p.Get("state"); st != f.OAuthState {
		return nil, authFailed("callback state does not match the authorisation that was started")
	}
	code := p.Get("code")
	if code == "" {
		return nil, fmt.Errorf("%w: callback has no authorisation code", obsdk.ErrInvalidRequest)
	}
	if f.Op == flowConnect {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {c.cfg.Credentials.ClientID},
			"code_verifier": {f.Verifier}}
		if !c.p.OAuthNoRedirectURI {
			form.Set("redirect_uri", f.RedirectURL)
		}
		tok, err := c.token(ctx, f.TokenURL, form)
		if err != nil {
			var ae *obsdk.APIError
			if asAPIError(err, &ae) && ae.Status < 500 {
				// invalid_grant: the code expired (10 minutes at Sparkassen) or the verifier does not match.
				return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, err)
			}
			return nil, err
		}
		f.token = tok
	}
	return c.afterRedirect(ctx, f)
}

// tokenResponse is an OAuth token response. Sparkassen send expires_in as a
// string, others as a number.
type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    flexInt   `json:"expires_in"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	issued       time.Time // set by token
}

type flexInt int64

func (n *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*n = flexInt(v)
	return nil
}

func (c *client) token(ctx context.Context, tokenURL string, form url.Values) (*tokenResponse, error) {
	if tokenURL == "" {
		return nil, fmt.Errorf("berlingroup: %s named no token endpoint in its OAuth metadata", c.bank())
	}
	var auth func(url.Values, http.Header) error
	if c.p.OAuthClientAuth != nil {
		auth = func(f url.Values, h http.Header) error { return c.p.OAuthClientAuth(c.cfg, tokenURL, f, h) }
	}
	res, err := c.external(ctx, opToken, http.MethodPost, tokenURL, form, auth)
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.apiErr(opToken, res)
	}
	var t tokenResponse
	if err := json.Unmarshal(res.body, &t); err != nil || t.AccessToken == "" {
		return nil, fmt.Errorf("berlingroup: %s: unreadable token response (HTTP %d)", c.bank(), res.status)
	}
	t.issued = c.now()
	return &t, nil
}

// applyToken stores a token response in a session. A refresh that returns no
// new refresh token keeps the current one.
func applyToken(s *obsdk.Session, t *tokenResponse, tokenURL string) {
	s.AccessToken = t.AccessToken
	if t.RefreshToken != "" {
		s.RefreshToken = t.RefreshToken
	}
	s.TokenType = firstNonEmpty(t.TokenType, s.TokenType)
	s.Scope = firstNonEmpty(t.Scope, s.Scope)
	s.AccessExpiresAt = nil
	if t.ExpiresIn > 0 {
		exp := t.issued.Add(time.Duration(t.ExpiresIn) * time.Second).UTC()
		s.AccessExpiresAt = &exp
	}
	if s.Meta == nil {
		s.Meta = map[string]string{}
	}
	if tokenURL != "" {
		s.Meta[metaTokenURL] = tokenURL
	}
}

// refreshToken renews a session's access token with its refresh token.
func (c *client) refreshToken(ctx context.Context, s *obsdk.Session) error {
	t, err := c.token(ctx, s.Meta[metaTokenURL], url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken},
		"client_id": {c.cfg.Credentials.ClientID}})
	if err != nil {
		var ae *obsdk.APIError
		if asAPIError(err, &ae) && ae.Status < 500 && ae.Status != http.StatusTooManyRequests {
			// invalid_grant: the refresh token expired or was revoked.
			return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: err}
		}
		return err
	}
	applyToken(s, t, "")
	return nil
}
