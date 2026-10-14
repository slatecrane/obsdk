package swedbank

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	ExpiresIn    float64 `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	Scope        string  `json:"scope"`
	TokenType    string  `json:"token_type"`
}

// expiry reads expires_in as a duration in seconds. The spec calls it "Unix
// time" but its example is 3600; a value that big can only be an absolute time.
func expiry(now time.Time, v float64) *time.Time {
	if v <= 0 {
		return nil
	}
	var t time.Time
	if v > 1e9 {
		t = time.Unix(int64(v), 0).UTC()
	} else {
		t = now.Add(time.Duration(v * float64(time.Second))).UTC()
	}
	return &t
}

func (c *client) tokenCall(ctx context.Context, q url.Values) (*tokenResponse, *resp, error) {
	q.Set("client_id", c.cfg.Credentials.ClientID)
	q.Set("client_secret", c.cfg.Credentials.ClientSecret.Reveal())
	r, err := c.do(ctx, req{op: opToken, method: http.MethodPost, path: "/psd2/token", query: q})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("swedbank: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// applyToken merges a token response into a session. A refresh token is
// replaced only when the bank sent one, which covers both rotating and
// non-rotating banks.
func (c *client) applyToken(s *obsdk.Session, tr *tokenResponse, r *resp) {
	now := c.now()
	s.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		s.RefreshToken = tr.RefreshToken
	}
	if tr.TokenType != "" {
		s.TokenType = tr.TokenType
	}
	if tr.Scope != "" {
		s.Scope = tr.Scope
	}
	s.AccessExpiresAt = expiry(now, tr.ExpiresIn)
	if m := r.header.Get("login-method"); m != "" {
		if s.Meta == nil {
			s.Meta = map[string]string{}
		}
		s.Meta["login_method"] = m
	}
	s.Touch(now)
}

func (c *client) newSession() *obsdk.Session {
	return &obsdk.Session{
		Bank: "swedbank", Country: c.target.Country, Segment: c.target.Segment,
		Env: c.cfg.Env, Integration: integrationID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{},
	}
}

// exchangeCode trades an authorization code for tokens.
func (c *client) exchangeCode(ctx context.Context, code, redirectURI string) (*obsdk.Session, error) {
	q := url.Values{"grant_type": {"authorization_code"}, "code": {code}}
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	tr, r, err := c.tokenCall(ctx, q)
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	s := c.newSession()
	c.applyToken(s, tr, r)
	return s, nil
}

// Refresh renews the access token.
func (c *client) Refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.RefreshToken == "" {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "no_refresh_token"}}
	}
	tr, r, err := c.tokenCall(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}})
	if err != nil {
		return nil, &obsdk.RefreshError{Temporary: true, Err: err}
	}
	if tr == nil {
		e := c.apiErr(opToken, r)
		if r.status == http.StatusTooManyRequests || r.status >= 500 {
			return nil, &obsdk.RefreshError{Temporary: true, Err: e}
		}
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "refresh_rejected", Err: e}}
	}
	ns := s.Clone()
	c.applyToken(ns, tr, r)
	return ns, nil
}

func (c *client) checkSession(s *obsdk.Session) error {
	switch {
	case s == nil:
		return fmt.Errorf("%w: nil session", obsdk.ErrInvalidRequest)
	case s.Integration != integrationID || s.Bank != "swedbank":
		return fmt.Errorf("%w: session belongs to %s/%s", obsdk.ErrInvalidRequest, s.Bank, s.Integration)
	case s.Country != c.target.Country || s.Env != c.cfg.Env:
		return fmt.Errorf("%w: session is for %s/%s, client for %s/%s", obsdk.ErrInvalidRequest, s.Country, s.Env, c.target.Country, c.cfg.Env)
	}
	return nil
}
