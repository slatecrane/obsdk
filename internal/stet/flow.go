package stet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// consentKind is the session's only consent: the user's authorization of the
// AISP, which in STET is the access token itself.
const consentKind = "aisp"

const (
	phConnect = "connect_redirect_wait"
	phPayment = "payment_redirect_wait"
)

// flow is the serialized state of a Connect or a payment.
type flow struct {
	Phase       string             `json:"phase"`
	PSU         obsdk.PSUContext   `json:"psu"`
	RedirectURL string             `json:"redirect_url"`
	OAuthState  string             `json:"oauth_state"`
	Verifier    string             `json:"verifier,omitempty"` // PKCE code verifier
	AuthURL     string             `json:"auth_url"`
	Caps        []obsdk.Capability `json:"caps,omitempty"`
	Pay         *payFlow           `json:"pay,omitempty"` // payments only
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// ---- tokens ----

type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    float64 `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	Scope        string  `json:"scope"`
}

// UnmarshalJSON accepts expires_in as a number or a string ("3600").
func (t *tokenResponse) UnmarshalJSON(b []byte) error {
	type plain tokenResponse
	var aux struct {
		plain
		ExpiresIn json.Number `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*t = tokenResponse(aux.plain)
	if aux.ExpiresIn != "" {
		t.ExpiresIn, _ = aux.ExpiresIn.Float64()
	}
	return nil
}

// withClientAuth adds the client's credentials to a token-endpoint request.
func (c *client) withClientAuth(r req) req {
	cred := c.cfg.Credentials
	switch c.p.clientAuth() {
	case ClientSecretBasic:
		r.basic = [2]string{cred.ClientID, cred.ClientSecret.Reveal()}
	case ClientSecretPost:
		r.form.Set("client_id", cred.ClientID)
		r.form.Set("client_secret", cred.ClientSecret.Reveal())
	default:
		r.form.Set("client_id", cred.ClientID)
	}
	return r
}

// tokenCall calls the token endpoint. A nil token with a nil error means the
// endpoint refused; the response explains why.
func (c *client) tokenCall(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	r, err := c.do(ctx, c.withClientAuth(req{op: op, method: http.MethodPost, path: c.token, form: form}))
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("stet: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// clientToken gets a client-credentials token for the PISP scope.
func (c *client) clientToken(ctx context.Context) (string, error) {
	tr, r, err := c.tokenCall(ctx, opToken, url.Values{"grant_type": {"client_credentials"}, "scope": {c.p.scopePIS()}})
	if err != nil {
		return "", err
	}
	if tr == nil {
		return "", c.apiErr(opToken, r)
	}
	return tr.AccessToken, nil
}

func (c *client) applyToken(s *obsdk.Session, tr *tokenResponse) {
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
	s.AccessExpiresAt = nil
	if tr.ExpiresIn > 0 {
		t := now.Add(time.Duration(tr.ExpiresIn * float64(time.Second))).UTC()
		s.AccessExpiresAt = &t
	}
	s.Touch(now)
}

// ---- connect ----

func (c *client) redirectURL(override string) (string, error) {
	u := firstNonEmpty(override, c.cfg.Credentials.RedirectURL)
	if u == "" {
		return "", fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or the request's RedirectURL)", obsdk.ErrInvalidConfig)
	}
	return u, nil
}

// wantsHistory reports whether the capabilities ask for more than 90 days.
func wantsHistory(caps []obsdk.Capability) bool {
	for _, c := range caps {
		if c == obsdk.CapTransactionsHistory {
			return true
		}
	}
	return false
}

// Connect returns the redirect to the bank's authorization page.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: %s only supports the redirect method here", obsdk.ErrInvalidRequest, c.target.Bank)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	scope := c.p.scopeAIS()
	if h := c.p.scopeHistory(); h != "" && wantsHistory(r.Capabilities) {
		scope += " " + h
	}
	f := &flow{Phase: phConnect, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Caps: r.Capabilities}
	q := url.Values{"response_type": {"code"}, "client_id": {c.cfg.Credentials.ClientID}, "redirect_uri": {redirectURL},
		"scope": {scope}, "state": {f.OAuthState}}
	if r.Language != "" {
		q.Set("ui_locales", r.Language)
	}
	if c.p.PKCE {
		// Two identifiers make a verifier of the required 43+ characters.
		f.Verifier = c.cfg.ID(obsdk.IDState) + c.cfg.ID(obsdk.IDState)
		sum := sha256.Sum256([]byte(f.Verifier))
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		q.Set("code_challenge_method", "S256")
	}
	if c.p.AuthParams != nil {
		c.p.AuthParams(c.cfg, c.target, q)
	}
	f.AuthURL = withQuery(c.auth, q)
	return c.pause(f, connectStep(f))
}

// withQuery adds parameters to a URL that may already have some.
func withQuery(raw string, q url.Values) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw + "?" + q.Encode()
	}
	all := u.Query()
	for k, v := range q {
		all[k] = v
	}
	u.RawQuery = all.Encode()
	return u.String()
}

func connectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to the bank to authorise access, then pass the callback URL to Resume."}
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// exchangeCallback checks an authorization callback and exchanges its code.
func (c *client) exchangeCallback(ctx context.Context, f *flow, cb string) (*tokenResponse, error) {
	p, err := callback.Parse(cb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if code, desc, failed := p.Error(); failed {
		return nil, authFailed("authorisation was not completed (%s: %s)", code, desc)
	}
	if st := p.Get("state"); st != f.OAuthState {
		return nil, authFailed("callback state does not match the authorisation that was started")
	}
	code := p.Get("code")
	if code == "" {
		return nil, fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURL}}
	if f.Verifier != "" {
		form.Set("code_verifier", f.Verifier)
	}
	tr, r, err := c.tokenCall(ctx, opToken, form)
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	return tr, nil
}

// Resume completes a Connect or a payment with the redirect callback.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	switch {
	case f.Phase == phPayment && f.Pay != nil:
		return c.resumePayment(ctx, &f, in)
	case f.Phase != phConnect:
		return nil, fmt.Errorf("%w: unknown flow phase %q", obsdk.ErrInvalidRequest, f.Phase)
	case in.Callback == "":
		return c.pause(&f, connectStep(&f))
	}
	tr, err := c.exchangeCallback(ctx, &f, in.Callback)
	if err != nil {
		return nil, err
	}
	s := &obsdk.Session{
		Bank: c.target.Bank, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: c.p.ID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{},
	}
	c.applyToken(s, tr)
	s.Consents[consentKind] = obsdk.Consent{Kind: consentKind, Status: "authorised"}

	psu := psuOrNil(f.PSU)
	accs, _, err := c.listAccounts(ctx, s, psu)
	if err == nil && c.p.ForwardConsent {
		if err = c.forwardConsent(ctx, s, accs, f.Caps, psu); err == nil {
			accs, _, err = c.listAccounts(ctx, s, psu)
		}
	}
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

// ---- refresh and disconnect ----

// Refresh renews the access token with the refresh token. STET narrows the
// scope on the first refresh: history beyond 90 days needs a new login.
func (c *client) Refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.RefreshToken == "" {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "no_refresh_token"}}
	}
	if s.RefreshExpiresAt != nil && !c.now().Before(*s.RefreshExpiresAt) {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "refresh_token_expired"}}
	}
	tr, r, err := c.tokenCall(ctx, opRefresh, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}})
	if err != nil {
		return nil, &obsdk.RefreshError{Temporary: true, Err: err}
	}
	if tr == nil {
		e := c.apiErr(opRefresh, r)
		return nil, &obsdk.RefreshError{Temporary: r.status == http.StatusTooManyRequests || r.status >= 500, Err: e}
	}
	ns := s.Clone()
	c.applyToken(ns, tr)
	return ns, nil
}

// Disconnect revokes the refresh token where the bank has a revocation
// endpoint. STET has no API to end the user's authorization otherwise; the
// tokens are dropped from the returned session either way.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	if ns.AccessToken == "" && ns.RefreshToken == "" {
		return res, nil
	}
	if c.p.RevokeURL == nil {
		res.Failed[consentKind] = c.target.Bank + " has no API to end the authorisation; the user can revoke it in online banking"
	} else if err := c.revoke(ctx, ns); err != nil {
		res.Failed[consentKind] = err.Error()
	} else {
		res.Closed = append(res.Closed, consentKind)
	}
	delete(ns.Consents, consentKind)
	ns.AccessToken, ns.RefreshToken = "", ""
	ns.AccessExpiresAt, ns.RefreshExpiresAt = nil, nil
	ns.Touch(c.now())
	return res, nil
}

func (c *client) revoke(ctx context.Context, s *obsdk.Session) error {
	token, hint := s.RefreshToken, "refresh_token"
	if token == "" {
		token, hint = s.AccessToken, "access_token"
	}
	r, err := c.do(ctx, c.withClientAuth(req{op: opRevoke, method: http.MethodPost, path: c.p.RevokeURL(c.cfg.Env, c.target),
		form: url.Values{"token": {token}, "token_type_hint": {hint}}}))
	if err != nil {
		return err
	}
	if r.status != http.StatusOK && r.status != http.StatusNoContent {
		return c.apiErr(opRevoke, r)
	}
	return nil
}
