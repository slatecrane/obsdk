package komercnibanka

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

const (
	// consentKind names the user's AIS access in Session.Consents. KB has no
	// consent resource: the login itself grants access to every account.
	consentKind = "ais"

	// consentDays is how long access lasts after the login (EU 2022/2360).
	consentDays = 180

	scopeAIS = "aisp"
	scopePIS = "pisp"

	phLogin    = "login_wait"
	phPayLogin = "payment_login_wait"
	phPaySign  = "payment_sign_wait"
)

// flow is the serialized state of a Connect, or of a payment waiting for
// the user's login or signature. Phase tells which.
type flow struct {
	Phase       string `json:"phase"`
	RedirectURL string `json:"redirect_url"`
	OAuthState  string `json:"oauth_state,omitempty"`
	AuthURL     string `json:"auth_url"`
	// Payments.
	Pay *payState `json:"pay,omitempty"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// authorizeURL builds the login link. KB takes one scope per login.
func (c *client) authorizeURL(scope, redirectURL, state string) string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {c.cfg.Credentials.ClientID},
		"redirect_uri":  {redirectURL},
		"scope":         {scope},
		"state":         {state},
	}
	sep := "?"
	if strings.Contains(c.auth, "?") {
		sep = "&"
	}
	return c.auth + sep + q.Encode()
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

// Connect returns the redirect to KB's login, where the user grants access
// to all their payment accounts.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: Komerční banka only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	f := &flow{Phase: phLogin, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState)}
	f.AuthURL = c.authorizeURL(scopeAIS, redirectURL, f.OAuthState)
	return c.pause(f, loginStep(f, "Send the user to Komerční banka to log in and grant access, then pass the callback URL to Resume."))
}

func loginStep(f *flow, msg string) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL}, Message: msg}
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// codeFromCallback checks the callback's state and returns its code.
func codeFromCallback(raw, state, what string) (string, error) {
	p, err := callback.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if code, desc, failed := p.Error(); failed {
		return "", authFailed("%s (%s: %s)", what, code, desc)
	}
	if st := p.Get("state"); st != state {
		return "", authFailed("callback state does not match the login that was started")
	}
	code := p.Get("code")
	if code == "" {
		return "", fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	return code, nil
}

// login exchanges a login's code for a new session with the given scope.
func (c *client) login(ctx context.Context, f *flow, raw, scope, what string) (*obsdk.Session, error) {
	code, err := codeFromCallback(raw, f.OAuthState, what)
	if err != nil {
		return nil, err
	}
	tr, r, err := c.tokenCall(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURL}})
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	s := c.newSession()
	s.Meta[metaRedirectURL] = f.RedirectURL
	if tr.Scope == "" {
		// KB's token response may leave the scope out; it is the one asked for.
		tr.Scope = scope
	}
	c.applyToken(s, tr)
	return s, nil
}

// metaRedirectURL keeps the login's redirect URI, which the sandbox wants
// again on every refresh.
const metaRedirectURL = "redirect_uri"

// Resume finishes a Connect (exchanges the code and lists the accounts) or
// continues a payment.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	switch f.Phase {
	case phPayLogin, phPaySign:
		return c.resumePayment(ctx, &f, in)
	case phLogin:
	default:
		return nil, fmt.Errorf("%w: unknown flow phase %q", obsdk.ErrInvalidRequest, f.Phase)
	}
	if in.Callback == "" {
		return c.pause(&f, loginStep(&f, "Send the user to Komerční banka to log in and grant access, then pass the callback URL to Resume."))
	}
	s, err := c.login(ctx, &f, in.Callback, scopeAIS, "access was not granted")
	if err != nil {
		return nil, err
	}
	until := c.now().AddDate(0, 0, consentDays).UTC().Truncate(time.Second)
	s.Consents[consentKind] = obsdk.Consent{Kind: consentKind, Status: "valid", ValidUntil: &until}
	s.Touch(c.now())

	accs, _, err := c.accounts(ctx, s, true)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	cons := s.Consents[consentKind]
	for _, a := range accs {
		for _, id := range a.Identifiers {
			if id.Scheme == obsdk.SchemeIBAN && !contains(cons.Accounts, id.Value) {
				cons.Accounts = append(cons.Accounts, id.Value)
			}
		}
	}
	s.Consents[consentKind] = cons
	s.Touch(c.now())
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func (c *client) newSession() *obsdk.Session {
	return &obsdk.Session{
		Bank: bankKey, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: integrationID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{},
	}
}

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

// hasScope reports whether the session's token was issued for scope.
func hasScope(s *obsdk.Session, scope string) bool {
	for _, x := range strings.Fields(s.Scope) {
		if x == scope {
			return true
		}
	}
	return false
}

// ---- refresh and disconnect ----

// Refresh renews the access token. KB keeps the refresh token (it lasts as
// long as the 180-day access) and issues no new one.
func (c *client) Refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	return c.refresh(ctx, s)
}

func (c *client) refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if s.RefreshToken == "" {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "no_refresh_token"}}
	}
	if cons, ok := s.Consents[consentKind]; ok && cons.ValidUntil != nil && !c.now().Before(*cons.ValidUntil) {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "consent_expired", Consent: consentKind}}
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}}
	if u := s.Meta[metaRedirectURL]; u != "" {
		form.Set("redirect_uri", u)
	}
	tr, r, err := c.tokenCall(ctx, opRefresh, form)
	if err != nil {
		return nil, &obsdk.RefreshError{Temporary: true, Err: err}
	}
	if tr == nil {
		e := c.apiErr(opRefresh, r)
		return nil, &obsdk.RefreshError{Temporary: r.status == http.StatusTooManyRequests || r.status >= 500, Err: e}
	}
	ns := s.Clone()
	if ns.Consents == nil {
		ns.Consents = map[string]obsdk.Consent{}
	}
	if ns.Meta == nil {
		ns.Meta = map[string]string{}
	}
	if tr.Scope == "" {
		tr.Scope = s.Scope
	}
	c.applyToken(ns, tr)
	return ns, nil
}

// Disconnect revokes the refresh token at KB, which ends the access. (The
// user can also revoke it in KB's internet banking.)
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	kind := consentKind
	if _, ok := s.Consents[kind]; !ok {
		if !hasScope(s, scopePIS) {
			return res, nil
		}
		kind = paymentKind
	}
	token := s.RefreshToken
	if token == "" {
		token = s.AccessToken
	}
	if token == "" {
		res.Failed[kind] = "the session has no token to revoke"
		return res, nil
	}
	form := url.Values{"token": {token}, "client_id": {c.cfg.Credentials.ClientID}}
	if sec := c.cfg.Credentials.ClientSecret.Reveal(); sec != "" {
		form.Set("client_secret", sec)
	}
	r, err := c.do(ctx, req{op: opRevoke, method: http.MethodPost, url: c.revokeURL(), form: form})
	if err != nil {
		res.Failed[kind] = err.Error()
		return res, nil
	}
	if r.status != http.StatusOK && r.status != http.StatusNoContent {
		res.Failed[kind] = c.apiErr(opRevoke, r).Error()
		return res, nil
	}
	res.Closed = append(res.Closed, kind)
	delete(ns.Consents, kind)
	ns.AccessToken, ns.RefreshToken = "", ""
	ns.AccessExpiresAt, ns.RefreshExpiresAt = nil, nil
	ns.Touch(c.now())
	return res, nil
}

// revokeURL sits next to the token endpoint.
func (c *client) revokeURL() string {
	return strings.TrimSuffix(c.token, "/token") + "/revoke"
}
