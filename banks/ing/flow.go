package ing

import (
	"context"
	"errors"
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
	// consentKind names the user's grant in Session.Consents. ING has no
	// consent resource: the grant lives in the refresh token.
	consentKind = "accounts"

	scopeBalances     = "payment-accounts:balances:view"
	scopeTransactions = "payment-accounts:transactions:view"

	phRedirectWait = "redirect_wait"
)

// flow is the serialized state of a Connect.
type flow struct {
	Phase       string `json:"phase"`
	RedirectURL string `json:"redirect_url"`
	OAuthState  string `json:"oauth_state"`
	AuthURL     string `json:"auth_url"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// scopes maps capabilities to ING scopes. Listing accounts needs either one.
func scopes(caps []obsdk.Capability) string {
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	var bal, tx bool
	for _, c := range caps {
		bal = bal || c == obsdk.CapBalances
		tx = tx || c == obsdk.CapTransactions || c == obsdk.CapTransactionsHistory
	}
	var out []string
	if bal || !tx {
		out = append(out, scopeBalances)
	}
	if tx {
		out = append(out, scopeTransactions)
	}
	return strings.Join(out, " ")
}

// Connect returns the redirect to ING's authorisation page for the client's
// country. No API call is needed until the user comes back.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: ING only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or ConnectRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	f := &flow{Phase: phRedirectWait, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState)}
	q := url.Values{
		"client_id": {c.cfg.Credentials.ClientID}, "scope": {scopes(r.Capabilities)}, "state": {f.OAuthState},
		"redirect_uri": {redirectURL}, "response_type": {"code"},
	}
	f.AuthURL = c.auth + string(c.target.Country) + "?" + q.Encode()
	return c.pause(f, redirectStep(f))
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to ING to authorise access, then pass the callback URL to Resume."}
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// Resume finishes a Connect (exchanges the callback's code for the
// customer's tokens and lists the granted accounts) or a payment approval.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if f.Phase == phPayRedirect {
		var pf payFlow
		if err := flowstate.Decode(state, &pf); err != nil {
			return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
		}
		return c.resumePayment(ctx, &pf, in)
	}
	if f.Phase != phRedirectWait {
		return nil, fmt.Errorf("%w: unknown flow phase %q", obsdk.ErrInvalidRequest, f.Phase)
	}
	if in.Callback == "" {
		return c.pause(&f, redirectStep(&f))
	}
	p, err := callback.Parse(in.Callback)
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
	app, err := c.applicationToken(ctx)
	if err != nil {
		return nil, err
	}
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURL}}, app)
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	s := &obsdk.Session{
		Bank: bankKey, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: integrationID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{},
	}
	c.applyToken(s, tr)
	s.Consents[consentKind] = obsdk.Consent{Kind: consentKind, Status: "granted", ValidUntil: s.RefreshExpiresAt}

	accs, err := c.accountsAfterGrant(ctx, s)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

// accountsAfterGrant lists the accounts right after the code exchange. ING
// may still be processing the mandate and answer 404 for a few seconds; its
// docs ask clients to retry.
func (c *client) accountsAfterGrant(ctx context.Context, s *obsdk.Session) ([]obsdk.Account, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		var accs []obsdk.Account
		if accs, _, err = c.listAccounts(ctx, s); err == nil {
			return accs, nil
		}
		var ae *obsdk.APIError
		if !errors.As(err, &ae) || ae.Status != http.StatusNotFound {
			return nil, err
		}
	}
	return nil, err
}

func (c *client) applyToken(s *obsdk.Session, tr *tokenResponse) {
	now := c.now()
	s.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		s.RefreshToken = tr.RefreshToken
		s.RefreshExpiresAt = nil
		if d := seconds(tr.RefreshTokenExpiresIn); d > 0 {
			t := now.Add(d).UTC()
			s.RefreshExpiresAt = &t
		}
	}
	if tr.TokenType != "" {
		s.TokenType = tr.TokenType
	}
	if tr.Scope != "" {
		s.Scope = tr.Scope
	}
	s.AccessExpiresAt = nil
	if d := seconds(tr.ExpiresIn); d > 0 {
		t := now.Add(d).UTC()
		s.AccessExpiresAt = &t
	}
	s.Touch(now)
}

// ---- refresh and disconnect ----

// Refresh renews the customer access token with the application token.
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
	app, err := c.applicationToken(ctx)
	if err != nil {
		return nil, &obsdk.RefreshError{Temporary: true, Err: err}
	}
	tr, r, err := c.token(ctx, opRefresh, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}}, app)
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

// Disconnect revokes the refresh token, which ends the user's grant.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	if s.RefreshToken == "" {
		return res, nil
	}
	fail := func(err error) (*obsdk.DisconnectResult, error) {
		res.Failed[consentKind] = err.Error()
		return res, nil
	}
	app, err := c.applicationToken(ctx)
	if err != nil {
		return fail(err)
	}
	r, err := c.do(ctx, req{op: opRevoke, method: http.MethodPost, path: "/oauth2/token/revoke", bearer: app,
		form: url.Values{"token": {s.RefreshToken}, "token_type_hint": {"refresh_token"}}})
	if err != nil {
		return fail(err)
	}
	if r.status != http.StatusOK && r.status != http.StatusNoContent {
		return fail(c.apiErr(opRevoke, r))
	}
	res.Closed = append(res.Closed, consentKind)
	delete(ns.Consents, consentKind)
	ns.AccessToken, ns.RefreshToken = "", ""
	ns.AccessExpiresAt, ns.RefreshExpiresAt = nil, nil
	ns.Touch(c.now())
	return res, nil
}
