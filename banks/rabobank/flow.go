package rabobank

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
	// consentKind names the user's AIS consent in Session.Consents.
	consentKind = "ais"

	// consentDays is how long a PSD2 consent lasts.
	consentDays = 180

	scopeBalances      = "ais.balances.read"
	scopeTransactions  = "ais.transactions.read-90days"
	scopeTxHistory     = "ais.transactions.read-history"
	phRedirectWait     = "redirect_wait"
	metaConsentedOnKey = "consented_on"
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

// scopes maps capabilities to Rabobank scopes. Listing accounts works with
// any AIS scope, so a request for accounts alone asks for balances.
func scopes(caps []obsdk.Capability) string {
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	var bal, tx, hist bool
	for _, c := range caps {
		bal = bal || c == obsdk.CapBalances
		tx = tx || c == obsdk.CapTransactions
		hist = hist || c == obsdk.CapTransactionsHistory
	}
	var out []string
	if bal || (!tx && !hist) {
		out = append(out, scopeBalances)
	}
	if tx || hist {
		out = append(out, scopeTransactions)
	}
	if hist {
		out = append(out, scopeTxHistory)
	}
	return strings.Join(out, " ")
}

// Connect returns the redirect to Rabobank's consent page. No API call is
// needed until the user comes back.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: Rabobank only supports the redirect method", obsdk.ErrInvalidRequest)
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
		"response_type": {"code"}, "client_id": {c.cfg.Credentials.ClientID}, "scope": {scopes(r.Capabilities)},
		"state": {f.OAuthState}, "redirect_uri": {redirectURL},
	}
	f.AuthURL = c.oauth + "/authorize?" + q.Encode()
	return c.pause(f, redirectStep(f))
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to Rabobank to give consent, then pass the callback URL to Resume."}
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// Resume finishes a Connect (exchanges the callback's code for tokens and
// lists the consented accounts) or a payment approval.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if f.Phase == phPayRedirect || f.Phase == phCancelRedirect {
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
		return nil, authFailed("consent was not given (%s: %s)", code, desc)
	}
	if st := p.Get("state"); st != f.OAuthState {
		return nil, authFailed("callback state does not match the authorisation that was started")
	}
	code := p.Get("code")
	if code == "" {
		return nil, fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURL}})
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

	accs, _, err := c.listAccounts(ctx, s, nil)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	cons := s.Consents[consentKind]
	for _, a := range accs {
		for _, id := range a.Identifiers {
			cons.Accounts = append(cons.Accounts, id.Value)
		}
	}
	s.Consents[consentKind] = cons
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

// applyToken stores a token response. The consent's id and start come with
// every token response; its 180 days run from the moment it was given.
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
	cons := s.Consents[consentKind]
	cons.Kind, cons.Status = consentKind, "valid"
	if id := tr.consentID(); id != "" {
		cons.ID = id
	}
	if on := seconds(tr.ConsentedOn); on > 0 {
		given := time.Unix(int64(on/time.Second), 0).UTC()
		until := given.AddDate(0, 0, consentDays)
		cons.ValidUntil = &until
		s.Meta[metaConsentedOnKey] = given.Format(time.RFC3339)
	}
	s.Consents[consentKind] = cons
	s.Touch(now)
}

// ---- refresh and disconnect ----

// Refresh renews the access token. Refresh tokens are single-use: the new
// session carries the replacement.
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
	tr, r, err := c.token(ctx, opRefresh, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}})
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
	c.applyToken(ns, tr)
	return ns, nil
}

// Disconnect revokes the consent (DELETE /oauth2/consents/{id}), which also
// voids the tokens.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	cons, ok := s.Consents[consentKind]
	if !ok {
		return res, nil
	}
	if cons.ID == "" {
		res.Failed[consentKind] = "the session has no consent id to revoke"
		return res, nil
	}
	r, err := c.do(ctx, req{op: opRevoke, method: http.MethodDelete, path: "/oauth2/consents/" + url.PathEscape(cons.ID)})
	if err != nil {
		res.Failed[consentKind] = err.Error()
		return res, nil
	}
	if r.status != http.StatusNoContent && r.status != http.StatusOK {
		res.Failed[consentKind] = c.apiErr(opRevoke, r).Error()
		return res, nil
	}
	res.Closed = append(res.Closed, consentKind)
	delete(ns.Consents, consentKind)
	ns.AccessToken, ns.RefreshToken = "", ""
	ns.AccessExpiresAt, ns.RefreshExpiresAt = nil, nil
	ns.Touch(c.now())
	return res, nil
}
