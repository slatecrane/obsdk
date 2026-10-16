package nordea

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

const (
	// consentKind names the user's grant in Session.Consents. Nordea has no
	// consent resource: the grant lives in the tokens.
	consentKind = "accounts"

	phRedirectWait = "redirect_wait"

	defaultConsentDays = 90
	maxConsentDays     = 180
)

type flow struct {
	Phase       string           `json:"phase"`
	PSU         obsdk.PSUContext `json:"psu"`
	RedirectURL string           `json:"redirect_url"`
	OAuthState  string           `json:"oauth_state"`
	AuthURL     string           `json:"auth_url"`
	Days        int              `json:"days"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// scopes maps capabilities to Nordea scopes. Listing accounts needs
// ACCOUNTS_BASIC; ACCOUNTS_DETAILS adds the account details call.
func scopes(caps []obsdk.Capability) []string {
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	out := []string{"ACCOUNTS_BASIC", "ACCOUNTS_DETAILS"}
	var bal, tx bool
	for _, c := range caps {
		bal = bal || c == obsdk.CapBalances
		tx = tx || c == obsdk.CapTransactions || c == obsdk.CapTransactionsHistory
	}
	if bal {
		out = append(out, "ACCOUNTS_BALANCES")
	}
	if tx {
		out = append(out, "ACCOUNTS_TRANSACTIONS")
	}
	return out
}

type authorizeBody struct {
	AccountList          []string `json:"account_list"`
	Country              string   `json:"country"`
	Duration             int      `json:"duration"` // minutes
	Language             string   `json:"language,omitempty"`
	RedirectURI          string   `json:"redirect_uri"`
	Scope                []string `json:"scope"`
	SkipAccountSelection bool     `json:"skip_account_selection"`
	State                string   `json:"state"`
}

// Connect starts the redirect flow. POST /authorize answers with a 302 whose
// Location is Nordea's login page (in the sandbox: the callback itself).
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: only the redirect method is implemented for Nordea", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or ConnectRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	days := r.ConsentValidityDays
	if days <= 0 {
		days = defaultConsentDays
	}
	days = min(days, maxConsentDays)
	f := &flow{Phase: phRedirectWait, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Days: days}
	body := authorizeBody{
		AccountList: []string{"ALL"}, Country: string(c.target.Country), Duration: days * 24 * 60, Language: r.Language,
		RedirectURI: redirectURL, Scope: scopes(r.Capabilities), State: f.OAuthState,
	}
	res, err := c.do(ctx, req{op: opAuthorize, method: http.MethodPost, path: "/" + c.segment() + "/v5/authorize", body: body, psu: psuOrNil(r.PSU)})
	if err != nil {
		return nil, err
	}
	loc := res.header.Get("Location")
	if res.status != http.StatusFound || loc == "" {
		return nil, c.apiErr(opAuthorize, res)
	}
	f.AuthURL = loc
	return c.pause(f, redirectStep(f))
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to Nordea to authorise access, then pass the callback URL to Resume."}
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
// lists the accounts) or a payment signature.
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
	until := c.now().AddDate(0, 0, f.Days).UTC()
	s.Consents[consentKind] = obsdk.Consent{Kind: consentKind, Status: "granted", ValidUntil: &until}

	accs, _, err := c.listAccounts(ctx, s, psuOrNil(f.PSU))
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

func psuOrNil(p obsdk.PSUContext) *obsdk.PSUContext {
	if p == (obsdk.PSUContext{}) {
		return nil
	}
	return &p
}

// ---- tokens ----

type tokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    json.Number `json:"expires_in"`
	RefreshToken string      `json:"refresh_token"`
}

func (c *client) token(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, path: "/" + c.segment() + "/v5/authorize/token", form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("nordea: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
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
	s.AccessExpiresAt = nil
	if f, err := tr.ExpiresIn.Float64(); err == nil && f > 0 {
		t := now.Add(time.Duration(f * float64(time.Second))).UTC()
		s.AccessExpiresAt = &t
	}
	s.Touch(now)
}

// Refresh exchanges the refresh token, which is one-time use: the response
// carries a new one.
func (c *client) Refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.RefreshToken == "" {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "no_refresh_token"}}
	}
	if cons, ok := s.Consents[consentKind]; ok && cons.ValidUntil != nil && !c.now().Before(*cons.ValidUntil) {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "consent_expired", Consent: consentKind}}
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
	c.applyToken(ns, tr)
	return ns, nil
}

// Disconnect revokes the refresh token, ending the grant.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	if s.RefreshToken == "" {
		return res, nil
	}
	r, err := c.do(ctx, req{op: opRevoke, method: http.MethodPost, path: "/" + c.segment() + "/v5/authorize/token/revoke",
		body: map[string]string{"token": s.RefreshToken}, bearer: s.AccessToken})
	switch {
	case err != nil:
		res.Failed[consentKind] = err.Error()
		return res, nil
	case r.status != http.StatusOK && r.status != http.StatusNoContent:
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
