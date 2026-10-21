package abnamro

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

const (
	// consentKind names the user's AIS consent in Session.Consents.
	consentKind = "ais"

	// consentDays is how long a production consent lasts.
	consentDays = 180

	scopeBalance     = "psd2:account:balance:read"
	scopeTransaction = "psd2:account:transaction:read"
	scopeDetails     = "psd2:account:details:read"

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

// scopes maps capabilities to ABN AMRO scopes. The details scope is always
// requested: it is what Accounts reads.
func scopes(caps []obsdk.Capability) []string {
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	out := []string{scopeDetails}
	for _, c := range caps {
		switch c {
		case obsdk.CapBalances:
			out = append(out, scopeBalance)
		case obsdk.CapTransactions:
			out = append(out, scopeTransaction)
		}
	}
	return out
}

// queryValue escapes a query value but keeps ":" and "/" readable, as in
// ABN AMRO's examples: the consent page refuses URLs longer than 256
// characters, and percent-encoding the scopes and redirect URL would cost
// about 30 of them.
func queryValue(s string) string {
	return strings.NewReplacer("%3A", ":", "%2F", "/").Replace(url.QueryEscape(s))
}

// newState returns a short OAuth state: 20 hex characters (80 bits) of a
// fresh id. A full UUID would push the authorize URL past ABN AMRO's
// 256-character limit.
func (c *client) newState() string {
	s := strings.ReplaceAll(c.cfg.ID(obsdk.IDState), "-", "")
	return s[:min(len(s), 20)]
}

// authorizeURL builds the consent page link. transactionID is set for payments.
func (c *client) authorizeURL(scope []string, redirectURL, state, transactionID string) string {
	var b strings.Builder
	b.WriteString(c.auth)
	b.WriteString("?scope=")
	for i, s := range scope {
		if i > 0 {
			b.WriteByte('+')
		}
		b.WriteString(queryValue(s))
	}
	b.WriteString("&client_id=" + queryValue(c.cfg.Credentials.ClientID))
	if transactionID != "" {
		b.WriteString("&transactionId=" + queryValue(transactionID))
	}
	b.WriteString("&response_type=code&flow=code&redirect_uri=" + queryValue(redirectURL) + "&state=" + queryValue(state))
	return b.String()
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

// Connect returns the redirect to ABN AMRO's consent page, where the user
// picks the one account the consent covers.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: ABN AMRO only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	f := &flow{Phase: phRedirectWait, RedirectURL: redirectURL, OAuthState: c.newState()}
	f.AuthURL = c.authorizeURL(scopes(r.Capabilities), redirectURL, f.OAuthState, "")
	return c.pause(f, redirectStep(f))
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to ABN AMRO to pick an account and give consent, then pass the callback URL to Resume."}
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
		// access_denied: the user cancelled, or has no account to choose.
		return "", authFailed("%s (%s: %s)", what, code, desc)
	}
	if st := p.Get("state"); st != state {
		return "", authFailed("callback state does not match the authorisation that was started")
	}
	code := p.Get("code")
	if code == "" {
		return "", fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	return code, nil
}

// Resume finishes a Connect (exchanges the code, reads which account the
// user picked and its details) or a payment approval.
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
	code, err := codeFromCallback(in.Callback, f.OAuthState, "consent was not given")
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
	c.applyToken(s, tr)

	ci, err := c.consentInfo(ctx, s.AccessToken)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	if ci.IBAN == "" {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: fmt.Errorf("abnamro: consent information names no account")}
	}
	cons := obsdk.Consent{Kind: consentKind, Status: "valid", Accounts: []string{ci.IBAN}}
	if ci.ConsentStatus != "" {
		cons.Status = strings.ToLower(ci.ConsentStatus)
	}
	if d := parseExpiresIn(ci.ConsentExpiresIn); d > 0 {
		until := c.now().Add(d).UTC().Truncate(time.Second)
		cons.ValidUntil = &until
	}
	if ci.Scopes != "" {
		s.Scope = ci.Scopes
	}
	s.Consents[consentKind] = cons
	s.Touch(c.now())

	acc, _, err := c.account(ctx, s, nil)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: []obsdk.Account{acc}}, nil
}

func (c *client) newSession() *obsdk.Session {
	return &obsdk.Session{
		Bank: bankKey, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: integrationID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{},
	}
}

// consentInfoJSON is GET /v1/consentinfo. ABN AMRO answers it at most twice
// per consent, so it is read once, at Connect, and kept in the session.
type consentInfoJSON struct {
	IBAN             string `json:"iban"`
	TransactionID    string `json:"transactionId"`
	Scopes           string `json:"scopes"`
	ConsentStatus    string `json:"consentStatus"`
	ConsentExpiresIn string `json:"consentExpiresIn"`
}

func (c *client) consentInfo(ctx context.Context, token string) (*consentInfoJSON, error) {
	r, err := c.do(ctx, req{op: opConsentInfo, method: http.MethodGet, path: "/v1/consentinfo", bearer: token})
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, c.apiErr(opConsentInfo, r)
	}
	var ci consentInfoJSON
	if err := json.Unmarshal(r.body, &ci); err != nil {
		return nil, fmt.Errorf("abnamro: unreadable consent information: %w", err)
	}
	return &ci, nil
}

var expiresPart = regexp.MustCompile(`(\d+)\s+(day|hour|minute|second)s?`)

// parseExpiresIn reads consentExpiresIn, which ABN AMRO sends as text:
// "26 days, 23 hours, 57 minutes, and 5 seconds".
func parseExpiresIn(s string) time.Duration {
	var d time.Duration
	for _, m := range expiresPart.FindAllStringSubmatch(s, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0
		}
		unit := map[string]time.Duration{"day": 24 * time.Hour, "hour": time.Hour, "minute": time.Minute, "second": time.Second}[m[2]]
		d += time.Duration(n) * unit
	}
	return d
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

// ---- refresh and disconnect ----

// Refresh renews the access token. ABN AMRO rotates the refresh token: the
// new session carries the replacement.
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
	tr, r, err := c.tokenCall(ctx, opRefresh, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}})
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

// Disconnect revokes the refresh token at the authorization server (RFC
// 7009), which voids every access token of the consent as well.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	kind := consentKind
	if _, ok := s.Consents[kind]; !ok {
		if _, ok := s.Consents[paymentKind]; !ok {
			return res, nil
		}
		kind = paymentKind
	}
	token, hint := s.RefreshToken, "refresh_token"
	if token == "" {
		token, hint = s.AccessToken, "access_token"
	}
	if token == "" {
		res.Failed[kind] = "the session has no token to revoke"
		return res, nil
	}
	form := url.Values{"token": {token}, "token_type_hint": {hint}, "client_id": {c.cfg.Credentials.ClientID}}
	r, err := c.do(ctx, req{op: opRevoke, method: http.MethodPost, url: c.revoke, form: form})
	if err != nil {
		res.Failed[kind] = err.Error()
		return res, nil
	}
	if r.status != http.StatusOK {
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
