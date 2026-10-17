package op

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

const (
	consentKind = "accounts"

	// maxConsentDays is OP's limit on an authorisation's expires.
	maxConsentDays = 180

	// refreshTTL is how long OP's refresh tokens stay valid (renewed on refresh).
	refreshTTL = 45 * 24 * time.Hour

	phConnect = "connect_redirect"
	phPayment = "payment_redirect"
	phCancel  = "cancel_redirect"
)

// flow is the serialized state of a Connect, a payment or a cancellation.
type flow struct {
	Phase       string           `json:"phase"`
	PSU         obsdk.PSUContext `json:"psu"`
	RedirectURL string           `json:"redirect_url"`
	OAuthState  string           `json:"oauth_state"`
	AuthURL     string           `json:"auth_url"`
	Consent     obsdk.Consent    `json:"consent,omitempty"`
	Pay         *payState        `json:"pay,omitempty"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// ---- tokens ----

// seconds reads expires_in, which OP sends as a number or as a string.
type seconds int64

func (s *seconds) UnmarshalJSON(b []byte) error {
	v := strings.Trim(string(b), `"`)
	if v == "" || v == "null" {
		*s = 0
		return nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return err
	}
	*s = seconds(n)
	return nil
}

type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    seconds `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	Scope        string  `json:"scope"`
}

func (c *client) token(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	form.Set("client_secret", c.cfg.Credentials.ClientSecret.Reveal())
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, path: "/oauth/token", form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("op: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// clientToken gets a client-credentials token for one scope ("accounts",
// "payments"); OP allows one scope per request.
func (c *client) clientToken(ctx context.Context, scope string) (string, error) {
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"client_credentials"}, "scope": {scope}})
	if err != nil {
		return "", err
	}
	if tr == nil {
		return "", c.apiErr(opToken, r)
	}
	return tr.AccessToken, nil
}

// exchangeCode trades the callback's code for the user's tokens.
func (c *client) exchangeCode(ctx context.Context, f *flow, in obsdk.StepInput, what string) (*tokenResponse, error) {
	p, err := callback.Parse(in.Callback)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if code, desc, failed := p.Error(); failed {
		if desc == "" {
			desc = p.Get("description") // OP's name for the reason, e.g. insufficient_funds
		}
		return nil, authFailed("%s was not approved (%s: %s)", what, code, desc)
	}
	if st := p.Get("state"); st != f.OAuthState {
		return nil, authFailed("callback state does not match the %s that was started", what)
	}
	code := p.Get("code")
	if code == "" {
		return nil, fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	// The id_token in the callback is not validated: the code exchange over
	// mTLS with the client secret is what authenticates the result here.
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURL}})
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	return tr, nil
}

func (c *client) applyToken(s *obsdk.Session, tr *tokenResponse) {
	now := c.now()
	s.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		s.RefreshToken = tr.RefreshToken
		t := now.Add(refreshTTL).UTC()
		s.RefreshExpiresAt = &t
	}
	if tr.TokenType != "" {
		s.TokenType = tr.TokenType
	}
	if tr.Scope != "" {
		s.Scope = tr.Scope
	}
	s.AccessExpiresAt = nil
	if tr.ExpiresIn > 0 {
		t := now.Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()
		s.AccessExpiresAt = &t
	}
	s.Touch(now)
}

func (c *client) newSession() *obsdk.Session {
	return &obsdk.Session{
		Bank: bankKey, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: integrationID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{},
	}
}

func (c *client) redirectURL(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if c.cfg.Credentials.RedirectURL != "" {
		return c.cfg.Credentials.RedirectURL, nil
	}
	return "", fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or the request's RedirectURL)", obsdk.ErrInvalidConfig)
}

// authorizeURL signs the request object and builds the link to OP's
// authorisation page. The query repeats what the request object says.
func (c *client) authorizeURL(f *flow, authorizationID, paymentID, scope string) error {
	jwt, err := c.signRequestObject(authorizationID, paymentID, f.RedirectURL, f.OAuthState, c.cfg.ID(obsdk.IDState), scope)
	if err != nil {
		return err
	}
	q := url.Values{
		"request": {jwt}, "response_type": {"code id_token"}, "client_id": {c.cfg.Credentials.ClientID},
		"scope": {"openid " + scope},
	}
	f.AuthURL = c.auth + "?" + q.Encode()
	return nil
}

// ---- connect ----

type authorizationJSON struct {
	AuthorizationID string `json:"authorizationId"`
	Status          string `json:"status"`
	Expires         string `json:"expires"`
}

// Connect registers an account authorisation and returns the redirect that
// lets the user approve it.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: OP only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	if _, _, err := c.alg(); err != nil { // fail on missing signing config before any call
		return nil, err
	}
	days := r.ConsentValidityDays
	if days <= 0 || days > maxConsentDays {
		days = maxConsentDays
	}
	cc, err := c.clientToken(ctx, "accounts")
	if err != nil {
		return nil, err
	}
	// A continuous authorisation; it reaches 90 days of history.
	body := map[string]string{"expires": c.now().AddDate(0, 0, days).UTC().Format("2006-01-02T15:04:05.000Z")}
	res, err := c.do(ctx, req{op: opConsent, method: http.MethodPost, path: "/accounts-psd2/v1/authorizations",
		body: body, bearer: cc, psu: psuOrNil(r.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opConsent, res)
	}
	var a authorizationJSON
	if err := json.Unmarshal(res.body, &a); err != nil || a.AuthorizationID == "" {
		return nil, fmt.Errorf("op: unreadable authorization response (HTTP %d)", res.status)
	}
	f := &flow{Phase: phConnect, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState),
		Consent: obsdk.Consent{ID: a.AuthorizationID, Kind: consentKind, Status: a.Status, ValidUntil: parseTime(a.Expires)}}
	if err := c.authorizeURL(f, a.AuthorizationID, "", "accounts"); err != nil {
		return nil, err
	}
	return c.pause(f, redirectStep(f, "Send the user to OP to approve account access, then pass the callback URL to Resume."))
}

func redirectStep(f *flow, msg string) *obsdk.Step {
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

// Resume completes a Connect, a payment or a cancellation with the redirect callback.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	switch {
	case f.Phase == phPayment && f.Pay != nil:
		return c.resumePayment(ctx, &f, in)
	case f.Phase == phCancel && f.Pay != nil:
		return c.resumeCancel(ctx, &f, in)
	case f.Phase != phConnect:
		return nil, fmt.Errorf("%w: unknown flow phase %q", obsdk.ErrInvalidRequest, f.Phase)
	}
	if in.Callback == "" {
		return c.pause(&f, redirectStep(&f, "Send the user to OP to approve account access, then pass the callback URL to Resume."))
	}
	tr, err := c.exchangeCode(ctx, &f, in, "account access")
	if err != nil {
		return nil, err
	}
	s := c.newSession()
	c.applyToken(s, tr)
	cons := f.Consent
	cons.Status = "Authorized"
	s.Consents[consentKind] = cons

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

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// ---- refresh and disconnect ----

// Refresh renews the access token; OP renews the refresh token with it.
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

// Disconnect revokes the account authorisation at OP, which OP asks AISPs
// to do when the user ends the service.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	if len(s.Consents) == 0 {
		return res, nil
	}
	cc, err := c.clientToken(ctx, "accounts")
	if err != nil {
		for kind := range s.Consents {
			res.Failed[kind] = err.Error()
		}
		return res, nil
	}
	for kind, con := range s.Consents {
		r, err := c.do(ctx, req{op: opConsent, method: http.MethodDelete, path: "/accounts-psd2/v1/authorizations/" + url.PathEscape(con.ID), bearer: cc})
		switch {
		case err != nil:
			res.Failed[kind] = err.Error()
		case r.status == http.StatusOK || r.status == http.StatusNoContent:
			res.Closed = append(res.Closed, kind)
			delete(ns.Consents, kind)
		case r.status == http.StatusNotFound:
			// The sandbox answers 404 "not found" for an approved authorization
			// that GET still shows as Authorized: only count it closed when it
			// is really gone or no longer valid.
			if live, st := c.authorizationLive(ctx, cc, con.ID); live {
				res.Failed[kind] = fmt.Sprintf("OP refused the revocation (HTTP 404) and still reports the authorization as %s", st)
			} else {
				res.Closed = append(res.Closed, kind)
				delete(ns.Consents, kind)
			}
		default:
			res.Failed[kind] = c.apiErr(opConsent, r).Error()
		}
	}
	ns.Touch(c.now())
	return res, nil
}

// authorizationLive reports whether OP still holds an account authorization
// that grants access, and its status.
func (c *client) authorizationLive(ctx context.Context, cc, id string) (bool, string) {
	r, err := c.do(ctx, req{op: opConsent, method: http.MethodGet, path: "/accounts-psd2/v1/authorizations/" + url.PathEscape(id), bearer: cc})
	if err != nil || r.status != http.StatusOK {
		return false, ""
	}
	var a authorizationJSON
	if json.Unmarshal(r.body, &a) != nil {
		return false, ""
	}
	return a.Status == "Authorized" || a.Status == "Unauthorized", a.Status
}
