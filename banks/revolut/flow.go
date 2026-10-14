package revolut

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
	consentKind = "accounts"

	phRedirectWait = "redirect_wait"
)

// flow is the serialized state of a Connect.
type flow struct {
	Phase       string           `json:"phase"`
	PSU         obsdk.PSUContext `json:"psu"`
	RedirectURL string           `json:"redirect_url"`
	OAuthState  string           `json:"oauth_state"`
	AuthURL     string           `json:"auth_url"`
	Consent     obsdk.Consent    `json:"consent"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// permissions maps capabilities to OBIE permission clusters.
func permissions(caps []obsdk.Capability) []string {
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	var out []string
	add := func(p ...string) {
		for _, x := range p {
			dup := false
			for _, y := range out {
				dup = dup || x == y
			}
			if !dup {
				out = append(out, x)
			}
		}
	}
	add("ReadAccountsBasic", "ReadAccountsDetail") // every cluster needs the accounts to be listed
	for _, c := range caps {
		switch c {
		case obsdk.CapBalances:
			add("ReadBalances")
		case obsdk.CapTransactions, obsdk.CapTransactionsHistory:
			add("ReadTransactionsBasic", "ReadTransactionsDetail", "ReadTransactionsCredits", "ReadTransactionsDebits")
		}
	}
	return out
}

// ---- tokens ----

type tokenResponse struct {
	AccessToken           string  `json:"access_token"`
	TokenType             string  `json:"token_type"`
	ExpiresIn             float64 `json:"expires_in"`
	RefreshToken          string  `json:"refresh_token"`
	RefreshTokenExpiresAt int64   `json:"refresh_token_expires_at"`
	Scope                 string  `json:"scope"`
}

func (c *client) token(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, path: "/token", form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("revolut: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// clientToken gets a client-credentials token, used for consent management.
func (c *client) clientToken(ctx context.Context) (string, error) {
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"client_credentials"}, "scope": {"accounts"}})
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
	if tr.RefreshTokenExpiresAt > 0 {
		t := time.Unix(tr.RefreshTokenExpiresAt, 0).UTC()
		s.RefreshExpiresAt = &t
	}
	s.Touch(now)
}

// ---- connect ----

type consentResponse struct {
	Data struct {
		ConsentID          string   `json:"ConsentId"`
		Status             string   `json:"Status"`
		ExpirationDateTime string   `json:"ExpirationDateTime"`
		Permissions        []string `json:"Permissions"`
	} `json:"Data"`
}

// Connect creates an account access consent and returns the redirect that
// lets the user authorise it.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: Revolut only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or ConnectRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	cc, err := c.clientToken(ctx)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"Permissions": permissions(r.Capabilities)}
	if r.ConsentValidityDays > 0 {
		body["ExpirationDateTime"] = c.now().AddDate(0, 0, r.ConsentValidityDays).UTC().Format(time.RFC3339)
	}
	res, err := c.do(ctx, req{op: opConsent, method: http.MethodPost, path: "/account-access-consents",
		body: map[string]any{"Data": body, "Risk": map[string]any{}}, bearer: cc, psu: psuOrNil(r.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opConsent, res)
	}
	var cr consentResponse
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.Data.ConsentID == "" {
		return nil, fmt.Errorf("revolut: unreadable consent response (HTTP %d)", res.status)
	}

	f := &flow{Phase: phRedirectWait, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState),
		Consent: obsdk.Consent{ID: cr.Data.ConsentID, Kind: consentKind, Status: cr.Data.Status, ValidUntil: parseTime(cr.Data.ExpirationDateTime)}}
	jwt, err := c.signRequestObject(f.Consent.ID, redirectURL, f.OAuthState)
	if err != nil {
		return nil, err
	}
	// state goes in the query too: the sandbox echoes the query's state and
	// returns "null" when it is only in the request object.
	q := url.Values{
		"response_type": {"code id_token"}, "scope": {"accounts"}, "redirect_uri": {redirectURL},
		"client_id": {c.cfg.Credentials.ClientID}, "request": {jwt}, "state": {f.OAuthState},
	}
	f.AuthURL = c.ui + "?" + q.Encode()
	return c.pause(f, redirectStep(f))
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to Revolut to authorise access, then pass the callback URL to Resume."}
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// Resume completes a Connect with the redirect callback.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
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
	// The id_token in the callback is not validated: the code exchange over
	// mTLS is what authenticates the result here.
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}})
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
	cons := f.Consent
	cons.Status = "Authorised"
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

// Refresh renews the access token. Revolut invalidates the previous access token.
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
	c.applyToken(ns, tr)
	return ns, nil
}

// Disconnect deletes the account access consent at Revolut.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	if len(s.Consents) == 0 {
		return res, nil
	}
	cc, err := c.clientToken(ctx)
	if err != nil {
		for kind := range s.Consents {
			res.Failed[kind] = err.Error()
		}
		return res, nil
	}
	for kind, con := range s.Consents {
		r, err := c.do(ctx, req{op: opConsent, method: http.MethodDelete, path: "/account-access-consents/" + url.PathEscape(con.ID), bearer: cc})
		switch {
		case err != nil:
			res.Failed[kind] = err.Error()
		case r.status == http.StatusNoContent || r.status == http.StatusOK || r.status == http.StatusNotFound:
			res.Closed = append(res.Closed, kind)
			delete(ns.Consents, kind)
		default:
			res.Failed[kind] = c.apiErr(opConsent, r).Error()
		}
	}
	ns.Touch(c.now())
	return res, nil
}
