package obie

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
	phPayRedirect  = "payment_redirect_wait"
)

// flow is the serialized state of a Connect or a payment.
type flow struct {
	Phase       string           `json:"phase"`
	PSU         obsdk.PSUContext `json:"psu"`
	RedirectURL string           `json:"redirect_url"`
	OAuthState  string           `json:"oauth_state"`
	AuthURL     string           `json:"auth_url"`
	Consent     obsdk.Consent    `json:"consent"`
	Pay         *payFlow         `json:"pay,omitempty"` // payments only
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// permissions maps capabilities to OBIE permission clusters.
func permissions(caps []obsdk.Capability) []string {
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	out := []string{"ReadAccountsBasic", "ReadAccountsDetail"} // every cluster needs the accounts to be listed
	var bal, tx bool
	for _, c := range caps {
		switch c {
		case obsdk.CapBalances:
			bal = true
		case obsdk.CapTransactions, obsdk.CapTransactionsHistory:
			tx = true
		}
	}
	if bal {
		out = append(out, "ReadBalances")
	}
	if tx {
		out = append(out, "ReadTransactionsBasic", "ReadTransactionsDetail", "ReadTransactionsCredits", "ReadTransactionsDebits")
	}
	return out
}

// ---- tokens ----

type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    float64 `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	Scope        string  `json:"scope"`
}

// UnmarshalJSON accepts expires_in as a number or a string ("300").
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

// token calls the token endpoint with the profile's client authentication.
func (c *client) token(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	if c.p.clientAuth() == PrivateKeyJWT {
		a, err := c.clientAssertion()
		if err != nil {
			return nil, nil, err
		}
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", a)
	}
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, path: c.p.TokenPath, form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("obie: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// clientToken gets a client-credentials token for a scope ("accounts", "payments").
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

type consentResponse struct {
	Data struct {
		ConsentID          string   `json:"ConsentId"`
		Status             string   `json:"Status"`
		ExpirationDateTime string   `json:"ExpirationDateTime"`
		Permissions        []string `json:"Permissions"`
	} `json:"Data"`
}

func (c *client) redirectURL(override string) (string, error) {
	u := override
	if u == "" {
		u = c.cfg.Credentials.RedirectURL
	}
	if u == "" {
		return "", fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or the request's RedirectURL)", obsdk.ErrInvalidConfig)
	}
	return u, nil
}

// Connect creates an account access consent and returns the redirect that
// lets the user authorise it.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: %s only supports the redirect method here", obsdk.ErrInvalidRequest, c.target.Bank)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	cc, err := c.clientToken(ctx, "accounts")
	if err != nil {
		return nil, err
	}
	data := map[string]any{"Permissions": permissions(r.Capabilities)}
	if r.ConsentValidityDays > 0 {
		data["ExpirationDateTime"] = c.now().AddDate(0, 0, r.ConsentValidityDays).UTC().Format(time.RFC3339)
	}
	res, err := c.do(ctx, req{op: opConsent, method: http.MethodPost, path: c.p.AISPath + "/account-access-consents",
		body: map[string]any{"Data": data, "Risk": map[string]any{}}, bearer: cc, psu: psuOrNil(r.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opConsent, res)
	}
	var cr consentResponse
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.Data.ConsentID == "" {
		return nil, fmt.Errorf("obie: unreadable consent response (HTTP %d)", res.status)
	}
	f := &flow{Phase: phRedirectWait, PSU: r.PSU, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState),
		Consent: obsdk.Consent{ID: cr.Data.ConsentID, Kind: consentKind, Status: cr.Data.Status, ValidUntil: parseTime(cr.Data.ExpirationDateTime)}}
	if f.AuthURL, err = c.authorizeURL(f, c.p.intentID(KindAccount, cr.Data.ConsentID), "accounts", r.Language); err != nil {
		return nil, err
	}
	return c.pause(f, redirectStep(f))
}

// authorizeURL builds the authorisation link with a signed request object.
func (c *client) authorizeURL(f *flow, intentID, scope, lang string) (string, error) {
	nonce := c.cfg.ID(obsdk.IDState)
	jwt, err := c.signRequestObject(intentID, f.RedirectURL, f.OAuthState, nonce, scope)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"response_type": {"code id_token"}, "scope": {"openid " + scope}, "redirect_uri": {f.RedirectURL},
		"client_id": {c.cfg.Credentials.ClientID}, "request": {jwt}, "state": {f.OAuthState}, "nonce": {nonce},
	}
	if lang != "" {
		q.Set("ui_locales", lang)
	}
	return c.auth + "?" + q.Encode(), nil
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to the bank to authorise access, then pass the callback URL (with its #fragment) to Resume."}
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// exchangeCallback checks the callback and exchanges its code for tokens.
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
	// The id_token in the callback is not validated: the code exchange over
	// mTLS is what authenticates the result here.
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURL}})
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
	if f.Phase == phPayRedirect && f.Pay != nil {
		return c.resumePayment(ctx, &f, in)
	}
	if f.Phase != phRedirectWait {
		return nil, fmt.Errorf("%w: unknown flow phase %q", obsdk.ErrInvalidRequest, f.Phase)
	}
	if in.Callback == "" {
		return c.pause(&f, redirectStep(&f))
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

// Refresh renews the access token. Refresh tokens are single-use at most
// OBIE banks: the new one replaces it in the returned session.
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

// Disconnect deletes the account access consent at the bank.
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
		r, err := c.do(ctx, req{op: opConsent, method: http.MethodDelete, path: c.p.AISPath + "/account-access-consents/" + url.PathEscape(con.ID), bearer: cc})
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
