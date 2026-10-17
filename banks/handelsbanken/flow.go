package handelsbanken

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

const (
	// consentKind names the AIS consent in Session.Consents.
	consentKind = "accounts"

	phInput     = "input"         // waiting for the company id
	phRedirect  = "redirect_wait" // the user is at the bank (or, in the sandbox, the callback is ready)
	phDecoupled = "decoupled"     // polling Mobile BankID

	methodRedirect  = "redirect"
	methodDecoupled = "decoupled"

	keyCorporateID = "corporate_id"
	keyPersonalID  = "personal_id"

	// Consents last 180 days, 90 in GB (Consents API description). The
	// lifetime is fixed: the request has no validity field.
	maxConsentDays = 180

	defaultPoll = 2 * time.Second
)

// scope prefixes for the OAuth scope that ties a token to one consent or payment.
const (
	scopeAIS = "AIS"
	scopePIS = "PIS"
)

// flow is the serialized state of a Connect, and of a payment's approval
// (Purpose "payment"); payments keep their own fields in Pay.
type flow struct {
	Phase       string           `json:"phase"`
	Purpose     string           `json:"purpose,omitempty"` // "" (connect) or "payment"
	Method      string           `json:"method"`
	PSU         obsdk.PSUContext `json:"psu"`
	RedirectURL string           `json:"redirect_url,omitempty"`
	OAuthState  string           `json:"oauth_state,omitempty"`
	Scope       string           `json:"scope,omitempty"` // "AIS:<consent id>" or "PIS:<payment id>"
	AuthURL     string           `json:"auth_url,omitempty"`
	TokenURL    string           `json:"token_url,omitempty"`  // decoupled poll link
	CancelURL   string           `json:"cancel_url,omitempty"` // decoupled cancel link
	PollMS      int              `json:"poll_ms,omitempty"`
	Challenge   *obsdk.Challenge `json:"challenge,omitempty"`
	ConsentID   string           `json:"consent_id,omitempty"`
	Days        int              `json:"days,omitempty"`
	Pay         *payState        `json:"pay,omitempty"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// method picks redirect or decoupled. Decoupled (Mobile BankID) is Swedish only.
func (c *client) method(m string) (string, error) {
	switch m {
	case "":
		return methodRedirect, nil
	case methodRedirect:
		return m, nil
	case methodDecoupled:
		if c.target.Country != "SE" {
			return "", fmt.Errorf("%w: Handelsbanken offers decoupled (Mobile BankID) authorisation in Sweden only", obsdk.ErrInvalidRequest)
		}
		return m, nil
	}
	return "", fmt.Errorf("%w: unknown method %q (redirect or decoupled)", obsdk.ErrInvalidRequest, m)
}

func (c *client) redirectURL(override string) string {
	if override != "" {
		return override
	}
	return c.cfg.Credentials.RedirectURL
}

// corporateID returns the PSU-Corporate-ID for a business user. GB has no
// usable id: the bank wants the literal UNKNOWN.
func (c *client) corporateID(psu obsdk.PSUContext) string {
	if !c.business() {
		return ""
	}
	if c.target.Country == "GB" {
		return "UNKNOWN"
	}
	return psu.CorporateID
}

func corporateField() obsdk.Field {
	// No pattern: production wants digits, the sandbox its user names.
	return obsdk.Field{Key: keyCorporateID, Label: "Company id (SE: organisation number, NL: corporate number)", Kind: obsdk.FieldText, Required: true}
}

var orgNumberRE = regexp.MustCompile(`^[0-9]{6}-[0-9]{4}$`)

// fill copies answers into the PSU context.
func fill(psu *obsdk.PSUContext, vals map[string]string) {
	if v := strings.TrimSpace(vals[keyCorporateID]); v != "" {
		if orgNumberRE.MatchString(v) {
			v = strings.ReplaceAll(v, "-", "") // 556677-8899 -> 5566778899
		}
		psu.CorporateID = v
	}
	if v := strings.TrimSpace(vals[keyPersonalID]); v != "" {
		psu.ID = v
	}
}

// Connect creates an AIS consent and starts its authorisation.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	m, err := c.method(r.Method)
	if err != nil {
		return nil, err
	}
	limit := maxConsentDays
	if c.target.Country == "GB" {
		limit = 90 // GB consents last 90 days (Consents API)
	}
	f := &flow{Method: m, PSU: r.PSU, RedirectURL: c.redirectURL(r.RedirectURL), Days: limit}
	if d := r.ConsentValidityDays; d > 0 && d < limit {
		f.Days = d
	}
	if m == methodRedirect && f.RedirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or ConnectRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	fill(&f.PSU, r.Values)
	if c.business() && c.corporateID(f.PSU) == "" {
		f.Phase = phInput
		return c.pause(f, &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true,
			Message: "Handelsbanken needs the company's id for a business connection.", Fields: []obsdk.Field{corporateField()}})
	}
	return c.startConsent(ctx, f)
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// scaMethod is one entry of a consent's or payment's scaMethods.
type scaMethod struct {
	Type  string `json:"scaMethodType"`
	Links struct {
		Authorization []struct {
			Href string `json:"href"`
			Name string `json:"name"`
		} `json:"authorization"`
	} `json:"_links"`
}

// link returns the authorisation link of the wanted approach.
func link(ms []scaMethod, method string) string {
	for _, m := range ms {
		if strings.EqualFold(m.Type, method) && len(m.Links.Authorization) > 0 {
			return m.Links.Authorization[0].Href
		}
	}
	return ""
}

func (c *client) psuHeaders(psu obsdk.PSUContext) map[string]string {
	h := map[string]string{}
	if id := c.corporateID(psu); id != "" {
		h["PSU-Corporate-ID"], h["PSU-Corporate-ID-Type"] = id, "BANK"
	}
	return h
}

func (c *client) startConsent(ctx context.Context, f *flow) (*obsdk.Step, error) {
	cct, err := c.clientToken(ctx, scopeAIS)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req{op: opConsent, method: http.MethodPost, url: c.apiURL(c.consentsPath()), api: true, bearer: cct,
		country: c.countryHeader(), header: c.psuHeaders(f.PSU), psu: psuOrNil(f.PSU), body: map[string]string{"access": "ALL_ACCOUNTS"}})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK && res.status != http.StatusCreated {
		return nil, c.apiErr(opConsent, res)
	}
	var cr struct {
		ConsentID  string      `json:"consentId"`
		Status     string      `json:"consentStatus"`
		SCAMethods []scaMethod `json:"scaMethods"`
	}
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.ConsentID == "" {
		return nil, fmt.Errorf("handelsbanken: unreadable consent response (HTTP %d)", res.status)
	}
	f.ConsentID, f.Scope = cr.ConsentID, scopeAIS+":"+cr.ConsentID
	return c.authorize(ctx, f, cr.SCAMethods)
}

// authorize starts the user's approval of f.Scope with the chosen method,
// from the links the consent or payment response offered.
func (c *client) authorize(ctx context.Context, f *flow, ms []scaMethod) (*obsdk.Step, error) {
	l := link(ms, f.Method)
	if l == "" {
		return nil, fmt.Errorf("%w: Handelsbanken did not offer %s authorisation here", obsdk.ErrUnsupported, f.Method)
	}
	if f.Method == methodDecoupled {
		return c.startDecoupled(ctx, f, l)
	}
	f.OAuthState = c.cfg.ID(obsdk.IDState)
	u, err := url.Parse(l)
	if err != nil {
		return nil, fmt.Errorf("handelsbanken: bad authorisation link %q", l)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("scope", f.Scope)
	q.Set("client_id", c.cfg.Credentials.ClientID)
	q.Set("state", f.OAuthState)
	q.Set("redirect_uri", f.RedirectURL)
	u.RawQuery = q.Encode()
	f.AuthURL = u.String()
	if c.cfg.Env == obsdk.Sandbox {
		// The sandbox has no login page: the authorize call names the user in a
		// header and answers at once with a 302 to the callback.
		if err := c.sandboxAuthorize(ctx, f); err != nil {
			return nil, err
		}
	}
	f.Phase = phRedirect
	return c.pause(f, c.redirectStep(f))
}

func (c *client) sandboxAuthorize(ctx context.Context, f *flow) error {
	h := map[string]string{}
	if u := c.cfg.Param(paramSandboxUser); u != "" {
		h["X-Sandbox-User"] = u
	}
	res, err := c.do(ctx, req{op: opAuthorize, method: http.MethodGet, url: f.AuthURL, header: h})
	if err != nil {
		return err
	}
	loc := res.header.Get("Location")
	if res.status/100 != 3 || loc == "" {
		e := c.apiErr(opAuthorize, res)
		if c.cfg.Param(paramSandboxUser) == "" {
			return fmt.Errorf("%w (set Config.Extra[%q] to a user from the sandbox test data)", e, paramSandboxUser)
		}
		return e
	}
	f.AuthURL = loc
	return nil
}

func (c *client) redirectStep(f *flow) *obsdk.Step {
	msg := "Send the user to Handelsbanken to approve access, then pass the callback URL to Resume."
	if f.Purpose == purposePayment {
		msg = "Send the user to Handelsbanken to sign the payment, then pass the callback URL to Resume."
	}
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL}, Message: msg}
}

// ---- decoupled (Mobile BankID) ----

type decoupledInit struct {
	ClientID       string `json:"client_id"`
	Scope          string `json:"scope"`
	PSUClientIP    string `json:"psu_client_ip"`
	PSUID          string `json:"psu_id,omitempty"`
	BISASameDevice bool   `json:"bisa_same_device"`
}

type decoupledResponse struct {
	AutoStartToken string `json:"auto_start_token"`
	QRCode         string `json:"qr_code"`
	SleepTime      int    `json:"sleep_time"`
	Links          struct {
		Token  struct{ Href string } `json:"token"`
		Cancel struct{ Href string } `json:"cancel"`
	} `json:"_links"`
}

func (c *client) startDecoupled(ctx context.Context, f *flow, l string) (*obsdk.Step, error) {
	body := decoupledInit{ClientID: c.cfg.Credentials.ClientID, Scope: f.Scope, PSUClientIP: f.PSU.IP, BISASameDevice: true}
	if body.PSUClientIP == "" {
		body.PSUClientIP = "127.0.0.1"
	}
	if !c.business() {
		body.PSUID = f.PSU.ID
		if body.PSUID == "" && c.cfg.Env == obsdk.Sandbox {
			body.PSUID = c.cfg.Param(paramSandboxUser) // the sandbox's stand-in for the personnummer
		}
	}
	res, err := c.do(ctx, req{op: opDecoupled, method: http.MethodPost, url: l, body: body})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.apiErr(opDecoupled, res)
	}
	var dr decoupledResponse
	if err := json.Unmarshal(res.body, &dr); err != nil || dr.Links.Token.Href == "" {
		return nil, fmt.Errorf("handelsbanken: unreadable Mobile BankID response (HTTP %d)", res.status)
	}
	f.Phase, f.TokenURL, f.CancelURL, f.PollMS = phDecoupled, dr.Links.Token.Href, dr.Links.Cancel.Href, dr.SleepTime
	f.Challenge = &obsdk.Challenge{AutoStartToken: dr.AutoStartToken, Code: dr.QRCode, Text: "Open Mobile BankID and confirm."}
	return c.pause(f, c.waitStep(f))
}

func (c *client) waitStep(f *flow) *obsdk.Step {
	d := time.Duration(f.PollMS) * time.Millisecond
	if d <= 0 {
		d = defaultPoll
	}
	return &obsdk.Step{Kind: obsdk.StepWait, NeedsUser: false, Challenge: f.Challenge, WaitFor: d,
		Message: "Waiting for the user to confirm in Mobile BankID."}
}

// pollDecoupled asks the token link once. It returns the token when the user
// confirmed, nil when still waiting.
func (c *client) pollDecoupled(ctx context.Context, f *flow) (*tokenResponse, error) {
	res, err := c.do(ctx, req{op: opDecoupled, method: http.MethodPost, url: f.TokenURL, body: struct{}{}})
	if err != nil {
		return nil, err
	}
	var pr struct {
		Result string `json:"result"`
		Error  string `json:"error"`
		tokenResponse
	}
	_ = json.Unmarshal(res.body, &pr)
	switch {
	case pr.Error != "":
		return nil, authFailed("Mobile BankID: %s", pr.Error)
	case res.status != http.StatusOK:
		return nil, c.apiErr(opDecoupled, res)
	case strings.EqualFold(pr.Result, "COMPLETE"):
		if pr.AccessToken == "" {
			return nil, fmt.Errorf("handelsbanken: Mobile BankID completed without a token")
		}
		return &pr.tokenResponse, nil
	}
	return nil, nil // outstandingTransaction, noClient, started, userSign
}

// ---- resume ----

// Resume continues a Connect, a payment's approval or a cancellation.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if f.Purpose == purposePayment {
		return c.resumePayment(ctx, &f, in)
	}
	switch f.Phase {
	case phInput:
		fill(&f.PSU, in.Values)
		if c.corporateID(f.PSU) == "" {
			return c.pause(&f, &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "The company id is required.", Fields: []obsdk.Field{corporateField()}})
		}
		return c.startConsent(ctx, &f)
	case phRedirect:
		code, err := c.callbackCode(&f, in)
		if err != nil || code == "" {
			if err == nil {
				return c.pause(&f, c.redirectStep(&f))
			}
			return nil, err
		}
		tr, err := c.exchange(ctx, &f, code)
		if err != nil {
			return nil, err
		}
		return c.finishConnect(ctx, &f, tr)
	case phDecoupled:
		tr, err := c.pollDecoupled(ctx, &f)
		if err != nil {
			return nil, err
		}
		if tr == nil {
			return c.pause(&f, c.waitStep(&f))
		}
		return c.finishConnect(ctx, &f, tr)
	}
	return nil, fmt.Errorf("%w: unknown flow phase %q", obsdk.ErrInvalidRequest, f.Phase)
}

// callbackCode reads the code from a redirect callback; empty input means
// the caller asked for the step again.
func (c *client) callbackCode(f *flow, in obsdk.StepInput) (string, error) {
	if in.Callback == "" {
		return "", nil
	}
	p, err := callback.Parse(in.Callback)
	if err != nil {
		return "", fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if code, desc, failed := p.Error(); failed {
		return "", authFailed("authorisation was not completed (%s: %s)", code, desc)
	}
	if st := p.Get("state"); st != f.OAuthState {
		return "", authFailed("callback state does not match the authorisation that was started")
	}
	code := p.Get("code")
	if code == "" {
		return "", fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	return code, nil
}

// exchange trades an authorisation code for the token of f.Scope.
func (c *client) exchange(ctx context.Context, f *flow, code string) (*tokenResponse, error) {
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "scope": {f.Scope}, "code": {code}, "redirect_uri": {f.RedirectURL}})
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	return tr, nil
}

func (c *client) newSession() *obsdk.Session {
	return &obsdk.Session{Bank: bankKey, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: integrationID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{}}
}

func (c *client) finishConnect(ctx context.Context, f *flow, tr *tokenResponse) (*obsdk.Step, error) {
	s := c.newSession()
	c.applyToken(s, tr)
	s.Scope = f.Scope
	until := c.now().AddDate(0, 0, f.Days).UTC()
	s.Consents[consentKind] = obsdk.Consent{ID: f.ConsentID, Kind: consentKind, Status: "valid", ValidUntil: &until}
	if f.Method != "" {
		s.Meta["method"] = f.Method
	}
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

// Refresh gets a new access token with the refresh token (AIS only).
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

// Disconnect forgets the tokens. Handelsbanken's Consents API only creates
// consents: there is no call to read or delete one (the sandbox answers 404),
// so the consent stays valid at the bank until it expires or the user
// withdraws it there.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	if _, ok := s.Consents[consentKind]; ok {
		res.Failed[consentKind] = "Handelsbanken has no API to revoke a consent; the user can withdraw it in the bank's online services"
	}
	ns.Consents = nil
	ns.AccessToken, ns.RefreshToken = "", ""
	ns.AccessExpiresAt, ns.RefreshExpiresAt = nil, nil
	ns.Touch(c.now())
	return res, nil
}
