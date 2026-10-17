package bunq

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Login methods (ConnectRequest.Method).
const (
	methodRedirect = "redirect" // OAuth: the user scans a QR code on bunq's page with the bunq app
	methodAPIKey   = "api_key"  // the user's own API key, for applications only its owner uses
)

const (
	phRedirectWait = "redirect_wait"
	phKeyInput     = "api_key_input"

	// fieldAPIKey is the input key for the api_key method (also accepted in ConnectRequest.Values).
	fieldAPIKey = "api_key"

	// Session.Meta keys.
	metaUserID       = "user_id"            // the id used in /user/{id}/... paths (the UserApiKey's for OAuth)
	metaUserType     = "user_type"          // UserPerson, UserCompany or UserApiKey
	metaGrantedBy    = "granted_by"         // OAuth: UserPerson or UserCompany that gave the access
	metaInstallation = "installation_token" // authenticates device-server and session-server calls
	metaSessionID    = "session_id"         // for DELETE /session/{id}
	metaMethod       = "method"

	defaultDevice = "obsdk"
)

// flow is the serialized state of a Connect.
type flow struct {
	Phase       string `json:"phase"`
	RedirectURL string `json:"redirect_url,omitempty"`
	OAuthState  string `json:"oauth_state,omitempty"`
	AuthURL     string `json:"auth_url,omitempty"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// Connect starts the OAuth redirect (default) or asks for the user's API key.
// bunq has no scopes: the user picks the shared accounts in the app, and the
// access covers accounts, payments and draft payments alike.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	switch r.Method {
	case "", methodRedirect:
	case methodAPIKey:
		if key := strings.TrimSpace(r.Values[fieldAPIKey]); key != "" {
			return c.activate(ctx, key, methodAPIKey)
		}
		return c.pause(&flow{Phase: phKeyInput}, keyStep())
	default:
		return nil, fmt.Errorf("%w: bunq methods are %q and %q", obsdk.ErrInvalidRequest, methodRedirect, methodAPIKey)
	}
	if c.cfg.Credentials.ClientID == "" || c.cfg.Credentials.ClientSecret == "" {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{"client_id and client_secret (the OAuth client)"}}
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or ConnectRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	f := &flow{Phase: phRedirectWait, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState)}
	q := url.Values{"response_type": {"code"}, "client_id": {c.cfg.Credentials.ClientID}, "redirect_uri": {redirectURL}, "state": {f.OAuthState}}
	f.AuthURL = c.auth + "?" + q.Encode()
	return c.pause(f, redirectStep(f))
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to bunq: they scan the QR code with the bunq app and pick the accounts to share. Then pass the callback URL to Resume."}
}

func keyStep() *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true,
		Message: "Create an API key in the bunq app (Profile, Settings, Developers, API keys) and enter it.",
		Fields:  []obsdk.Field{{Key: fieldAPIKey, Label: "bunq API key", Kind: obsdk.FieldSecret, Required: true}}}
}

func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	return st, nil
}

// Resume finishes a Connect (OAuth callback or API key) or continues a payment.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	switch f.Phase {
	case phPayWait:
		var pf payFlow
		if err := flowstate.Decode(state, &pf); err != nil {
			return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
		}
		return c.resumePayment(ctx, &pf)
	case phKeyInput:
		key := strings.TrimSpace(in.Values[fieldAPIKey])
		if key == "" {
			return c.pause(&f, keyStep())
		}
		return c.activate(ctx, key, methodAPIKey)
	case phRedirectWait:
	default:
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
		return nil, authFailed("access was not granted (%s: %s)", code, desc)
	}
	if st := p.Get("state"); st != f.OAuthState {
		return nil, authFailed("callback state does not match the authorisation that was started")
	}
	code := p.Get("code")
	if code == "" {
		return nil, fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	token, err := c.exchange(ctx, code, f.RedirectURL)
	if err != nil {
		return nil, err
	}
	return c.activate(ctx, token, methodRedirect)
}

// exchange trades the authorization code for the user's access token. bunq
// reads the parameters from the query string only, even on this POST.
func (c *client) exchange(ctx context.Context, code, redirectURL string) (string, error) {
	q := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURL},
		"client_id": {c.cfg.Credentials.ClientID}, "client_secret": {c.cfg.Credentials.ClientSecret.Reveal()},
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.token+"?"+q.Encode(), http.NoBody)
	if err != nil {
		return "", err
	}
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("Cache-Control", "no-cache")
	hr.Header.Set("User-Agent", "obsdk")
	r, err := c.send(hr, opToken)
	if err != nil {
		return "", err
	}
	if r.status != http.StatusOK {
		return "", fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("bunq: unreadable token response (HTTP %d)", r.status)
	}
	return tr.AccessToken, nil
}

// ---- API context: installation, device, session ----

// activate turns an access token or API key into a session: a new
// installation with the client's key, a device-server binding the token to
// this device, and a session-server call. Then it lists the accounts the
// user shared.
func (c *client) activate(ctx context.Context, secret, method string) (*obsdk.Step, error) {
	s := &obsdk.Session{
		Bank: bankKey, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: integrationID,
		RefreshToken: secret, Consents: map[string]obsdk.Consent{}, Meta: map[string]string{metaMethod: method},
	}
	if err := c.install(ctx, s, opSession); err != nil {
		return nil, err
	}
	if err := c.startSession(ctx, s, opSession); err != nil {
		return nil, err
	}
	accs, _, err := c.listAccounts(ctx, s)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	cons := s.Consents[consentKind(s)]
	cons.Accounts = nil
	for _, a := range accs {
		for _, id := range a.Identifiers {
			cons.Accounts = append(cons.Accounts, id.Value)
		}
	}
	s.Consents[consentKind(s)] = cons
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

// consentKind names the access in Session.Consents: "oauth" or "api_key".
func consentKind(s *obsdk.Session) string {
	if s.Meta[metaMethod] == methodAPIKey {
		return methodAPIKey
	}
	return "oauth"
}

// install creates an installation and registers the device for s.RefreshToken.
// bunq allows one device per installation, so every token gets its own.
func (c *client) install(ctx context.Context, s *obsdk.Session, op string) error {
	body, _ := json.Marshal(map[string]string{"client_public_key": c.pubPEM})
	r, err := c.do(ctx, req{op: opInstall, method: http.MethodPost, path: "/installation", body: body})
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return c.apiErr(opInstall, r)
	}
	e, err := parseEnvelope(r.body)
	if err != nil {
		return err
	}
	var tok struct {
		Token string `json:"token"`
	}
	if raw := e.first("Token"); raw == nil || json.Unmarshal(raw, &tok) != nil || tok.Token == "" {
		return fmt.Errorf("bunq: installation response has no token")
	}

	name := c.cfg.Param(paramDevice)
	if name == "" {
		name = defaultDevice
	}
	dev := map[string]any{"description": name, "secret": s.RefreshToken}
	if ips := c.permittedIPs(); len(ips) > 0 {
		dev["permitted_ips"] = ips
	}
	body, _ = json.Marshal(dev)
	r, err = c.do(ctx, req{op: opDevice, method: http.MethodPost, path: "/device-server", body: body, auth: tok.Token})
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		err := c.apiErr(opDevice, r)
		if op == opSession {
			// During Connect a refused token means the login failed.
			return fmt.Errorf("%w: %w", obsdk.ErrAuthFailed, err)
		}
		return err
	}
	s.Meta[metaInstallation] = tok.Token
	return nil
}

func (c *client) permittedIPs() []string {
	var out []string
	for _, ip := range strings.Split(c.cfg.Param(paramPermittedIPs), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// sessionUser is the user object a session-server call returns. For OAuth
// it is a UserApiKey wrapping the app (requested_by_user) and the bunq user
// who granted access (granted_by_user).
type sessionUser struct {
	ID             json.Number `json:"id"`
	SessionTimeout int         `json:"session_timeout"`
	RequestedBy    userRef     `json:"requested_by_user"`
	GrantedBy      userRef     `json:"granted_by_user"`
}

// userRef is {"UserPerson": {...}} or {"UserCompany": {...}}, ...
type userRef map[string]struct {
	ID             json.Number `json:"id"`
	SessionTimeout int         `json:"session_timeout"`
}

func (u userRef) kind() (string, int) {
	for k, v := range u {
		return k, v.SessionTimeout
	}
	return "", 0
}

// startSession calls session-server with the installation token and stores
// the session token and user in s.
func (c *client) startSession(ctx context.Context, s *obsdk.Session, op string) error {
	body, _ := json.Marshal(map[string]string{"secret": s.RefreshToken})
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, path: "/session-server", body: body, auth: s.Meta[metaInstallation]})
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		err := c.apiErr(op, r)
		if op == opSession {
			return fmt.Errorf("%w: %w", obsdk.ErrAuthFailed, err)
		}
		return err
	}
	e, err := parseEnvelope(r.body)
	if err != nil {
		return err
	}
	var id, tok struct {
		ID    json.Number `json:"id"`
		Token string      `json:"token"`
	}
	if raw := e.first("Token"); raw == nil || json.Unmarshal(raw, &tok) != nil || tok.Token == "" {
		return fmt.Errorf("bunq: session response has no token")
	}
	_ = json.Unmarshal(e.first("Id"), &id)

	var (
		user    sessionUser
		typ     string
		timeout int
	)
	for _, t := range []string{"UserApiKey", "UserPerson", "UserCompany", "UserPaymentServiceProvider"} {
		if raw := e.first(t); raw != nil {
			typ = t
			if err := json.Unmarshal(raw, &user); err != nil {
				return fmt.Errorf("bunq: unreadable %s in session response: %w", t, err)
			}
			break
		}
	}
	if typ == "" || user.ID == "" {
		return fmt.Errorf("bunq: session response has no user")
	}
	timeout = user.SessionTimeout
	if typ == "UserApiKey" {
		// The shorter of the app's and the user's auto-logout times.
		granted, gt := user.GrantedBy.kind()
		_, rt := user.RequestedBy.kind()
		timeout = gt
		if rt > 0 && (timeout == 0 || rt < timeout) {
			timeout = rt
		}
		s.Meta[metaGrantedBy] = granted
	}
	if prev := s.Meta[metaUserID]; prev != "" && prev != user.ID.String() {
		return fmt.Errorf("bunq: the token now belongs to user %s, not %s", user.ID, prev)
	}

	now := c.now()
	s.AccessToken, s.TokenType = tok.Token, "bunq-session"
	s.AccessExpiresAt = nil
	if timeout > 0 {
		t := now.Add(time.Duration(timeout) * time.Second).UTC()
		s.AccessExpiresAt = &t
	}
	s.Meta[metaUserID], s.Meta[metaUserType] = user.ID.String(), typ
	s.Meta[metaSessionID] = id.ID.String()
	kind := consentKind(s)
	cons := s.Consents[kind]
	cons.Kind, cons.Status = kind, "valid"
	if typ == "UserApiKey" {
		cons.ID = user.ID.String()
	}
	s.Consents[kind] = cons
	s.Touch(now)
	return nil
}

// ---- refresh and disconnect ----

// Refresh starts a new bunq session with the stored access token (or API
// key). When the installation is missing or no longer accepted (it is tied to
// the key that made it, so a new Config.Seal key also lands here), it makes
// a new one first.
func (c *client) Refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.RefreshToken == "" {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "no_access_token"}}
	}
	ns := s.Clone()
	if ns.Consents == nil {
		ns.Consents = map[string]obsdk.Consent{}
	}
	if ns.Meta == nil {
		ns.Meta = map[string]string{}
	}
	fresh := ns.Meta[metaInstallation] == ""
	if fresh {
		if err := c.install(ctx, ns, opRefresh); err != nil {
			return nil, refreshErr(err)
		}
	}
	err := c.startSession(ctx, ns, opRefresh)
	var re *obsdk.ReauthError
	if !fresh && asReauth(err, &re) {
		// The installation may be gone rather than the token: try once more
		// with a new one before asking the user to log in again.
		if err = c.install(ctx, ns, opRefresh); err == nil {
			err = c.startSession(ctx, ns, opRefresh)
		}
	}
	if err != nil {
		return nil, refreshErr(err)
	}
	return ns, nil
}

func asReauth(err error, re **obsdk.ReauthError) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*obsdk.ReauthError)
	if ok {
		*re = e
	}
	return ok
}

func refreshErr(err error) error {
	switch e := err.(type) {
	case *obsdk.ReauthError:
		return &obsdk.RefreshError{Err: e}
	case *obsdk.RateLimitedError:
		return &obsdk.RefreshError{Temporary: true, Err: e}
	case *obsdk.APIError:
		return &obsdk.RefreshError{Temporary: e.Status >= 500, Err: e}
	}
	return &obsdk.RefreshError{Temporary: true, Err: err}
}

// Disconnect ends the bunq session. bunq has no API to revoke an OAuth grant
// or an API key: the user does that in the app, so the access is reported in
// Failed and the session loses its tokens.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	if id := s.Meta[metaSessionID]; id != "" && s.AccessToken != "" && !s.AccessExpired(c.now()) {
		r, err := c.do(ctx, req{op: opLogout, method: http.MethodDelete, path: "/session/" + url.PathEscape(id), auth: s.AccessToken})
		if err == nil && r.status != http.StatusOK && r.status != http.StatusForbidden {
			err = c.apiErr(opLogout, r)
		}
		if err != nil {
			c.log.Debug("bunq: ending the session failed", "err", err)
		}
	}
	kind := consentKind(s)
	if _, ok := s.Consents[kind]; ok {
		res.Failed[kind] = "bunq has no API to revoke this access; the user can revoke it in the bunq app (Settings, Security, connected apps or API keys)"
	}
	ns.Consents = nil
	ns.AccessToken, ns.RefreshToken = "", ""
	ns.AccessExpiresAt = nil
	delete(ns.Meta, metaInstallation)
	delete(ns.Meta, metaSessionID)
	ns.Touch(c.now())
	return res, nil
}
