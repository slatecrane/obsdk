package swedbank

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

const (
	goalConnect   = "connect"
	goalStatement = "statement"

	methodRedirect  = "redirect"
	methodDecoupled = "decoupled"

	defaultConsentDays = 90
	maxConsentDays     = 180
	pollInterval       = 2 * time.Second
	statementInterval  = 60 * time.Second // the bank proposes 60s between download attempts
)

// Phases of the flow state machine. Each either advances (sets the next
// phase) or pauses by returning a Step.
const (
	phStart = "start"

	phRedirectStart = "login_redirect_start"
	phRedirectWait  = "login_redirect_wait"

	phMethod = "login_method"
	phFields = "login_fields"
	phPost   = "login_post"
	phPoll   = "login_poll"
	phBankID = "login_bank_id"

	phAllStart      = "consent_all_start"
	phDetailedStart = "consent_detailed_start"
	phOver90Start   = "consent_over90_start"
	phConsentSCA    = "consent_sca"
	phConsentPoll   = "consent_poll"
	phConsentRedir  = "consent_redirect_wait"
	phConsentCheck  = "consent_check"
	phFinish        = "finish"

	phStmtPost     = "stmt_post"
	phStmtAuth     = "stmt_authorise"
	phStmtPoll     = "stmt_poll"
	phStmtRedir    = "stmt_redirect_wait"
	phStmtStatus   = "stmt_status"
	phStmtDownload = "stmt_download"
)

// flow is the serialized state of a resumable operation.
type flow struct {
	Goal  string `json:"goal"`
	Phase string `json:"phase"`

	Method       string            `json:"method"`
	PSU          obsdk.PSUContext  `json:"psu"`
	RedirectURL  string            `json:"redirect_url"`
	Language     string            `json:"language,omitempty"`
	ValidityDays int               `json:"validity_days"`
	Values       map[string]string `json:"values,omitempty"`

	OAuthState   string           `json:"oauth_state,omitempty"`
	AuthURL      string           `json:"auth_url,omitempty"`
	PollPath     string           `json:"poll_path,omitempty"`
	Challenge    *obsdk.Challenge `json:"challenge,omitempty"`
	Message      string           `json:"message,omitempty"`
	Session      *obsdk.Session   `json:"session,omitempty"`
	Consent      *consentFlow     `json:"consent,omitempty"`
	Accounts     []obsdk.Account  `json:"accounts,omitempty"`
	CallbackSeen bool             `json:"callback_seen,omitempty"`
	Retried      bool             `json:"retried,omitempty"`

	Stmt *stmtFlow `json:"stmt,omitempty"`
}

type consentFlow struct {
	Kind         string   `json:"kind"`
	ID           string   `json:"id"`
	Approach     string   `json:"approach,omitempty"`
	ChosenMethod string   `json:"chosen_method,omitempty"`
	RedirectURL  string   `json:"redirect_url,omitempty"`
	SelectPath   string   `json:"select_path,omitempty"`
	ScaPath      string   `json:"sca_path,omitempty"`
	StatusPath   string   `json:"status_path,omitempty"`
	Accounts     []string `json:"accounts,omitempty"`
	ValidUntil   string   `json:"valid_until,omitempty"`
}

type stmtFlow struct {
	AccountID    string `json:"account_id"`
	AccountRef   string `json:"account_ref"`
	From         string `json:"from"`
	To           string `json:"to"`
	Status       string `json:"status"`
	ID           string `json:"id,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
	StartAuth    string `json:"start_auth,omitempty"`
	SelectPath   string `json:"select_path,omitempty"`
	ScaPath      string `json:"sca_path,omitempty"`
	StatusPath   string `json:"status_path,omitempty"`
	DownloadPath string `json:"download_path,omitempty"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

func tppSummary(msgs []tppMessage) string {
	if len(msgs) == 0 {
		return "no details from the bank"
	}
	return strings.TrimSpace(msgs[0].Code + " " + msgs[0].Text)
}

// ---- entry points ----

// Connect starts login, consents and account discovery.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.PSU.IP == "" || r.PSU.UserAgent == "" {
		return nil, fmt.Errorf("%w: PSU.IP and PSU.UserAgent are required (Swedbank needs them to create consents)", obsdk.ErrInvalidRequest)
	}
	redirectURL := r.RedirectURL
	if redirectURL == "" {
		redirectURL = c.cfg.Credentials.RedirectURL
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: no redirect URL (Credentials.RedirectURL or ConnectRequest.RedirectURL)", obsdk.ErrInvalidConfig)
	}
	method := r.Method
	if method == "" {
		method = methodRedirect
	}
	if method != methodRedirect && method != methodDecoupled {
		return nil, fmt.Errorf("%w: unknown method %q (want redirect or decoupled)", obsdk.ErrInvalidRequest, method)
	}
	days := r.ConsentValidityDays
	if days <= 0 {
		days = defaultConsentDays
	}
	if days > maxConsentDays {
		days = maxConsentDays
	}
	f := &flow{
		Goal: goalConnect, Phase: phStart, Method: method, PSU: r.PSU, RedirectURL: redirectURL,
		Language: r.Language, ValidityDays: days, Values: map[string]string{},
	}
	for k, v := range r.Values {
		f.Values[k] = v
	}
	return c.run(ctx, f, obsdk.StepInput{})
}

// Resume continues a Connect or an extended-history export.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	return c.run(ctx, &f, in)
}

// run drives the state machine until it must pause.
func (c *client) run(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	if f.Values == nil {
		f.Values = map[string]string{}
	}
	for k, v := range in.Values {
		f.Values[k] = v
	}
	if f.PSU.ID != "" && f.Values["psu_id"] == "" {
		f.Values["psu_id"] = f.PSU.ID
	}
	for i := 0; i < 60; i++ {
		step, advance, err := c.phase(ctx, f, in)
		in.Callback = "" // a callback is consumed by exactly one phase
		if err != nil {
			if f.Session != nil && f.Session.AccessToken != "" {
				return nil, &obsdk.FlowError{Session: f.Session.Clone(), Err: err}
			}
			return nil, err
		}
		if step != nil {
			if step.Session == nil && f.Session != nil && f.Session.AccessToken != "" {
				step.Session = f.Session.Clone()
			}
			if step.Kind != obsdk.StepDone {
				st, err := flowstate.Encode(f)
				if err != nil {
					return nil, err
				}
				step.State = st
			}
			return step, nil
		}
		if !advance {
			return nil, fmt.Errorf("swedbank: flow stalled in phase %q", f.Phase)
		}
	}
	return nil, fmt.Errorf("swedbank: flow did not settle (phase %q)", f.Phase)
}

func (c *client) phase(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, bool, error) {
	switch f.Phase {
	case phStart:
		if f.Method == methodRedirect {
			f.Phase = phRedirectStart
		} else {
			f.Phase = phMethod
		}
		return nil, true, nil

	// ---- login: redirect ----
	case phRedirectStart:
		return c.loginRedirectStart(ctx, f)
	case phRedirectWait:
		return c.loginRedirectWait(ctx, f, in)

	// ---- login: decoupled ----
	case phMethod:
		return c.loginMethod(ctx, f)
	case phFields:
		return c.loginFields(f)
	case phPost:
		return c.loginPost(ctx, f)
	case phPoll:
		return c.loginPoll(ctx, f)
	case phBankID:
		return c.loginBankID(ctx, f)

	// ---- consents ----
	case phAllStart:
		return c.startConsent(ctx, f, kindAll, nil)
	case phDetailedStart:
		return c.detailedStart(ctx, f)
	case phOver90Start:
		return c.startConsent(ctx, f, kindOver90, []string{f.Stmt.AccountRef})
	case phConsentSCA:
		return c.consentSCA(ctx, f)
	case phConsentPoll:
		return c.consentPoll(ctx, f)
	case phConsentRedir:
		return c.consentRedirect(f, in)
	case phConsentCheck:
		return c.consentCheck(ctx, f)
	case phFinish:
		return c.finish(ctx, f)

	// ---- extended history ----
	case phStmtPost:
		return c.stmtPost(ctx, f)
	case phStmtAuth:
		return c.stmtAuthorise(ctx, f)
	case phStmtPoll:
		return c.stmtPoll(ctx, f)
	case phStmtRedir:
		return c.stmtRedirect(f, in)
	case phStmtStatus:
		return c.stmtStatus(ctx, f)
	case phStmtDownload:
		return c.stmtDownload(ctx, f)
	}
	return nil, false, fmt.Errorf("swedbank: unknown flow phase %q", f.Phase)
}

func waitStep(f *flow, userAction bool, d time.Duration) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepWait, NeedsUser: userAction, Challenge: f.Challenge, Message: f.Message, WaitFor: d}
}

// ---- login: redirect ----

func (c *client) loginRedirectStart(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	f.OAuthState = c.cfg.ID(obsdk.IDState)
	q := url.Values{
		"bic": {c.bic}, "client_id": {c.cfg.Credentials.ClientID}, "response_type": {"code"},
		"scope": {c.scope()}, "redirect_uri": {f.RedirectURL}, "state": {f.OAuthState},
	}
	r, err := c.do(ctx, req{op: opAuthorize, method: http.MethodGet, path: "/psd2/authorize", query: q, noRedirect: true})
	if err != nil {
		return nil, false, err
	}
	switch r.status {
	case 301, 302, 303, 307, 308:
		loc := r.header.Get("Location")
		if loc == "" {
			return nil, false, fmt.Errorf("swedbank: authorize redirect without Location header")
		}
		f.AuthURL, f.Phase = loc, phRedirectWait
		return redirectStep(f, "log in"), false, nil
	}
	return nil, false, c.apiErr(opAuthorize, r)
}

// redirectStep sends the user to f.AuthURL; purpose completes "Send the user
// to the bank to ...".
func redirectStep(f *flow, purpose string) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to the bank to " + purpose + ", then pass the callback URL to Resume."}
}

func (c *client) loginRedirectWait(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, bool, error) {
	if in.Callback == "" {
		return redirectStep(f, "log in"), false, nil
	}
	p, err := callback.Parse(in.Callback)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if code, desc, failed := p.Error(); failed {
		return nil, false, authFailed("login was not completed (%s: %s)", code, desc)
	}
	if st := p.Get("state"); f.OAuthState != "" && st != f.OAuthState {
		return nil, false, authFailed("callback state does not match the login that was started")
	}
	code := p.Get("access_code", "code")
	if code == "" {
		return nil, false, fmt.Errorf("%w: callback has no access_code", obsdk.ErrInvalidRequest)
	}
	s, err := c.exchangeCode(ctx, code, f.RedirectURL)
	if err != nil {
		return nil, false, err
	}
	s.Meta["approach"] = methodRedirect
	f.Session, f.Phase = s, phAllStart
	return nil, true, nil
}

// ---- login: decoupled ----

// AuthMethods lists the decoupled login methods the bank currently offers.
// It needs no user context.
func (c *client) AuthMethods(ctx context.Context) ([]obsdk.AuthMethod, error) {
	r, err := c.do(ctx, req{
		op: opAuthMethods, method: http.MethodGet, path: "/psd2/v5/available-authentication-methods",
		query:  url.Values{"bic": {c.bic}, "apiKey": {c.cfg.Credentials.ClientID}},
		header: map[string]string{"TPP-Redirect-Preferred": "false"},
	})
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, c.apiErr(opAuthMethods, r)
	}
	var b struct {
		Methods []authObject `json:"authenticationMethods"`
	}
	if err := json.Unmarshal(r.body, &b); err != nil {
		return nil, fmt.Errorf("swedbank: unreadable authentication methods: %w", err)
	}
	out := make([]obsdk.AuthMethod, 0, len(b.Methods))
	for _, m := range b.Methods {
		out = append(out, obsdk.AuthMethod{ID: m.ID, Name: m.Type, Approach: methodDecoupled})
	}
	return out, nil
}

func (c *client) loginMethod(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	if f.Values["auth_method"] != "" {
		f.Phase = phFields
		return nil, true, nil
	}
	methods, err := c.AuthMethods(ctx)
	if err != nil {
		return nil, false, err
	}
	switch len(methods) {
	case 0:
		return nil, false, fmt.Errorf("%w: the bank offers no decoupled login methods", obsdk.ErrUnsupported)
	case 1:
		f.Values["auth_method"] = methods[0].ID
		f.Phase = phFields
		return nil, true, nil
	}
	opts := make([]obsdk.Option, len(methods))
	for i, m := range methods {
		opts[i] = obsdk.Option{Value: m.ID, Label: m.Name}
	}
	return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "Choose how to log in.",
		Fields: []obsdk.Field{{Key: "auth_method", Label: "Login method", Kind: obsdk.FieldSelect, Required: true, Options: opts}}}, false, nil
}

// methodFields are the per-method PSU fields (Baltic countries). In Sweden the
// bank identifies the user through the app, so nothing is needed.
func (c *client) methodFields(method string) []obsdk.Field {
	if !isBaltic(c.target.Country) {
		return nil
	}
	if method == "MOBILE_ID" {
		return []obsdk.Field{{Key: "phone_number", Label: "Phone number", Kind: obsdk.FieldText, Required: true}}
	}
	return []obsdk.Field{{Key: "personal_id", Label: "Personal identification number", Kind: obsdk.FieldText, Required: true}}
}

func (c *client) loginFields(f *flow) (*obsdk.Step, bool, error) {
	var need []obsdk.Field
	if isBaltic(c.target.Country) {
		need = append(need, obsdk.Field{Key: "psu_id", Label: "Internet bank user ID", Kind: obsdk.FieldText, Required: true})
	}
	need = append(need, c.methodFields(f.Values["auth_method"])...)
	var missing []obsdk.Field
	for _, fl := range need {
		if fl.Required && f.Values[fl.Key] == "" {
			missing = append(missing, fl)
		}
	}
	if len(missing) > 0 {
		return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "The bank needs a few details to start the login.", Fields: missing}, false, nil
	}
	f.Phase = phPost
	return nil, true, nil
}

func psuData(vals map[string]string) map[string]string {
	d := map[string]string{}
	if v := vals["personal_id"]; v != "" {
		d["personalID"] = v
	}
	if v := vals["phone_number"]; v != "" {
		d["phoneNumber"] = v
	}
	return d
}

func (c *client) loginPost(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	body := map[string]any{
		"authenticationMethodId": f.Values["auth_method"], "clientID": c.cfg.Credentials.ClientID,
		"redirectUri": f.RedirectURL, "scope": c.scope(),
	}
	if d := psuData(f.Values); len(d) > 0 {
		body["psuData"] = d
	}
	hdr := map[string]string{"PSU-ID": f.Values["psu_id"], "PSU-IP-Address": f.PSU.IP, "PSU-CORPORATE-ID": f.PSU.CorporateID}
	if f.Values["qr_code"] == "true" {
		hdr["Qr-Code-Required"] = "true"
	}
	r, err := c.do(ctx, req{
		op: opDecoupled, method: http.MethodPost, path: "/psd2/v5/authorize-decoupled", body: body, header: hdr,
		query: url.Values{"bic": {c.bic}, "client_id": {c.cfg.Credentials.ClientID}, "apiKey": {c.cfg.Credentials.ClientID}},
	})
	if err != nil {
		return nil, false, err
	}
	if r.status == http.StatusBadRequest && !f.Retried && strings.Contains(string(r.body), "Other login session is ongoing") {
		f.Retried = true // the spec says repeating the request terminates the stale session
		return nil, true, nil
	}
	if r.status != http.StatusCreated {
		return nil, false, c.apiErr(opDecoupled, r)
	}
	var b struct {
		AuthorizeID string          `json:"authorizeId"`
		Links       map[string]link `json:"_links"`
		Challenge   *challengeData  `json:"challengeData"`
		PSUMessage  string          `json:"psuMessage"`
	}
	if err := json.Unmarshal(r.body, &b); err != nil || b.AuthorizeID == "" {
		return nil, false, fmt.Errorf("swedbank: unreadable authorize-decoupled response")
	}
	// The login API lives under /psd2 in both environments, but the sandbox's
	// scaStatus link says /sandbox/v5/..., which answers 404 (seen 2026-10-13).
	f.PollPath = strings.Replace(b.Links["scaStatus"].Href, "/sandbox/v5/authorize-decoupled/", "/psd2/v5/authorize-decoupled/", 1)
	if f.PollPath == "" {
		f.PollPath = "/psd2/v5/authorize-decoupled/authorize/" + b.AuthorizeID
	}
	f.Challenge, f.Message = c.challenge(b.Challenge, ""), b.PSUMessage
	f.Phase = phPoll
	return waitStep(f, true, pollInterval), false, nil
}

type pollResponse struct {
	Code   string `json:"authorizationCode"`
	Status string `json:"scaStatus"`
}

func (c *client) loginPoll(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	r, err := c.do(ctx, req{
		op: opDecoupled, method: http.MethodGet, path: f.PollPath,
		query: url.Values{"bic": {c.bic}, "client_id": {c.cfg.Credentials.ClientID}, "apiKey": {c.cfg.Credentials.ClientID}},
	})
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusOK {
		return nil, false, c.apiErr(opDecoupled, r)
	}
	return c.afterAuthorizePoll(ctx, f, r)
}

func (c *client) afterAuthorizePoll(ctx context.Context, f *flow, r *resp) (*obsdk.Step, bool, error) {
	var p pollResponse
	_ = json.Unmarshal(r.body, &p)
	if p.Code != "" {
		s, err := c.exchangeCode(ctx, p.Code, f.RedirectURL)
		if err != nil {
			return nil, false, err
		}
		s.Meta["auth_method"], s.Meta["approach"] = f.Values["auth_method"], methodDecoupled
		f.Session, f.Phase = s, phAllStart
		return nil, true, nil
	}
	msgs := parseTPP(r.body)
	if hasCode(msgs, "MISSING_BANK_ID") {
		f.Phase = phBankID
		return nil, true, nil
	}
	if p.Status == "failed" {
		return nil, false, authFailed("login failed or was cancelled in the app: %s", tppSummary(msgs))
	}
	return waitStep(f, true, pollInterval), false, nil
}

// loginBankID handles Swedish users with engagements in several banks.
func (c *client) loginBankID(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	if v := f.Values["bank_id"]; v != "" {
		delete(f.Values, "bank_id")
		r, err := c.do(ctx, req{
			op: opDecoupled, method: http.MethodPut, path: f.PollPath, body: map[string]any{"psuData": map[string]string{"bankID": v}},
			query: url.Values{"bic": {c.bic}, "client_id": {c.cfg.Credentials.ClientID}, "apiKey": {c.cfg.Credentials.ClientID}},
		})
		if err != nil {
			return nil, false, err
		}
		if r.status != http.StatusOK {
			return nil, false, c.apiErr(opDecoupled, r)
		}
		f.Phase = phPoll
		var p pollResponse
		_ = json.Unmarshal(r.body, &p)
		if p.Code == "" {
			return waitStep(f, true, pollInterval), false, nil
		}
		return c.afterAuthorizePoll(ctx, f, r)
	}
	r, err := c.do(ctx, req{
		op: opDecoupled, method: http.MethodGet, path: "/psd2/available-bankids",
		query: url.Values{"apiKey": {c.cfg.Credentials.ClientID}, "bic": {c.bic}},
	})
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusOK {
		return nil, false, c.apiErr(opDecoupled, r)
	}
	var b struct {
		Banks []struct {
			ID   string `json:"bankID"`
			Name string `json:"name"`
		} `json:"availableBanks"`
	}
	if err := json.Unmarshal(r.body, &b); err != nil || len(b.Banks) == 0 {
		return nil, false, fmt.Errorf("swedbank: no bank ids available")
	}
	opts := make([]obsdk.Option, len(b.Banks))
	for i, x := range b.Banks {
		opts[i] = obsdk.Option{Value: x.ID, Label: x.Name}
	}
	return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "You have accounts in several banks. Which one do you want to connect?",
		Fields: []obsdk.Field{{Key: "bank_id", Label: "Bank", Kind: obsdk.FieldSelect, Required: true, Options: opts}}}, false, nil
}
