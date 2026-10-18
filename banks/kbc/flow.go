package kbc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	// consentKind names the user's AIS consent in Session.Consents.
	consentKind = "ais"

	// KBC publishes no maximum validUntil; 90 days is the default and 180
	// the PSD2 ceiling we allow (docs/kbc.md).
	defaultConsentDays = 90
	maxConsentDays     = 180
	// frequencyPerDay is the PSD2 limit of unattended reads per day.
	frequencyPerDay = 4

	phRedirectWait = "redirect_wait"

	// valueIBAN optionally names the account the consent is for.
	valueIBAN = "iban"
	// idPKCE is the Config.NewID purpose for the PKCE code verifier.
	idPKCE = "pkce"
)

// flow is the serialized state of a Connect.
type flow struct {
	Phase       string           `json:"phase"`
	RedirectURL string           `json:"redirect_url"`
	OAuthState  string           `json:"oauth_state"`
	Verifier    string           `json:"verifier"` // PKCE code_verifier; secret
	ConsentID   string           `json:"consent_id"`
	ValidUntil  string           `json:"valid_until"`
	IBAN        string           `json:"iban,omitempty"`
	AuthURL     string           `json:"auth_url"`
	PSU         obsdk.PSUContext `json:"psu"`
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// ---- consent ----

type accountRef struct {
	IBAN string `json:"iban"`
}

type consentRequest struct {
	Access                   map[string][]accountRef `json:"access"` // "balances", "transactions"
	RecurringIndicator       bool                    `json:"recurringIndicator"`
	ValidUntil               string                  `json:"validUntil"`
	FrequencyPerDay          int                     `json:"frequencyPerDay"`
	CombinedServiceIndicator bool                    `json:"combinedServiceIndicator"`
}

// consentBody asks for one account's balances and, unless only balances or
// accounts are wanted, its transactions. KBC supports one IBAN, or none: then
// the arrays are empty (a bank-offered consent) and the user picks the
// account on KBC's page.
func consentBody(caps []obsdk.Capability, iban, validUntil string) consentRequest {
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	tx := false
	for _, c := range caps {
		tx = tx || c == obsdk.CapTransactions || c == obsdk.CapTransactionsHistory
	}
	refs := []accountRef{}
	if iban != "" {
		refs = append(refs, accountRef{IBAN: iban})
	}
	access := map[string][]accountRef{"balances": refs}
	if tx {
		access["transactions"] = refs
	}
	return consentRequest{Access: access, RecurringIndicator: true, ValidUntil: validUntil, FrequencyPerDay: frequencyPerDay}
}

func validityDays(n int) int {
	switch {
	case n <= 0:
		return defaultConsentDays
	case n > maxConsentDays:
		return maxConsentDays
	}
	return n
}

// pkceChallenge is the S256 code challenge of a verifier (RFC 7636).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newVerifier derives a code verifier from two identifiers (two random UUIDs
// by default; Config.NewID keeps it reproducible in replays). Hashing gives
// the 43 characters RFC 7636 asks for, whatever the identifiers look like.
func (c *client) newVerifier() string {
	sum := sha256.Sum256([]byte(c.cfg.ID(idPKCE) + c.cfg.ID(idPKCE)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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

// Connect creates the consent and returns the redirect to KBC's authorisation
// page. The consent id travels in the OAuth scope (AIS:<consentId>).
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	if r.Method != "" && r.Method != "redirect" {
		return nil, fmt.Errorf("%w: KBC only supports the redirect method", obsdk.ErrInvalidRequest)
	}
	if r.PSU.IP == "" {
		return nil, fmt.Errorf("%w: KBC requires the user's IP address (ConnectRequest.PSU.IP)", obsdk.ErrInvalidRequest)
	}
	redirectURL, err := c.redirectURL(r.RedirectURL)
	if err != nil {
		return nil, err
	}
	iban := strings.ToUpper(strings.ReplaceAll(r.Values[valueIBAN], " ", ""))
	if iban != "" {
		if err := obsdk.ValidateIdentifier(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: iban}); err != nil {
			return nil, fmt.Errorf("%w: Values[%q] %v", obsdk.ErrInvalidRequest, valueIBAN, err)
		}
	}
	validUntil := c.now().UTC().AddDate(0, 0, validityDays(r.ConsentValidityDays)).Format("2006-01-02")
	body, err := json.Marshal(consentBody(r.Capabilities, iban, validUntil))
	if err != nil {
		return nil, err
	}
	h := psuHeaders(&r.PSU)
	h["TPP-Redirect-URI"] = redirectURL
	res, err := c.do(ctx, req{op: opConsent, method: http.MethodPost, path: "/consents", body: body, header: h})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opConsent, res)
	}
	var cr struct {
		ConsentStatus string `json:"consentStatus"`
		ConsentID     string `json:"consentId"`
	}
	if err := json.Unmarshal(res.body, &cr); err != nil || cr.ConsentID == "" {
		return nil, fmt.Errorf("kbc: unreadable consent response (HTTP %d)", res.status)
	}

	f := &flow{Phase: phRedirectWait, RedirectURL: redirectURL, OAuthState: c.cfg.ID(obsdk.IDState), Verifier: c.newVerifier(),
		ConsentID: cr.ConsentID, ValidUntil: validUntil, IBAN: iban, PSU: r.PSU}
	q := url.Values{
		"client_id": {c.cfg.Credentials.ClientID}, "redirect_uri": {redirectURL}, "response_type": {"code"},
		"scope": {"AIS:" + cr.ConsentID}, "state": {f.OAuthState},
		"code_challenge": {pkceChallenge(f.Verifier)}, "code_challenge_method": {"S256"},
		"mainCompany": {c.brand.mainCompany},
	}
	if c.brand.company != "" {
		q.Set("company", c.brand.company)
	}
	if l := strings.ToUpper(r.Language); l == "NL" || l == "FR" || l == "DE" || l == "EN" {
		q.Set("language", l)
	}
	f.AuthURL = c.authorize + "?" + q.Encode()
	return c.pause(f, redirectStep(f))
}

func redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.AuthURL},
		Message: "Send the user to KBC to approve access, then pass the callback URL to Resume."}
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
// lists the consented account) or a payment approval.
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
		// access_denied with "user cancelled" or "technical error"; for
		// invalid_scope and unauthorized_client KBC sends no state.
		return nil, authFailed("access was not approved (%s: %s)", code, desc)
	}
	if st := p.Get("state"); st != f.OAuthState {
		return nil, authFailed("callback state does not match the authorisation that was started")
	}
	code := p.Get("code")
	if code == "" {
		return nil, fmt.Errorf("%w: callback has no code", obsdk.ErrInvalidRequest)
	}
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.RedirectURL}, "code_verifier": {f.Verifier}})
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, fmt.Errorf("%w: code exchange rejected: %w", obsdk.ErrAuthFailed, c.apiErr(opToken, r))
	}
	s := &obsdk.Session{
		Bank: c.brand.bank, Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: c.integrationID(),
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{},
	}
	cons := obsdk.Consent{ID: f.ConsentID, Kind: consentKind, Status: "valid"}
	if t, err := time.Parse("2006-01-02", f.ValidUntil); err == nil {
		cons.ValidUntil = &t
	}
	s.Consents[consentKind] = cons
	c.applyToken(s, tr)

	accs, _, err := c.listAccounts(ctx, s, &f.PSU)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	cons = s.Consents[consentKind]
	for _, a := range accs {
		for _, id := range a.Identifiers {
			cons.Accounts = append(cons.Accounts, id.Value)
		}
	}
	s.Consents[consentKind] = cons
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

// applyToken stores a token response. KBC returns a new refresh token on each
// refresh, except near the end of the refresh token's life, when the current
// one stays usable until it expires.
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
	if d := seconds(tr.ExpiresIn); d > 0 {
		t := now.Add(d).UTC()
		s.AccessExpiresAt = &t
	}
	s.Touch(now)
}

// ---- refresh and disconnect ----

// Refresh renews the access token. Refresh tokens rotate: the old one stops
// working once the new session exists.
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
	if ns.Consents == nil {
		ns.Consents = map[string]obsdk.Consent{}
	}
	if ns.Meta == nil {
		ns.Meta = map[string]string{}
	}
	c.applyToken(ns, tr)
	return ns, nil
}

// Disconnect deletes the consent. KBC's specification lists no deletion
// endpoint; the Berlin Group DELETE /consents/{id} is tried, and anything but
// success is reported as a failure (the user can still revoke the access in
// KBC's own apps).
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
		res.Failed[consentKind] = "the session has no consent id to delete"
		return res, nil
	}
	r, err := c.do(ctx, req{op: opRevoke, method: http.MethodDelete, path: "/consents/" + url.PathEscape(cons.ID), bearer: s.AccessToken})
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
