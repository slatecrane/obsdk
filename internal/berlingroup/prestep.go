package berlingroup

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
)

// PreStep describes the "OAuth2 as a pre-step" the Berlin Group standard
// allows and Redsys requires: before a consent or payment is created, the
// user logs in at the bank in an authorisation-code flow with PKCE, and every
// XS2A request afterwards (the consent and payment requests, their status,
// the account reads) carries the access token. The consent or payment is
// then approved as usual, normally with a second redirect.
//
// The token is the user's session: Connect returns it with the consent, and
// payment steps return it too, because reading or cancelling a payment needs
// it (PaymentCallOptions.Session). PaymentRequest.Session reuses one whose
// scope covers payments, without a new login.
type PreStep struct {
	// URL returns the OAuth root for a target and institution; the
	// authorisation and token endpoints are URL+"/authorize" and
	// URL+"/token". Config.Extra "oauth_url" overrides it.
	URL func(env obsdk.Env, t obsdk.Target, institution string) string

	// AISScope and PISScope are the scopes asked for by Connect and by
	// payments. Empty means "AIS" and "PIS".
	AISScope, PISScope string

	// ClientID returns the OAuth client id. Nil uses Credentials.ClientID.
	ClientID func(cfg obsdk.Config) string
}

// paramOAuthURL overrides PreStep.URL (tests, proxies).
const paramOAuthURL = "oauth_url"

func (c *client) preStepClientID() string {
	if ps := c.p.PreStep; ps != nil && ps.ClientID != nil {
		return ps.ClientID(c.cfg)
	}
	return c.cfg.Credentials.ClientID
}

func (c *client) preStepScope(op string) string {
	ps := c.p.PreStep
	if op == flowConnect {
		return firstNonEmpty(ps.AISScope, "AIS")
	}
	return firstNonEmpty(ps.PISScope, "PIS")
}

// create makes the consent or payment of a flow, after the pre-step when the
// bank wants one and the flow has no token yet.
func (c *client) create(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	if c.p.PreStep != nil {
		if f.Session == nil {
			return c.startPreStep(f)
		}
		c = c.withBearer(f.Session.AccessToken)
	}
	if f.Op == flowConnect {
		return c.createConsent(ctx, f, in)
	}
	return c.createPayment(ctx, f, in)
}

// startPreStep sends the user to the bank's OAuth authorisation endpoint.
func (c *client) startPreStep(f *flow) (*obsdk.Step, error) {
	clientID := c.preStepClientID()
	if clientID == "" {
		return nil, &obsdk.ConfigError{Bank: c.bank(), Env: c.cfg.Env, Missing: []string{"client_id"}}
	}
	if f.RedirectURL == "" {
		var err error
		if f.RedirectURL, err = c.redirectURL(""); err != nil {
			return nil, err
		}
	}
	root := strings.TrimRight(firstNonEmpty(c.cfg.Param(paramOAuthURL), c.p.PreStep.URL(c.cfg.Env, c.target, c.inst)), "/")
	if root == "" {
		return nil, &obsdk.ConfigError{Bank: c.bank(), Env: c.cfg.Env, Missing: []string{paramOAuthURL}}
	}
	f.Verifier, f.OAuthState, f.TokenURL = c.newVerifier(), c.cfg.ID(idState), root+"/token"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"scope":                 {c.preStepScope(f.Op)},
		"state":                 {f.OAuthState},
		"redirect_uri":          {f.RedirectURL},
		"code_challenge":        {pkceChallenge(f.Verifier)},
		"code_challenge_method": {"S256"},
	}
	// Spaces between scopes as %20, as the hub's examples show.
	f.SCARedirect = root + "/authorize?" + strings.ReplaceAll(q.Encode(), "+", "%20")
	f.OAuth, f.PreStep, f.Need = true, true, needRedirect
	return c.pause(f, &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.SCARedirect},
		Message: fmt.Sprintf("Send the user to %s to log in, then pass the callback URL to Resume.", c.p.Info.Name)})
}

// finishPreStep turns the exchanged code into the flow's session and goes
// on to create the consent or payment.
func (c *client) finishPreStep(ctx context.Context, f *flow, tok *tokenResponse) (*obsdk.Step, error) {
	s := c.newSession(f.Approach)
	s.Scope = c.preStepScope(f.Op)
	applyToken(s, tok, f.TokenURL)
	s.Touch(c.now())
	f.Session = s
	f.PreStep, f.OAuth, f.SCARedirect, f.OAuthState, f.Verifier = false, false, "", "", ""
	return c.create(ctx, f, obsdk.StepInput{})
}

// newSession is a session for this client's bank, without consents.
func (c *client) newSession(approach string) *obsdk.Session {
	s := &obsdk.Session{
		Bank: c.bank(), Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: c.p.ID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{metaApproach: approach},
	}
	if c.inst != "" {
		s.Meta[metaInstitution] = c.inst
	}
	return s
}

// reusableSession returns a copy of a payment request's session when it can
// stand in for the pre-step: same bank and institution, a scope that covers
// payments, and a token that is valid or can be renewed.
func (c *client) reusableSession(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	if s == nil || c.p.PreStep == nil {
		return nil, nil
	}
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.Meta[metaInstitution] != c.inst || s.AccessToken == "" || !hasScope(s.Scope, c.preStepScope(flowPayment)) {
		return nil, nil
	}
	ns := s.Clone()
	if ns.AccessExpired(c.now()) {
		if ns.RefreshToken == "" {
			return nil, nil
		}
		if err := c.refreshToken(ctx, ns); err != nil {
			var re *obsdk.ReauthError
			if errors.As(err, &re) {
				return nil, nil // log in again
			}
			return nil, err
		}
		ns.Touch(c.now())
	}
	return ns, nil
}

func hasScope(scopes, want string) bool {
	for _, s := range strings.Fields(scopes) {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// renewToken refreshes a pre-step session's access token. Without a refresh
// token, an expired access token means logging in again.
func (c *client) renewToken(ctx context.Context, s *obsdk.Session) error {
	if s.RefreshToken == "" {
		if s.AccessExpired(c.now()) {
			return &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "token_expired"}}
		}
		return nil
	}
	if err := c.refreshToken(ctx, s); err != nil {
		var re *obsdk.ReauthError
		return &obsdk.RefreshError{Temporary: !errors.As(err, &re), Err: err}
	}
	s.Touch(c.now())
	return nil
}

// forPayment is the client for reading or cancelling a payment: with the
// pre-step, the session's token is needed.
func (c *client) forPayment(s *obsdk.Session) (*client, error) {
	if c.p.PreStep == nil {
		return c, nil
	}
	if s == nil {
		return nil, fmt.Errorf("%w: %s reads and cancels payments with the user's session (PaymentCallOptions.Session, from the payment's steps)",
			obsdk.ErrInvalidRequest, c.p.Info.Name)
	}
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" {
		return nil, &obsdk.ReauthError{Reason: "no_token"}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (refresh the session first)", obsdk.ErrAccessExpired)
	}
	return c.withBearer(s.AccessToken), nil
}
