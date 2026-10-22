package berlingroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// Operations a flow can be driving.
const (
	flowConnect = "connect"
	flowPayment = "payment"
	flowCancel  = "cancel"
)

// What a paused flow waits for.
const (
	needPSUID    = "psu_id"   // the login id, before the consent or payment is created
	needRedirect = "redirect" // the user is at the bank
	needInput    = "input"    // answers to an input step (login, method, TAN)
	needPoll     = "poll"     // decoupled approval in the bank's app
)

// Field keys of input steps.
const (
	fieldPSUID     = "psu_id"
	fieldPassword  = "password"
	fieldSCAMethod = "sca_method"
	fieldOTP       = "otp"
)

// pollInterval is how long a decoupled wait step asks the caller to wait.
const pollInterval = 3 * time.Second

const flowVersion = 1

// flow is the serialized state of a Connect, a payment approval or a
// cancellation. It holds no credentials: passwords and TANs are sent as soon
// as they arrive and never stored.
type flow struct {
	V        int    `json:"v"`
	Op       string `json:"op"`
	Approach string `json:"approach"`
	Need     string `json:"need"`

	RedirectURL string           `json:"redirect_url"`
	PSU         obsdk.PSUContext `json:"psu"` // PSU.ID is the PSU-ID header once known
	Language    string           `json:"language,omitempty"`
	Institution string           `json:"institution,omitempty"` // Profile.Institution value the resource lives at

	// The bank's steering links (API paths from /v1/ on), its redirect URL,
	// and where the authorisation stands.
	Links       map[string]string `json:"links,omitempty"`
	SCARedirect string            `json:"sca_redirect,omitempty"`
	SCAStatus   string            `json:"sca_status,omitempty"`
	StatusPath  string            `json:"status_path,omitempty"` // the resource's status
	Methods     []scaMethod       `json:"methods,omitempty"`
	Challenge   *challengeData    `json:"challenge,omitempty"`
	PSUMessage  string            `json:"psu_message,omitempty"`

	// OAuth SCA approach: SCARedirect is then the authorisation URL, and the
	// callback carries a code. Verifier is the PKCE code verifier (secret).
	OAuth      bool           `json:"oauth,omitempty"`
	OAuthState string         `json:"oauth_state,omitempty"`
	Verifier   string         `json:"verifier,omitempty"`
	TokenURL   string         `json:"token_url,omitempty"`
	token      *tokenResponse // the exchanged code, only within the Resume that got it

	// OAuth pre-step (Profile.PreStep): PreStep while the user logs in;
	// Session once the token is there (secret), sent on every request.
	PreStep bool           `json:"pre_step,omitempty"`
	Session *obsdk.Session `json:"session,omitempty"`
	// PreStep.CreateOnly: the token between the login and the creating
	// request, within one Resume (secret).
	CreateToken string `json:"create_token,omitempty"`

	// Connect.
	Caps       []obsdk.Capability `json:"caps,omitempty"`
	IBANs      []string           `json:"ibans,omitempty"`
	ValidUntil string             `json:"valid_until,omitempty"`
	ConsentID  string             `json:"consent_id,omitempty"`

	// Payments and cancellations.
	Pay     *payState       `json:"pay,omitempty"`
	PayBody json.RawMessage `json:"pay_body,omitempty"` // built request, kept while the PSU-ID is asked for first
	PayXML  []byte          `json:"pay_xml,omitempty"`  // the same for pain.001 bodies (Profile.PaymentXML)
}

type scaMethod struct {
	Type    string `json:"authenticationType"`
	Version string `json:"authenticationVersion,omitempty"`
	ID      string `json:"authenticationMethodId"`
	Name    string `json:"name,omitempty"`
	Explain string `json:"explanation,omitempty"`
}

func (m scaMethod) label() string {
	return firstNonEmpty(m.Name, m.Explain, m.Type, m.ID)
}

type challengeData struct {
	Image          string   `json:"image,omitempty"` // base64
	Data           []string `json:"data,omitempty"`
	ImageLink      string   `json:"imageLink,omitempty"`
	OTPMaxLength   int      `json:"otpMaxLength,omitempty"`
	OTPFormat      string   `json:"otpFormat,omitempty"` // "characters" or "integer"
	AdditionalInfo string   `json:"additionalInformation,omitempty"`
}

// scaResponse is the part of consent, payment, cancellation and
// authorisation responses that steers the approval.
type scaResponse struct {
	ConsentID         string         `json:"consentId"`
	ConsentStatus     string         `json:"consentStatus"`
	PaymentID         string         `json:"paymentId"`
	TransactionStatus string         `json:"transactionStatus"`
	SCAStatus         string         `json:"scaStatus"`
	SCAMethods        []scaMethod    `json:"scaMethods"`
	ChosenSCAMethod   *scaMethod     `json:"chosenScaMethod"`
	ChallengeData     *challengeData `json:"challengeData"`
	PSUMessage        string         `json:"psuMessage"`
	Links             links          `json:"_links"`
}

// Steering link names, by what they ask for.
var (
	linksPSUAuth = []string{"startAuthorisationWithPsuAuthentication", "updatePsuAuthentication"}
	linksPSUID   = []string{"startAuthorisationWithPsuIdentification", "updatePsuIdentification"}
	linksMethod  = []string{"startAuthorisationWithAuthenticationMethodSelection", "selectAuthenticationMethod"}
	linksOTP     = []string{"startAuthorisationWithTransactionAuthorisation", "authoriseTransaction"}
	linksStart   = []string{"startAuthorisation"}
	linksEncrypt = []string{"startAuthorisationWithEncryptedPsuAuthentication", "updateEncryptedPsuAuthentication"}
	actionLinks  = concat(linksPSUAuth, linksPSUID, linksMethod, linksOTP, linksStart, linksEncrypt, linksOAuth, []string{"scaRedirect", "redirect"})
)

func concat(ls ...[]string) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l...)
	}
	return out
}

func (f *flow) link(names ...string) (name, path string) {
	for _, n := range names {
		if p := f.Links[n]; p != "" {
			return n, p
		}
	}
	return "", ""
}

// absorb takes the steering part of a response. A response that carries
// action links replaces the previous ones (they describe the next step); one
// without links (a status read) leaves them alone.
func (f *flow) absorb(r *scaResponse, versions ...string) error {
	if f.Links == nil {
		f.Links = map[string]string{}
	}
	if len(r.Links) > 0 {
		for _, n := range actionLinks {
			delete(f.Links, n)
		}
		f.SCARedirect, f.OAuth = "", false
		for n, l := range r.Links {
			if l == "" {
				continue
			}
			switch {
			case n == "scaRedirect" || n == "redirect" || isOAuthLink(n):
				// Outside the XS2A API: kept as sent. SIBS names the redirect
				// link "redirect".
				if n == "scaRedirect" || n == "redirect" {
					n = "scaRedirect"
					f.SCARedirect = string(l)
				}
				f.Links[n] = string(l)
				continue
			case n == "self" || n == "account" || n == "download" || n == "confirmation":
				continue
			}
			p, err := apiPath(string(l), versions...)
			if err != nil {
				return err
			}
			if n == "status" {
				f.StatusPath = p
				continue
			}
			f.Links[n] = p
		}
	}
	if r.SCAStatus != "" {
		f.SCAStatus = r.SCAStatus
	}
	if len(r.SCAMethods) > 0 {
		f.Methods = r.SCAMethods
	}
	if r.ChosenSCAMethod != nil {
		f.Methods = []scaMethod{*r.ChosenSCAMethod}
	}
	if r.ChallengeData != nil {
		f.Challenge = r.ChallengeData
	}
	if r.PSUMessage != "" {
		f.PSUMessage = r.PSUMessage
	}
	return nil
}

func authFailed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", obsdk.ErrAuthFailed, fmt.Sprintf(format, args...))
}

// pause encodes the flow into a step.
func (c *client) pause(f *flow, st *obsdk.Step) (*obsdk.Step, error) {
	f.V = flowVersion
	s, err := flowstate.Encode(f)
	if err != nil {
		return nil, err
	}
	st.State = s
	if f.Session != nil && st.Session == nil {
		st.Session = f.Session.Clone()
	}
	if f.Pay != nil && f.Pay.ID != "" && st.Payment == nil {
		if st.Payment, err = c.paymentOf(f.Pay, "", nil); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// Resume continues a Connect, a payment approval or a cancellation.
func (c *client) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	var f flow
	if err := flowstate.Decode(state, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
	}
	if f.V != flowVersion {
		return nil, fmt.Errorf("%w: unsupported flow state version %d", obsdk.ErrInvalidRequest, f.V)
	}
	c, err := c.forInstitution(f.Institution)
	if err != nil {
		return nil, err
	}
	if f.Session != nil {
		c = c.withBearer(f.Session.AccessToken)
	}
	st, err := c.resume(ctx, &f, in)
	if err == nil && st.Kind == obsdk.StepDone && st.Session == nil && f.Session != nil {
		st.Session = f.Session.Clone()
	}
	return st, c.wrapFlowErr(&f, err)
}

// wrapFlowErr attaches the payment to errors once the bank created it, and
// the session once the pre-step made one.
func (c *client) wrapFlowErr(f *flow, err error) error {
	if err == nil {
		return nil
	}
	var sess *obsdk.Session
	if f.Session != nil {
		sess = f.Session.Clone()
	}
	if fe, ok := err.(*obsdk.FlowError); ok {
		if fe.Session == nil {
			fe.Session = sess
		}
		return fe
	}
	var pay *obsdk.Payment
	if f.Pay != nil && f.Pay.ID != "" {
		pay, _ = c.paymentOf(f.Pay, "", nil)
	}
	if pay == nil && sess == nil {
		return err
	}
	return &obsdk.FlowError{Session: sess, Payment: pay, Err: err}
}

func (c *client) resume(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	switch f.Need {
	case needPSUID:
		id := strings.TrimSpace(in.Values[fieldPSUID])
		if id == "" {
			return c.pause(f, psuIDStep())
		}
		f.PSU.ID = id
		return c.create(ctx, f, in)
	case needRedirect:
		if in.Callback == "" {
			return c.pause(f, c.redirectStep(f))
		}
		if f.OAuth {
			return c.afterOAuth(ctx, f, in.Callback)
		}
		if p, err := callback.Parse(in.Callback); err == nil {
			if code, desc, failed := p.Error(); failed {
				return nil, authFailed("%s was not approved at the bank (%s%s)", f.subject(), code, prefixed(": ", desc))
			}
		}
		return c.afterRedirect(ctx, f)
	case needInput, needPoll:
		return c.advance(ctx, f, in)
	}
	return nil, fmt.Errorf("%w: unknown flow step %q", obsdk.ErrInvalidRequest, f.Need)
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

func (f *flow) subject() string {
	switch f.Op {
	case flowPayment:
		return "the payment"
	case flowCancel:
		return "the cancellation"
	}
	return "access"
}

func psuIDStep() *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true,
		Message: "Enter the online banking login (PSU-ID).",
		Fields:  []obsdk.Field{{Key: fieldPSUID, Label: "Online banking login", Kind: obsdk.FieldText, Required: true}}}
}

func (c *client) redirectStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepRedirect, NeedsUser: true, Redirect: &obsdk.Redirect{URL: f.SCARedirect},
		Message: fmt.Sprintf("Send the user to %s to approve %s, then pass the callback URL to Resume.", c.p.Info.Name, f.subject())}
}

// advance drives the authorisation from the current links until the user has
// to act or it is finished. Input values are used once. A decoupled wait reads
// the scaStatus once per Resume.
func (c *client) advance(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	vals := in.Values
	for i := 0; i < 10; i++ {
		switch f.SCAStatus {
		case "finalised", "exempted":
			return c.finish(ctx, f)
		case "failed":
			return nil, authFailed("%s was not approved (scaStatus failed)", f.subject())
		}
		if _, l := f.link(linksOAuth...); l != "" && f.SCARedirect == "" {
			if f.RedirectURL == "" {
				return nil, fmt.Errorf("%w: %s asked for an OAuth approval, which needs a redirect URL; use the redirect method", obsdk.ErrUnsupported, c.p.Info.Name)
			}
			if err := c.startOAuth(ctx, f, l); err != nil {
				return nil, err
			}
		}
		if c.wantsFixedOAuth(f) {
			if err := c.startFixedOAuth(f); err != nil {
				return nil, err
			}
		}
		if f.SCARedirect != "" {
			// Whatever was preferred, a redirect link means the bank chose it.
			f.Need = needRedirect
			return c.pause(f, c.redirectStep(f))
		}
		if n, _ := f.link(linksEncrypt...); n != "" {
			return nil, fmt.Errorf("%w: %s asked for encrypted PSU authentication, which is not supported", obsdk.ErrUnsupported, c.p.Info.Name)
		}
		if v := strings.TrimSpace(vals[fieldPSUID]); v != "" {
			f.PSU.ID = v
		}

		var r *scaResponse
		var err error
		if n, p := f.link(linksPSUAuth...); n != "" {
			pw := vals[fieldPassword]
			if pw == "" || f.PSU.ID == "" {
				return c.pause(f, c.loginStep(f))
			}
			vals = nil
			r, err = c.authorise(ctx, f, n, p, map[string]any{"psuData": map[string]string{"password": pw}})
		} else if n, p := f.link(linksPSUID...); n != "" {
			if f.PSU.ID == "" {
				f.Need = needInput
				return c.pause(f, psuIDStep())
			}
			vals = nil
			r, err = c.authorise(ctx, f, n, p, map[string]any{})
		} else if n, p := f.link(linksMethod...); n != "" {
			id := vals[fieldSCAMethod]
			if id == "" && len(f.Methods) == 1 {
				id = f.Methods[0].ID
			}
			if id == "" {
				return c.pause(f, c.methodStep(f))
			}
			vals = nil
			r, err = c.authorise(ctx, f, n, p, map[string]any{"authenticationMethodId": id})
		} else if n, p := f.link(linksOTP...); n != "" {
			otp := strings.TrimSpace(vals[fieldOTP])
			if otp == "" {
				return c.pause(f, c.otpStep(f))
			}
			vals = nil
			r, err = c.authorise(ctx, f, n, p, map[string]any{"scaAuthenticationData": otp})
		} else if n, p := f.link(linksStart...); n != "" {
			r, err = c.authorise(ctx, f, n, p, map[string]any{})
		} else if _, p := f.link("scaStatus"); p != "" {
			if f.Need != needPoll || i > 0 {
				f.Need = needPoll
				return c.pause(f, c.waitStep(f))
			}
			r, err = c.readSCAStatus(ctx, f, p)
		} else {
			// No steering links left: the resource's own status decides.
			return c.finish(ctx, f)
		}
		if err != nil {
			return nil, err
		}
		if err := f.absorb(r, c.p.linkVersions()...); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("berlingroup: %s: the authorisation did not settle", c.bank())
}

// authorise calls a steering link: start* links create an authorisation
// (POST), the others update the current one (PUT).
func (c *client) authorise(ctx context.Context, f *flow, name, path string, body map[string]any) (*scaResponse, error) {
	method := http.MethodPut
	if strings.HasPrefix(name, "start") {
		method = http.MethodPost
	}
	h := psuHeaders(&f.PSU)
	c.redirectHeaders(f, h)
	res, err := c.do(ctx, req{op: opAuthorise, method: method, path: path, body: body, header: h})
	if err != nil {
		return nil, err
	}
	if res.status >= 300 {
		return nil, c.apiErr(opAuthorise, res)
	}
	var r scaResponse
	if err := json.Unmarshal(res.body, &r); err != nil {
		return nil, fmt.Errorf("berlingroup: unreadable authorisation response (HTTP %d)", res.status)
	}
	return &r, nil
}

// redirectHeaders adds the approach preference and the redirect URIs to a
// request that creates a resource or an authorisation.
func (c *client) redirectHeaders(f *flow, h map[string]string) {
	h["TPP-Redirect-Preferred"] = fmt.Sprint(f.Approach == Redirect)
	if f.Approach == Decoupled {
		h["TPP-Decoupled-Preferred"] = "true"
	}
	if f.Approach == Redirect {
		h["TPP-Redirect-URI"] = f.RedirectURL
		if !c.p.NoNokRedirect {
			h["TPP-Nok-Redirect-URI"] = nokURL(f.RedirectURL)
		}
	}
}

// nokURL is the redirect URL with error=access_denied, so a refusal at the
// bank reaches Resume as a callback error.
func nokURL(u string) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	if i := strings.Index(u, "#"); i >= 0 {
		return u[:i] + sep + "error=access_denied" + u[i:]
	}
	return u + sep + "error=access_denied"
}

func (c *client) readSCAStatus(ctx context.Context, f *flow, path string) (*scaResponse, error) {
	res, err := c.do(ctx, req{op: opAuthorise, method: http.MethodGet, path: path, header: psuHeaders(&f.PSU)})
	if err != nil {
		return nil, err
	}
	if res.status >= 300 {
		return nil, c.apiErr(opAuthorise, res)
	}
	var r scaResponse
	if err := json.Unmarshal(res.body, &r); err != nil {
		return nil, fmt.Errorf("berlingroup: unreadable scaStatus response (HTTP %d)", res.status)
	}
	if r.SCAStatus == "" {
		return nil, errNoSCAStatus
	}
	return &r, nil
}

// errNoSCAStatus is a scaStatus read that answered without one (Bankart's
// sandbox: {}); after a redirect the resource's own status decides instead.
var errNoSCAStatus = errors.New("berlingroup: the scaStatus response has no scaStatus")

// afterRedirect checks the authorisation once the user is back: the
// scaStatus when the bank gave a link to it, then the resource itself.
func (c *client) afterRedirect(ctx context.Context, f *flow) (*obsdk.Step, error) {
	if _, p := f.link("scaStatus"); p != "" {
		r, err := c.readSCAStatus(ctx, f, p)
		var ae *obsdk.APIError
		if err != nil && f.Op == flowCancel && asAPIError(err, &ae) && (ae.Status == http.StatusNotFound || ae.Status == http.StatusForbidden) {
			// Redsys's sandbox links a cancellation's scaStatus it doesn't
			// know (404, then 403 HUB076 once cancelled); the payment's
			// status settles a cancellation anyway.
			return c.finish(ctx, f)
		}
		if errors.Is(err, errNoSCAStatus) {
			return c.finish(ctx, f)
		}
		if err != nil {
			return nil, err
		}
		f.SCAStatus = r.SCAStatus
		if r.SCAStatus == "failed" {
			return nil, authFailed("%s was not approved at the bank (scaStatus failed)", f.subject())
		}
	}
	return c.finish(ctx, f)
}

func (c *client) finish(ctx context.Context, f *flow) (*obsdk.Step, error) {
	switch f.Op {
	case flowConnect:
		return c.finishConnect(ctx, f)
	case flowPayment:
		return c.finishPayment(ctx, f)
	case flowCancel:
		return c.finishCancel(ctx, f)
	}
	return nil, fmt.Errorf("%w: unknown flow %q", obsdk.ErrInvalidRequest, f.Op)
}

// ---- input steps ----

func (c *client) loginStep(f *flow) *obsdk.Step {
	f.Need = needInput
	st := &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true,
		Message: fmt.Sprintf("Enter the %s online banking login.", c.p.Info.Name)}
	if f.PSU.ID == "" {
		st.Fields = append(st.Fields, obsdk.Field{Key: fieldPSUID, Label: "Online banking login", Kind: obsdk.FieldText, Required: true})
	}
	st.Fields = append(st.Fields, obsdk.Field{Key: fieldPassword, Label: "Password / PIN", Kind: obsdk.FieldSecret, Required: true})
	return st
}

func (c *client) methodStep(f *flow) *obsdk.Step {
	f.Need = needInput
	fl := obsdk.Field{Key: fieldSCAMethod, Label: "Authentication method", Kind: obsdk.FieldSelect, Required: true}
	for _, m := range f.Methods {
		fl.Options = append(fl.Options, obsdk.Option{Value: m.ID, Label: m.label()})
	}
	return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "Choose how to confirm.", Fields: []obsdk.Field{fl}}
}

func (c *client) otpStep(f *flow) *obsdk.Step {
	f.Need = needInput
	st := &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true,
		Message: firstNonEmpty(f.PSUMessage, "Enter the confirmation code (TAN).")}
	fl := obsdk.Field{Key: fieldOTP, Label: "Confirmation code (TAN)", Kind: obsdk.FieldOTP, Required: true}
	if ch := f.Challenge; ch != nil {
		if ch.OTPFormat == "integer" {
			fl.Pattern = `^[0-9]+$`
			if ch.OTPMaxLength > 0 {
				fl.Pattern = fmt.Sprintf(`^[0-9]{1,%d}$`, ch.OTPMaxLength)
			}
		}
		// data carries what a TAN generator reads: the chipTAN flicker code
		// or HHD start code.
		st.Challenge = &obsdk.Challenge{Text: ch.AdditionalInfo, Code: strings.Join(ch.Data, "\n"), ImageURL: ch.ImageLink}
		if ch.ImageLink == "" && ch.Image != "" {
			st.Challenge.ImageURL = "data:image/png;base64," + ch.Image
		}
	}
	if len(f.Methods) == 1 {
		fl.Label = fmt.Sprintf("Confirmation code (%s)", f.Methods[0].label())
	}
	st.Fields = []obsdk.Field{fl}
	return st
}

func (c *client) waitStep(f *flow) *obsdk.Step {
	return &obsdk.Step{Kind: obsdk.StepWait, NeedsUser: true, WaitFor: pollInterval,
		Message: firstNonEmpty(f.PSUMessage, fmt.Sprintf("Approve %s in the %s app.", f.subject(), c.p.Info.Name))}
}
