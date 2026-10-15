package swedbank

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
)

// Phases of a resource's approval (consent, statement, payment, cancellation).
const (
	phSCA      = "sca"
	phSCAPoll  = "sca_poll"
	phSCARedir = "sca_redirect_wait"
)

// scaFlow is the approval of one resource, driven from the steering links the
// bank returned when the resource was created.
type scaFlow struct {
	Purpose string `json:"purpose"` // completes "Send the user to the bank to ...", e.g. "approve the payment"
	Subject string `json:"subject"` // for errors, e.g. "the payment"
	Op      string `json:"op"`
	After   string `json:"after"` // phase to continue with once approved (it checks the resource's status)

	// ConsentKind is sent as Consent-ID on approval calls; empty sends none
	// (consent and payment endpoints).
	ConsentKind string `json:"consent_kind,omitempty"`

	// PollAfterRedirect: after the user returns, check scaStatus before
	// After (Swedbank's advice for payments: authorisation status first).
	PollAfterRedirect bool `json:"poll_after_redirect,omitempty"`

	RedirectURL  string `json:"redirect_url,omitempty"`
	StartAuth    string `json:"start_auth,omitempty"`
	SelectPath   string `json:"select_path,omitempty"`
	ScaPath      string `json:"sca_path,omitempty"`
	ChosenMethod string `json:"chosen_method,omitempty"`
}

// scaLinks fills the approval links from a Berlin Group style _links object.
func (s *scaFlow) scaLinks(l map[string]link) {
	s.RedirectURL = l["scaRedirect"].Href
	s.ScaPath = l["scaStatus"].Href
	s.StartAuth = l["startAuthorisation"].Href
	if h := l["startAuthorisationWithAuthenticationMethodSelection"].Href; h != "" {
		s.SelectPath = h
	}
	if h := l["selectAuthenticationMethod"].Href; h != "" {
		s.SelectPath = h
	}
}

// startSCA moves the flow into the approval of a resource.
func startSCA(f *flow, s *scaFlow) (*obsdk.Step, bool, error) {
	f.SCA, f.Phase, f.CallbackSeen = s, phSCA, false
	return nil, true, nil
}

func (c *client) scaCall(ctx context.Context, f *flow, r req) (*resp, error) {
	if f.SCA.ConsentKind != "" {
		return c.aisCall(ctx, f.Session, f.SCA.ConsentKind, r, &f.PSU)
	}
	return c.callAuthed(ctx, f.Session, r, &f.PSU)
}

func (c *client) tppRedirectHeaders(f *flow) map[string]string {
	return map[string]string{
		"TPP-Redirect-Preferred": fmt.Sprint(f.Method == methodRedirect),
		"TPP-Redirect-URI":       f.RedirectURL,
	}
}

// scaStart picks the approval route the bank offered: a redirect, an
// explicit authorisation to create first, or a method to select for
// app-based (decoupled) approval.
func (c *client) scaStart(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	s := f.SCA
	switch {
	case s.RedirectURL != "":
		f.AuthURL, f.Phase = s.RedirectURL, phSCARedir
		return redirectStep(f, s.Purpose), false, nil
	case s.StartAuth != "": // explicit authorisation: create the sub-resource first
		r, err := c.scaCall(ctx, f, req{op: s.Op, method: http.MethodPost, path: s.StartAuth, header: c.tppRedirectHeaders(f)})
		if err != nil {
			return nil, false, err
		}
		if r.status != http.StatusOK && r.status != http.StatusCreated {
			return nil, false, c.apiErr(s.Op, r)
		}
		var b struct {
			Links  map[string]link `json:"_links"`
			Chosen *authObject     `json:"chosenScaMethod"`
		}
		_ = json.Unmarshal(r.body, &b)
		s.StartAuth = ""
		s.scaLinks(b.Links)
		if b.Chosen != nil {
			s.ChosenMethod = b.Chosen.ID
		}
		return nil, true, nil
	case s.SelectPath != "":
		return c.scaSelect(ctx, f)
	case s.ScaPath != "":
		f.Phase = phSCAPoll
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("swedbank: %s needs approval but the bank gave no way to give it", s.Subject)
}

// scaSelect picks the method and starts the app challenge.
func (c *client) scaSelect(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	s := f.SCA
	method := f.Values["auth_method"]
	if method == "" {
		method = s.ChosenMethod
	}
	if method == "" {
		return c.askMethod(ctx, f)
	}
	var missing []obsdk.Field
	for _, fl := range c.methodFields(method) {
		if fl.Required && f.Values[fl.Key] == "" {
			missing = append(missing, fl)
		}
	}
	if len(missing) > 0 {
		return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "The bank needs these details to ask for your approval.", Fields: missing}, false, nil
	}
	body := map[string]any{"authenticationMethodId": method}
	if d := psuData(f.Values); len(d) > 0 {
		body["psuData"] = d
	}
	hdr := map[string]string{}
	if f.Values["qr_code"] == "true" {
		hdr["Qr-Code-Required"] = "true"
	}
	r, err := c.scaCall(ctx, f, req{op: s.Op, method: http.MethodPut, path: s.SelectPath, body: body, header: hdr})
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusOK && r.status != http.StatusCreated {
		return nil, false, c.apiErr(s.Op, r)
	}
	var b struct {
		Links      map[string]link `json:"_links"`
		Challenge  *challengeData  `json:"challengeData"`
		PSUMessage string          `json:"psuMessage"`
	}
	_ = json.Unmarshal(r.body, &b)
	if l := b.Links["scaStatus"].Href; l != "" {
		s.ScaPath = l
	}
	s.SelectPath = ""
	f.Challenge, f.Message = c.challenge(b.Challenge, ""), b.PSUMessage
	f.Phase = phSCAPoll
	return waitStep(f, true, pollInterval), false, nil
}

// askMethod asks the user how to approve when nothing chose a method yet
// (a payment started without a decoupled login, for example).
func (c *client) askMethod(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	methods, err := c.AuthMethods(ctx)
	if err != nil {
		return nil, false, err
	}
	switch len(methods) {
	case 0:
		return nil, false, fmt.Errorf("%w: the bank offers no app-based approval methods", obsdk.ErrUnsupported)
	case 1:
		f.Values["auth_method"] = methods[0].ID
		return nil, true, nil
	}
	opts := make([]obsdk.Option, len(methods))
	for i, m := range methods {
		opts[i] = obsdk.Option{Value: m.ID, Label: m.Name}
	}
	return &obsdk.Step{Kind: obsdk.StepInputRequired, NeedsUser: true, Message: "Choose how to approve.",
		Fields: []obsdk.Field{{Key: "auth_method", Label: "Approval method", Kind: obsdk.FieldSelect, Required: true, Options: opts}}}, false, nil
}

func (c *client) scaPoll(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	s := f.SCA
	if s.ScaPath == "" {
		return nil, false, fmt.Errorf("swedbank: the bank gave no status link for the approval of %s", s.Subject)
	}
	r, err := c.scaCall(ctx, f, req{op: s.Op, method: http.MethodGet, path: s.ScaPath})
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusOK {
		return nil, false, c.apiErr(s.Op, r)
	}
	var b struct {
		Status string `json:"scaStatus"`
	}
	_ = json.Unmarshal(r.body, &b)
	switch b.Status {
	case "finalised":
		f.Phase = s.After
		return nil, true, nil
	case "failed":
		return nil, false, authFailed("approval of %s failed: %s", s.Subject, tppSummary(parseTPP(r.body)))
	}
	return waitStep(f, true, pollInterval), false, nil
}

func (c *client) scaRedirect(f *flow, in obsdk.StepInput) (*obsdk.Step, bool, error) {
	s := f.SCA
	if in.Callback == "" && !f.CallbackSeen {
		return redirectStep(f, s.Purpose), false, nil
	}
	if in.Callback != "" {
		// Swedbank returns the user from an approval without any parameters
		// (seen in the SE sandbox); the status check that follows decides.
		p, err := callback.Parse(in.Callback)
		if err != nil && !errors.Is(err, callback.ErrNoParams) {
			return nil, false, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
		}
		if code, desc, failed := p.Error(); failed {
			return nil, false, authFailed("approval of %s was not completed (%s: %s)", s.Subject, code, desc)
		}
		f.CallbackSeen = true
	}
	f.Phase = s.After
	if s.PollAfterRedirect && s.ScaPath != "" {
		f.Phase = phSCAPoll
	}
	return nil, true, nil
}
