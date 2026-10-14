package swedbank

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/callback"
)

// callAuthed performs a request authenticated with the flow's access token,
// without a Consent-ID (consent management endpoints).
func (c *client) callAuthed(ctx context.Context, s *obsdk.Session, r req, psu *obsdk.PSUContext) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w", obsdk.ErrAccessExpired)
	}
	if r.header == nil {
		r.header = map[string]string{}
	}
	r.header["Authorization"] = bearer(s)
	psuHeaders(r.header, psu)
	r.ais = true
	return c.do(ctx, r)
}

func refs(ids []string) []map[string]string {
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		if len(id) >= 2 && id[0] >= 'A' && id[0] <= 'Z' && id[1] >= 'A' && id[1] <= 'Z' {
			out = append(out, map[string]string{"iban": id})
		} else {
			out = append(out, map[string]string{"bban": id})
		}
	}
	return out
}

func accountRef(a obsdk.Account) string {
	for _, id := range a.Identifiers {
		if id.Scheme == "IBAN" {
			return id.Value
		}
	}
	for _, id := range a.Identifiers {
		if id.Scheme == "BBAN" {
			return id.Value
		}
	}
	return ""
}

type consentCreated struct {
	ID     string          `json:"consentId"`
	Status string          `json:"consentStatus"`
	Links  map[string]link `json:"_links"`
	Chosen *authObject     `json:"chosenScaMethod"`
}

// startConsent creates a consent of the given kind and moves the flow to the
// SCA phase when the bank wants the user to approve it.
func (c *client) startConsent(ctx context.Context, f *flow, kind string, accounts []string) (*obsdk.Step, bool, error) {
	now := c.now()
	validUntil := now.AddDate(0, 0, f.ValidityDays)
	body := map[string]any{"combinedServiceIndicator": false}
	switch kind {
	case kindAll:
		body["access"] = map[string]any{"availableAccounts": "allAccounts"}
		body["recurringIndicator"], body["frequencyPerDay"] = false, 1
		validUntil = now.AddDate(0, 0, 1)
		body["validUntil"] = day(validUntil)
	case kindDetailed:
		body["access"] = map[string]any{"accounts": refs(accounts), "balances": refs(accounts), "transactions": refs(accounts)}
		body["recurringIndicator"], body["frequencyPerDay"] = true, 4
		body["validUntil"] = day(validUntil)
	case kindOver90:
		body["access"] = map[string]any{"transactionsOver90Days": refs(accounts)}
		body["recurringIndicator"] = false // validUntil and frequencyPerDay are not allowed for this kind
	}
	hdr := map[string]string{
		"TPP-Redirect-Preferred": fmt.Sprint(f.Method == methodRedirect),
		"TPP-Redirect-URI":       f.RedirectURL,
	}
	r, err := c.callAuthed(ctx, f.Session, req{op: opConsent, method: http.MethodPost, path: c.aisBase() + "/consents", body: body, header: hdr}, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusCreated {
		return nil, false, c.apiErr(opConsent, r)
	}
	var cc consentCreated
	if err := json.Unmarshal(r.body, &cc); err != nil || cc.ID == "" {
		return nil, false, fmt.Errorf("swedbank: unreadable consent response")
	}
	cf := &consentFlow{
		Kind: kind, ID: cc.ID, Approach: r.header.Get("ASPSP-SCA-Approach"), Accounts: accounts,
		RedirectURL: cc.Links["scaRedirect"].Href, ScaPath: cc.Links["scaStatus"].Href, StatusPath: cc.Links["status"].Href,
		SelectPath: cc.Links["startAuthorisationWithAuthenticationMethodSelection"].Href,
	}
	if kind != kindOver90 {
		cf.ValidUntil = day(validUntil)
	}
	if cc.Chosen != nil {
		cf.ChosenMethod = cc.Chosen.ID
	}
	f.Consent = cf
	switch cc.Status {
	case "valid":
		return c.consentValid(f)
	case "received":
		f.Phase = phConsentSCA
		return nil, true, nil
	}
	return nil, false, authFailed("consent %s was not accepted (status %s)", kind, cc.Status)
}

// consentValid records the consent in the session and picks the next phase.
func (c *client) consentValid(f *flow) (*obsdk.Step, bool, error) {
	cf := f.Consent
	con := obsdk.Consent{ID: cf.ID, Kind: cf.Kind, Status: "valid", Accounts: cf.Accounts}
	if cf.ValidUntil != "" {
		if t, err := time.Parse("2006-01-02", cf.ValidUntil); err == nil {
			end := t.Add(24*time.Hour - time.Second).UTC()
			con.ValidUntil = &end
		}
	}
	// The flow state drops an empty map when it is serialized (omitempty),
	// so a session that came back through Resume may have none.
	if f.Session.Consents == nil {
		f.Session.Consents = map[string]obsdk.Consent{}
	}
	f.Session.Consents[cf.Kind] = con
	f.Session.Touch(c.now())
	f.Consent = nil
	switch cf.Kind {
	case kindAll:
		f.Phase = phDetailedStart
	case kindDetailed:
		f.Phase = phFinish
	case kindOver90:
		f.Phase = phStmtPost
	}
	return nil, true, nil
}

func (c *client) detailedStart(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	accs, _, _, err := c.listAccounts(ctx, f.Session, kindAll, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	var ids []string
	for _, a := range accs {
		if ref := accountRef(a); ref != "" {
			ids = append(ids, ref)
		}
	}
	if len(ids) == 0 {
		return nil, false, authFailed("the bank reports no accounts for this user")
	}
	f.Accounts = accs
	return c.startConsent(ctx, f, kindDetailed, ids)
}

func (c *client) consentSCA(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	cf := f.Consent
	switch {
	case cf.RedirectURL != "":
		f.AuthURL, f.Phase = cf.RedirectURL, phConsentRedir
		return redirectStep(f, consentPurpose(f.Consent.Kind)), false, nil
	case cf.SelectPath != "":
		method := f.Values["auth_method"]
		if method == "" {
			method = cf.ChosenMethod
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
		r, err := c.callAuthed(ctx, f.Session, req{op: opConsent, method: http.MethodPut, path: cf.SelectPath, body: body, header: hdr}, &f.PSU)
		if err != nil {
			return nil, false, err
		}
		if r.status != http.StatusOK && r.status != http.StatusCreated {
			return nil, false, c.apiErr(opConsent, r)
		}
		var b struct {
			Links      map[string]link `json:"_links"`
			Challenge  *challengeData  `json:"challengeData"`
			PSUMessage string          `json:"psuMessage"`
		}
		_ = json.Unmarshal(r.body, &b)
		if l := b.Links["scaStatus"].Href; l != "" {
			cf.ScaPath = l
		}
		f.Challenge, f.Message = c.challenge(b.Challenge, ""), b.PSUMessage
		f.Phase = phConsentPoll
		return waitStep(f, true, pollInterval), false, nil
	case cf.ScaPath != "":
		f.Phase = phConsentPoll
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("swedbank: consent %s needs approval but the bank gave no way to give it", cf.Kind)
}

func (c *client) consentPoll(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	if f.Consent.ScaPath == "" {
		return nil, false, fmt.Errorf("swedbank: the bank gave no status link for the approval of consent %s", f.Consent.Kind)
	}
	r, err := c.callAuthed(ctx, f.Session, req{op: opConsent, method: http.MethodGet, path: f.Consent.ScaPath}, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusOK {
		return nil, false, c.apiErr(opConsent, r)
	}
	var b struct {
		Status string `json:"scaStatus"`
	}
	_ = json.Unmarshal(r.body, &b)
	switch b.Status {
	case "finalised":
		f.Phase = phConsentCheck
		return nil, true, nil
	case "failed":
		return nil, false, authFailed("approval of consent %s failed: %s", f.Consent.Kind, tppSummary(parseTPP(r.body)))
	}
	return waitStep(f, true, pollInterval), false, nil
}

// consentPurpose says what the user approves, for redirect step messages.
func consentPurpose(kind string) string {
	if kind == kindOver90 {
		return "approve access to older transactions"
	}
	return "approve access to account data"
}

func (c *client) consentRedirect(f *flow, in obsdk.StepInput) (*obsdk.Step, bool, error) {
	if in.Callback == "" && !f.CallbackSeen {
		return redirectStep(f, consentPurpose(f.Consent.Kind)), false, nil
	}
	if in.Callback != "" {
		// Swedbank returns the user from an approval without any parameters
		// (seen in the SE sandbox); the status check below decides.
		p, err := callback.Parse(in.Callback)
		if err != nil && !errors.Is(err, callback.ErrNoParams) {
			return nil, false, fmt.Errorf("%w: %v", obsdk.ErrInvalidRequest, err)
		}
		if code, desc, failed := p.Error(); failed {
			return nil, false, authFailed("consent approval was not completed (%s: %s)", code, desc)
		}
		f.CallbackSeen = true
	}
	f.Phase = phConsentCheck
	return nil, true, nil
}

func (c *client) consentCheck(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	cf := f.Consent
	path := cf.StatusPath
	if path == "" {
		path = c.aisBase() + "/consents/" + url.PathEscape(cf.ID) + "/status"
	}
	r, err := c.callAuthed(ctx, f.Session, req{op: opConsent, method: http.MethodGet, path: path}, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusOK {
		return nil, false, c.apiErr(opConsent, r)
	}
	var b struct {
		Status string `json:"consentStatus"`
	}
	_ = json.Unmarshal(r.body, &b)
	switch b.Status {
	case "valid":
		return c.consentValid(f)
	case "received":
		return waitStep(f, false, pollInterval), false, nil
	}
	return nil, false, authFailed("consent %s ended with status %q", cf.Kind, b.Status)
}

// finish returns the connected session and the accounts the bank exposed.
func (c *client) finish(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	accs := f.Accounts
	// Prefer the account list under the final consent, so ids match what later calls will use.
	if again, _, _, err := c.listAccounts(ctx, f.Session, kindDetailed, &f.PSU); err == nil && len(again) > 0 {
		accs = again
	}
	s := f.Session
	if f.Values["auth_method"] != "" {
		if s.Meta == nil {
			s.Meta = map[string]string{}
		}
		s.Meta["auth_method"] = f.Values["auth_method"]
	}
	s.Touch(c.now())
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, false, nil
}

// Disconnect terminates the session's consents at the bank.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	for kind, con := range s.Consents {
		r, err := c.callAuthed(ctx, ns, req{op: opConsent, method: http.MethodDelete, path: c.aisBase() + "/consents/" + url.PathEscape(con.ID)}, nil)
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
