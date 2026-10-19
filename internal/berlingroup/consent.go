package berlingroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	// consentKind names the AIS consent in Session.Consents.
	consentKind = "ais"
	// valueIBAN names the accounts of a dedicated consent (comma separated).
	valueIBAN = "iban"
	// metaApproach records the SCA approach the session was approved with.
	metaApproach = "approach"
)

type accountRef struct {
	IBAN string `json:"iban"`
}

type consentRequest struct {
	Access                   any    `json:"access"`
	RecurringIndicator       bool   `json:"recurringIndicator"`
	ValidUntil               string `json:"validUntil"`
	FrequencyPerDay          int    `json:"frequencyPerDay"`
	CombinedServiceIndicator bool   `json:"combinedServiceIndicator"`
}

// access builds the consent's access object: dedicated to the given IBANs,
// all accounts (global) or bank-offered (empty lists, the user picks).
func (c *client) access(caps []obsdk.Capability, ibans []string) any {
	if len(ibans) == 0 && c.p.Consent != ConsentBankOffered {
		return map[string]string{"allPsd2": firstNonEmpty(c.p.AllAccountsValue, "allAccounts")}
	}
	if len(caps) == 0 {
		caps = obsdk.AISP
	}
	refs := []accountRef{}
	for _, i := range ibans {
		refs = append(refs, accountRef{IBAN: i})
	}
	a := map[string][]accountRef{"accounts": refs}
	for _, cp := range caps {
		switch cp {
		case obsdk.CapBalances:
			a["balances"] = refs
		case obsdk.CapTransactions, obsdk.CapTransactionsHistory:
			a["transactions"] = refs
		}
	}
	return a
}

func parseIBANs(s string) ([]string, error) {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' }) {
		iban := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(part), " ", ""))
		if iban == "" {
			continue
		}
		if err := obsdk.ValidateIdentifier(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: iban}); err != nil {
			return nil, fmt.Errorf("%w: Values[%q]: %s %v", obsdk.ErrInvalidRequest, valueIBAN, iban, err)
		}
		out = append(out, iban)
	}
	return out, nil
}

// Connect creates the AIS consent and starts its authorisation with the
// requested approach.
func (c *client) Connect(ctx context.Context, r obsdk.ConnectRequest) (*obsdk.Step, error) {
	approach, err := c.approach(r.Method)
	if err != nil {
		return nil, err
	}
	if c, err = c.forNew(); err != nil {
		return nil, err
	}
	f := &flow{Op: flowConnect, Approach: approach, PSU: r.PSU, Language: r.Language, Caps: r.Capabilities, Institution: c.inst}
	if approach == Redirect {
		if f.RedirectURL, err = c.redirectURL(r.RedirectURL); err != nil {
			return nil, err
		}
	}
	if f.IBANs, err = parseIBANs(r.Values[valueIBAN]); err != nil {
		return nil, err
	}
	if c.p.Consent == ConsentBankOffered && len(f.IBANs) == 0 && approach != Redirect {
		return nil, fmt.Errorf("%w: %s lets the user pick accounts only on its own pages; use the redirect method or name the accounts in Values[%q]",
			obsdk.ErrInvalidRequest, c.p.Info.Name, valueIBAN)
	}
	if v := strings.TrimSpace(r.Values[fieldPSUID]); v != "" {
		f.PSU.ID = v
	}
	f.ValidUntil = c.now().UTC().AddDate(0, 0, c.p.consentDays(r.ConsentValidityDays)).Format(firstNonEmpty(c.p.ValidUntilLayout, "2006-01-02"))
	if f.PSU.ID == "" && (c.p.PSUID == PSUIDRequired || approach == Decoupled) {
		f.Need = needPSUID
		return c.pause(f, psuIDStep())
	}
	return c.createConsent(ctx, f, obsdk.StepInput{Values: r.Values})
}

func (c *client) createConsent(ctx context.Context, f *flow, in obsdk.StepInput) (*obsdk.Step, error) {
	body := consentRequest{Access: c.access(f.Caps, f.IBANs), RecurringIndicator: true, ValidUntil: f.ValidUntil,
		FrequencyPerDay: c.p.frequency()}
	h := psuHeaders(&f.PSU)
	c.redirectHeaders(f, h)
	res, err := c.do(ctx, req{op: opConsent, method: http.MethodPost, path: "/v1/consents", body: body, header: h})
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return nil, c.apiErr(opConsent, res)
	}
	var r scaResponse
	if err := json.Unmarshal(res.body, &r); err != nil || r.ConsentID == "" {
		return nil, fmt.Errorf("berlingroup: unreadable consent response (HTTP %d)", res.status)
	}
	f.ConsentID = r.ConsentID
	f.StatusPath = "/v1/consents/" + url.PathEscape(r.ConsentID) + "/status"
	if err := f.absorb(&r, c.p.linkVersions()...); err != nil {
		return nil, err
	}
	f.Need = ""
	return c.advance(ctx, f, in)
}

// consentState reads a consent's status.
func (c *client) consentState(ctx context.Context, path string, psu *obsdk.PSUContext) (string, error) {
	res, err := c.do(ctx, req{op: opConsentState, method: http.MethodGet, path: path, header: psuHeaders(psu)})
	if err != nil {
		return "", err
	}
	if res.status != http.StatusOK {
		return "", c.apiErr(opConsentState, res)
	}
	var b struct {
		ConsentStatus string `json:"consentStatus"`
	}
	if err := json.Unmarshal(res.body, &b); err != nil || b.ConsentStatus == "" {
		return "", fmt.Errorf("berlingroup: unreadable consent status (HTTP %d)", res.status)
	}
	return b.ConsentStatus, nil
}

// finishConnect checks that the consent is valid, builds the session and
// lists the consented accounts.
func (c *client) finishConnect(ctx context.Context, f *flow) (*obsdk.Step, error) {
	status, err := c.consentState(ctx, f.StatusPath, &f.PSU)
	if err != nil {
		return nil, err
	}
	switch status {
	case "valid":
	case "received", "partiallyAuthorised":
		return nil, authFailed("access was not approved at the bank (consent %s)", status)
	default: // rejected, revokedByPsu, expired, terminatedByTpp
		return nil, authFailed("the consent is %s", status)
	}
	s := &obsdk.Session{
		Bank: c.bank(), Country: c.target.Country, Segment: c.target.Segment, Env: c.cfg.Env, Integration: c.p.ID,
		Consents: map[string]obsdk.Consent{}, Meta: map[string]string{metaApproach: f.Approach},
	}
	if c.inst != "" {
		s.Meta[metaInstitution] = c.inst
	}
	if f.token != nil {
		applyToken(s, f.token, f.TokenURL)
		s.Meta[metaApproach] = "oauth"
	}
	cons := obsdk.Consent{ID: f.ConsentID, Kind: consentKind, Status: status}
	// The consent is valid through the day of validUntil, a date or (at some
	// banks) a date-time.
	if t, err := time.Parse("2006-01-02", firstN(c.consentValidUntil(ctx, f), 10)); err == nil {
		cons.ValidUntil = &t
	}
	s.Consents[consentKind] = cons
	s.Touch(c.now())

	psu := f.PSU
	psu.ID = ""
	accs, _, err := c.listAccounts(ctx, s, &psu)
	if err != nil {
		return nil, &obsdk.FlowError{Session: s.Clone(), Err: err}
	}
	for _, a := range accs {
		for _, id := range a.Identifiers {
			cons.Accounts = append(cons.Accounts, id.Value)
		}
	}
	s.Consents[consentKind] = cons
	return &obsdk.Step{Kind: obsdk.StepDone, Session: s, Accounts: accs}, nil
}

// consentValidUntil reads the validity the bank granted, which may differ
// from what was asked; the request's value stands in when it can't be read.
func (c *client) consentValidUntil(ctx context.Context, f *flow) string {
	res, err := c.do(ctx, req{op: opConsentState, method: http.MethodGet, path: "/v1/consents/" + url.PathEscape(f.ConsentID),
		header: psuHeaders(&f.PSU)})
	if err != nil || res.status != http.StatusOK {
		return f.ValidUntil
	}
	var b struct {
		ValidUntil string `json:"validUntil"`
	}
	if json.Unmarshal(res.body, &b) != nil || b.ValidUntil == "" {
		return f.ValidUntil
	}
	return b.ValidUntil
}

// ---- refresh and disconnect ----

// Refresh has no token to renew (the consent id is the credential); it checks
// that the consent is still valid and returns the session unchanged, or a
// ReauthError inside a RefreshError when the user must connect again.
func (c *client) Refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	c, err := c.forSession(s)
	if err != nil {
		return nil, err
	}
	cons, ok := s.Consents[consentKind]
	if !ok || cons.ID == "" {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "no_consent", Consent: consentKind}}
	}
	if cons.ValidUntil != nil && !c.now().Before(cons.ValidUntil.AddDate(0, 0, 1)) {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "consent_expired", Consent: consentKind}}
	}
	status, err := c.consentState(ctx, "/v1/consents/"+url.PathEscape(cons.ID)+"/status", nil)
	if err != nil {
		var ae *obsdk.APIError
		temporary := !asAPIError(err, &ae) || ae.Status == http.StatusTooManyRequests || ae.Status >= 500
		if !temporary && (ae.Code == "CONSENT_UNKNOWN" || ae.Code == "CONSENT_EXPIRED" || ae.Code == "CONSENT_INVALID") {
			return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: strings.ToLower(ae.Code), Consent: consentKind, Err: err}}
		}
		return nil, &obsdk.RefreshError{Temporary: temporary, Err: err}
	}
	if status != "valid" {
		return nil, &obsdk.RefreshError{Err: &obsdk.ReauthError{Reason: "consent_" + strings.ToLower(status), Consent: consentKind}}
	}
	ns := s.Clone()
	if ns.RefreshToken != "" {
		// OAuth SCA approach: the account calls need a fresh access token.
		if err := c.refreshToken(ctx, ns); err != nil {
			var re *obsdk.ReauthError
			return nil, &obsdk.RefreshError{Temporary: !errors.As(err, &re), Err: err}
		}
		ns.Touch(c.now())
	}
	return ns, nil
}

// Disconnect deletes the consent at the bank.
func (c *client) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	c, err := c.forSession(s)
	if err != nil {
		return nil, err
	}
	ns := s.Clone()
	res := &obsdk.DisconnectResult{Session: ns, Failed: map[string]string{}}
	cons, ok := s.Consents[consentKind]
	if !ok || cons.ID == "" {
		return res, nil
	}
	h := map[string]string{}
	if s.AccessToken != "" && !s.AccessExpired(c.now()) {
		h["Authorization"] = "Bearer " + s.AccessToken
	}
	r, err := c.do(ctx, req{op: opRevoke, method: http.MethodDelete, path: "/v1/consents/" + url.PathEscape(cons.ID), header: h})
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

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
