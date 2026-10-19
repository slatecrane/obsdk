package berlingroup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const maxBody = 16 << 20

// SDK operation names; error classification depends on them.
const (
	opConsent      = "consent"
	opConsentState = "consent_status"
	opAuthorise    = "authorisation"
	opRevoke       = "revoke"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opPayment      = "payment"
	opPayStatus    = "payment_status"
	opCancel       = "cancel_payment"
)

type req struct {
	op     string
	method string
	path   string // "/v1/..." (from apiPath), with or without a query
	query  url.Values
	body   any    // marshalled as JSON when non-nil
	raw    []byte // sent as is with contentType when body is nil
	header map[string]string

	contentType string // of raw
	accept      string // default application/json
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

// apiPath reduces a link or path to the part from "/v1/" on, so it can be
// sent to the configured base URL. Banks return absolute links on their own
// host, links that repeat the base path, or bare paths; all of them land on
// the API root the client was configured with (which keeps base_url
// overrides and replays working). Links that do not point into the API are
// refused. versions are the profile's path segments for "v1" (PathVersion,
// AISPathVersion); a link using one is rewritten to the canonical "/v1/" form
// that flows store.
func apiPath(link string, versions ...string) (string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", fmt.Errorf("berlingroup: unreadable link %q", link)
	}
	p := u.EscapedPath()
	for _, version := range versions {
		if version == "" || version == "v1" {
			continue
		}
		if i := strings.Index(p+"/", "/"+version+"/"); i >= 0 {
			p = "/v1" + p[i+1+len(version):]
			break
		}
	}
	i := strings.Index(p, "/v1/")
	if i < 0 {
		if strings.HasSuffix(p, "/v1") {
			i = len(p) - 3
		} else {
			return "", fmt.Errorf("berlingroup: link %q is not on the XS2A API", link)
		}
	}
	p = p[i:]
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p, nil
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	if !strings.HasPrefix(r.path, "/v1/") {
		return nil, fmt.Errorf("berlingroup: refusing to call %q: not an XS2A path", r.path)
	}
	u, err := url.Parse(c.base + "/" + c.p.versionFor(r.path) + strings.TrimPrefix(r.path, "/v1"))
	if err != nil {
		return nil, err
	}
	if len(r.query) > 0 {
		q := u.Query()
		for k, vs := range r.query {
			q[k] = vs
		}
		u.RawQuery = q.Encode()
	}
	body, ctype := r.raw, r.contentType
	if r.body != nil {
		if body, err = json.Marshal(r.body); err != nil {
			return nil, err
		}
		ctype = "application/json"
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		hr.Body, hr.ContentLength = http.NoBody, 0
	} else {
		hr.Header.Set("Content-Type", ctype)
	}
	hr.Header.Set("Accept", firstNonEmpty(r.accept, "application/json"))
	hr.Header.Set("X-Request-ID", c.cfg.ID(obsdk.IDRequest))
	if c.p.Headers != nil {
		c.p.Headers(c.cfg, hr.Header)
	}
	for k, v := range r.header {
		if v != "" {
			hr.Header.Set(k, v)
		}
	}
	if c.p.DateLayout != "" {
		hr.Header.Set("Date", c.now().UTC().Format(c.p.DateLayout))
	}
	if c.p.BodyDigest && len(body) > 0 {
		hr.Header.Set("Digest", (&Signing{SHA512: c.p.Signing != nil && c.p.Signing.SHA512}).digest(body))
	}
	if s := c.p.Signing; s != nil && (s.Required || c.cfg.Seal != nil) {
		if err := s.sign(hr, body, c.cfg.Seal, c.now().UTC().Format(http.TimeFormat)); err != nil {
			return nil, err
		}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("berlingroup request failed", "bank", c.bank(), "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("berlingroup request", "bank", c.bank(), "op", r.op, "method", r.method, "url", u.Redacted(),
		"status", res.StatusCode, "request_id", res.Header.Get("X-Request-ID"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// psuHeaders are the PSU context headers; PSU-ID is added by the caller
// where the flow knows it.
func psuHeaders(p *obsdk.PSUContext) map[string]string {
	h := map[string]string{}
	if p == nil {
		return h
	}
	h["PSU-IP-Address"] = p.IP
	h["PSU-IP-Port"] = p.Port
	h["PSU-User-Agent"] = p.UserAgent
	h["PSU-ID"] = p.ID
	h["PSU-Corporate-ID"] = p.CorporateID
	return h
}

func meta(h http.Header) obsdk.Meta { return obsdk.Meta{RequestID: h.Get("X-Request-ID")} }

// ---- links ----

// href reads a Berlin Group link: {"href": "..."}, or a bare string as some
// banks send.
type href string

func (l *href) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*l = href(s)
		return nil
	}
	var o struct {
		Href string `json:"href"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	*l = href(o.Href)
	return nil
}

type links map[string]href

// ---- errors ----

type tppMessage struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Text     string `json:"text"`
	Path     string `json:"path"`
}

// tppMessages accepts the array of 1.3 and the single object some banks send.
type tppMessages []tppMessage

func (m *tppMessages) UnmarshalJSON(b []byte) error {
	var list []tppMessage
	if err := json.Unmarshal(b, &list); err == nil {
		*m = list
		return nil
	}
	var one tppMessage
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*m = tppMessages{one}
	return nil
}

// errorBody covers the error shapes of the standard: tppMessages (JSON) and
// the problem-details variant (title, detail, code, additionalErrors), plus
// OAuth errors and gateway {"message"} bodies.
type errorBody struct {
	TPPMessages tppMessages `json:"tppMessages"`
	Code        string      `json:"code"`
	Title       string      `json:"title"`
	Detail      string      `json:"detail"`
	Additional  []struct {
		Code   string `json:"code"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	} `json:"additionalErrors"`
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
	Message   string `json:"message"`
}

func parseError(b []byte) (code, text string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	for _, m := range e.TPPMessages {
		if m.Category == "" || strings.EqualFold(m.Category, "ERROR") {
			return m.Code, m.Text
		}
	}
	switch {
	case e.Code != "":
		return e.Code, firstNonEmpty(e.Detail, e.Title)
	case len(e.Additional) > 0:
		return e.Additional[0].Code, firstNonEmpty(e.Additional[0].Detail, e.Additional[0].Title)
	case e.Error != "":
		return e.Error, e.ErrorDesc
	case e.Title != "":
		return "", firstNonEmpty(e.Detail, e.Title)
	}
	return "", e.Message
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func isAIS(op string) bool { return op == opAccounts || op == opBalances || op == opTransactions }

// apiErr turns a failed response into the most specific error, using the
// status, the Berlin Group code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, RequestID: r.header.Get("X-Request-ID"), Body: r.body}
	e.Code, e.Text = parseError(r.body)
	switch {
	case r.status == http.StatusTooManyRequests || e.Code == "ACCESS_EXCEEDED":
		// ACCESS_EXCEEDED: the consent's frequencyPerDay is used up for today.
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case isAIS(op) && e.Code == "CONSENT_EXPIRED":
		return &obsdk.ReauthError{Reason: "consent_expired", Consent: consentKind, Err: e}
	case isAIS(op) && (e.Code == "CONSENT_INVALID" || e.Code == "CONSENT_UNKNOWN"):
		// Revoked by the user, never authorised, or not covering the resource.
		return &obsdk.ReauthError{Reason: "consent_invalid", Consent: consentKind, Err: e}
	case e.Code == "TOKEN_EXPIRED":
		return e.Classify(obsdk.ErrAccessExpired)
	case isAIS(op) && (e.Code == "TOKEN_INVALID" || r.status == http.StatusUnauthorized):
		return &obsdk.ReauthError{Reason: "token_invalid", Err: e}
	case op == opAuthorise && (e.Code == "PSU_CREDENTIALS_INVALID" || e.Code == "SCA_INVALID" || e.Code == "PSU_UNKNOWN" ||
		e.Code == "STATUS_INVALID" || e.Code == "SCA_METHOD_UNKNOWN"):
		// Wrong login, wrong TAN, a blocked or unknown user, or an authorisation
		// that already failed.
		return e.Classify(obsdk.ErrAuthFailed)
	}
	return e
}

func retryAfter(h http.Header) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

func asAPIError(err error, target **obsdk.APIError) bool { return errors.As(err, target) }
