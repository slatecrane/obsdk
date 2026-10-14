package swedbank

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	maxBody = 64 << 20 // statements can be large; they are unzipped separately with their own limit
)

// SDK operation names; error classification depends on them.
const (
	opAuthorize    = "authorize"
	opAuthMethods  = "auth_methods"
	opDecoupled    = "authorize_decoupled"
	opToken        = "token"
	opConsent      = "consent"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opStatement    = "statement"
)

type req struct {
	op         string
	method     string
	path       string // "/path" relative to host, or an absolute URL
	query      url.Values
	header     map[string]string
	body       any
	noRedirect bool
	ais        bool // add bic and (sandbox) app-id defaults
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

// abs resolves a steering link or path against the API host.
func (c *client) abs(href string) string {
	switch {
	case strings.HasPrefix(href, "http://"), strings.HasPrefix(href, "https://"):
		return href
	case strings.HasPrefix(href, "/"):
		return c.host + href
	default:
		return c.host + "/" + href
	}
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	u, err := url.Parse(c.abs(r.path))
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k, v := range r.query {
		q[k] = v
	}
	if r.ais {
		if q.Get("bic") == "" {
			q.Set("bic", c.bic)
		}
		if c.cfg.Env == obsdk.Sandbox && q.Get("app-id") == "" {
			q.Set("app-id", c.cfg.Credentials.ClientID)
		}
	}
	u.RawQuery = q.Encode()

	var body io.Reader
	if r.body != nil {
		b, err := json.Marshal(r.body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("Date", c.now().UTC().Format(http.TimeFormat))
	hr.Header.Set("X-Request-ID", c.cfg.ID(obsdk.IDRequest))
	if r.body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	if r.method == http.MethodPost && r.body == nil && r.op == opToken {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range r.header {
		if v != "" {
			hr.Header.Set(k, v)
		}
	}

	hc := c.http
	if hcl, ok := c.http.(*http.Client); ok && r.noRedirect {
		// Only the authorize call needs the 302 itself; other doers are expected not to follow redirects.
		cp := *hcl
		cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		hc = &cp
	}
	res, err := hc.Do(hr)
	if err != nil {
		c.log.Debug("swedbank request failed", "op", r.op, "method", r.method, "url", redact(u), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("swedbank request", "op", r.op, "method", r.method, "url", redact(u), "status", res.StatusCode,
		"request_id", hr.Header.Get("X-Request-ID"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// redact hides credentials that Swedbank carries in query strings.
func redact(u *url.URL) string {
	cp := *u
	q := cp.Query()
	for _, k := range []string{"client_secret", "refresh_token", "code", "apiKey", "access_code"} {
		if q.Has(k) {
			q.Set(k, "[redacted]")
		}
	}
	cp.RawQuery = q.Encode()
	return cp.String()
}

// ---- errors ----

type tppMessage struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Text     string `json:"text"`
}

// parseTPP reads tppMessages, which is an array in most responses and a
// single object in some (decoupled authorize polling).
func parseTPP(body []byte) []tppMessage {
	var env struct {
		M json.RawMessage `json:"tppMessages"`
	}
	if json.Unmarshal(body, &env) != nil || len(env.M) == 0 {
		return nil
	}
	switch env.M[0] {
	case '[':
		var l []tppMessage
		_ = json.Unmarshal(env.M, &l)
		return l
	case '{':
		var m tppMessage
		if json.Unmarshal(env.M, &m) == nil {
			return []tppMessage{m}
		}
	}
	return nil
}

func hasCode(msgs []tppMessage, code string) bool {
	for _, m := range msgs {
		if m.Code == code {
			return true
		}
	}
	return false
}

// errNotPosted marks "transactions over 90 days must be posted first". It is
// only produced for the transactions operation, where it is meaningful.
type notPostedError struct{ *obsdk.APIError }

func (e *notPostedError) Unwrap() error { return e.APIError }

// consentCodes are Berlin Group style codes that mean the consent is unusable.
var consentCodes = map[string]string{
	"CONSENT_INVALID": "consent_invalid",
	"CONSENT_EXPIRED": "consent_expired",
	"CONSENT_UNKNOWN": "consent_unknown",
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank error code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	msgs := parseTPP(r.body)
	e := &obsdk.APIError{Op: op, Status: r.status, RequestID: r.header.Get("X-Request-ID"), Body: r.body}
	if len(msgs) > 0 {
		e.Code, e.Text = msgs[0].Code, msgs[0].Text
	}
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case r.status == http.StatusUnauthorized && hasCode(msgs, "TOKEN_INVALID"):
		return e.Classify(obsdk.ErrAccessExpired)
	case r.status == http.StatusUnauthorized && hasCode(msgs, "RESOURCE_NOT_POSTED") && op == opTransactions:
		return &notPostedError{e}
	case r.status == http.StatusNotFound && op == opConsent:
		return &obsdk.ReauthError{Reason: "consent_not_found", Err: e}
	}
	for code, reason := range consentCodes {
		if hasCode(msgs, code) {
			return &obsdk.ReauthError{Reason: reason, Err: e}
		}
	}
	return e
}

func retryAfter(h http.Header) time.Duration {
	for _, k := range []string{"Retry-After", "X-Rate-Limit-Reset"} {
		if v := h.Get(k); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}

func rateLimitMeta(h http.Header) obsdk.Meta {
	m := obsdk.Meta{RequestID: h.Get("X-Request-ID")}
	l, e1 := strconv.Atoi(h.Get("X-Rate-Limit-Limit"))
	r, e2 := strconv.Atoi(h.Get("X-Rate-Limit-Remaining"))
	if e1 == nil && e2 == nil {
		rl := &obsdk.RateLimit{Limit: l, Remaining: r}
		if s, err := strconv.Atoi(h.Get("X-Rate-Limit-Reset")); err == nil {
			rl.ResetIn = time.Duration(s) * time.Second
		}
		m.RateLimit = rl
	}
	return m
}

// ---- shared request pieces ----

func psuHeaders(h map[string]string, p *obsdk.PSUContext) {
	if p == nil {
		return
	}
	set := func(k, v string) {
		if v != "" {
			h[k] = v
		}
	}
	set("PSU-IP-Address", p.IP)
	set("PSU-IP-Port", p.Port)
	set("PSU-User-Agent", p.UserAgent)
	set("PSU-ID", p.ID)
	set("PSU-CORPORATE-ID", p.CorporateID)
}

func bearer(s *obsdk.Session) string { return "Bearer " + s.AccessToken }

type link struct {
	Href string `json:"href"`
}

type authObject struct {
	ID   string `json:"authenticationMethodId"`
	Type string `json:"authenticationType"`
}

type challengeData struct {
	AutoStartToken string `json:"autoStartToken"`
	Code           string `json:"code"`
	ImageLink      string `json:"imageLink"`
}

func (c *client) challenge(cd *challengeData, text string) *obsdk.Challenge {
	if cd == nil && text == "" {
		return nil
	}
	ch := &obsdk.Challenge{Text: text}
	if cd != nil {
		ch.Code, ch.AutoStartToken = cd.Code, cd.AutoStartToken
		if cd.ImageLink != "" {
			// The spec's example ("v5/authorize-image/...") is relative to /psd2.
			l := cd.ImageLink
			if !strings.HasPrefix(l, "/") && !strings.HasPrefix(l, "http") {
				l = "/psd2/" + l
			}
			ch.ImageURL = c.abs(l)
		}
	}
	return ch
}
