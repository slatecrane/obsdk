package stet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const maxBody = 16 << 20

// SDK operation names; error classification depends on them.
const (
	opToken        = "token"
	opRefresh      = "refresh"
	opRevoke       = "revoke"
	opConsent      = "consent"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opPayment      = "payment"
	opConfirm      = "payment_confirmation"
	opPayStatus    = "payment_status"
	opCancel       = "payment_cancellation"
)

type req struct {
	op     string
	method string
	path   string // "/path" relative to the API root, or an absolute URL
	query  url.Values
	form   url.Values // sent as application/x-www-form-urlencoded (token endpoint); not signed
	body   any        // sent as JSON
	header map[string]string
	bearer string
	basic  [2]string // HTTP Basic credentials (token endpoint)
	psu    *obsdk.PSUContext
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	raw := r.path
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		raw = c.base + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if len(r.query) > 0 {
		q := u.Query()
		for k, v := range r.query {
			q[k] = v
		}
		u.RawQuery = q.Encode()
	}

	var payload []byte
	var ctype string
	switch {
	case r.form != nil:
		payload, ctype = []byte(r.form.Encode()), "application/x-www-form-urlencoded"
	case r.body != nil:
		if payload, err = json.Marshal(r.body); err != nil {
			return nil, err
		}
		ctype = "application/json"
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if payload == nil {
		hr.Body, hr.ContentLength = http.NoBody, 0
	}
	if ctype != "" {
		hr.Header.Set("Content-Type", ctype)
	}
	if r.form != nil {
		hr.Header.Set("Accept", "application/json")
	} else {
		hr.Header.Set("Accept", "application/hal+json, application/json")
		hr.Header.Set("X-Request-ID", c.cfg.ID(obsdk.IDRequest))
		if c.p.Headers != nil {
			c.p.Headers(c.cfg, c.target, hr.Header)
		}
		if p := r.psu; p != nil {
			setIf(hr.Header, "PSU-IP-Address", p.IP)
			setIf(hr.Header, "PSU-IP-Port", p.Port)
			setIf(hr.Header, "PSU-User-Agent", p.UserAgent)
		}
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if r.basic[0] != "" {
		hr.SetBasicAuth(url.QueryEscape(r.basic[0]), url.QueryEscape(r.basic[1]))
	}
	if r.form == nil && c.p.Signing != nil {
		if err := c.p.Signing.sign(hr, payload, c.cfg.Seal); err != nil {
			return nil, err
		}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("stet request failed", "bank", c.target.Bank, "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("stet request", "bank", c.target.Bank, "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode,
		"request_id", res.Header.Get("X-Request-ID"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

func setIf(h http.Header, k, v string) {
	if v != "" {
		h.Set(k, v)
	}
}

func meta(r *resp) obsdk.Meta { return obsdk.Meta{RequestID: r.header.Get("X-Request-ID")} }

// ---- errors ----

// errorBody covers STET's ErrorModel (status, error, message, details), the
// hapi.js shape some gateways answer with (statusCode, error, message) and
// OAuth errors (error, error_description).
type errorBody struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Desc    string `json:"error_description"`
	Details []struct {
		Message string `json:"message"`
		Path    string `json:"path"`
		Name    string `json:"name"`
	} `json:"details"`
}

// stetCode matches STET's message codes (FORMAT_ERROR, ACCESS_EXCEEDED, ...).
var stetCode = regexp.MustCompile(`^[A-Z][A-Z0-9_ ]*[A-Z0-9]$`)

func parseError(b []byte) (code, text string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	switch {
	case e.Desc != "" || (e.Error != "" && e.Message == ""):
		// OAuth: {"error":"invalid_grant","error_description":"..."}
		return e.Error, e.Desc
	case stetCode.MatchString(e.Message):
		code, text = strings.ReplaceAll(e.Message, " ", ""), e.Error
	default:
		text = e.Message
	}
	if len(e.Details) > 0 {
		d := e.Details[0]
		where := firstNonEmpty(d.Path, d.Name)
		if where != "" {
			where += ": "
		}
		text = strings.TrimSpace(text + " (" + where + d.Message + ")")
	}
	return code, text
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, Body: r.body, RequestID: r.header.Get("X-Request-ID")}
	e.Code, e.Text = parseError(r.body)
	ais := op == opAccounts || op == opBalances || op == opTransactions || op == opConsent
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case ais && r.status == http.StatusUnauthorized:
		return e.Classify(obsdk.ErrAccessExpired)
	case ais && r.status == http.StatusForbidden:
		// The user's authorization was revoked or no longer covers the
		// request (e.g. more than 90 days of history after a refresh).
		return &obsdk.ReauthError{Reason: "access_not_granted", Consent: consentKind, Err: e}
	case op == opRefresh && (e.Code == "invalid_grant" || r.status == http.StatusBadRequest || r.status == http.StatusUnauthorized):
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
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
