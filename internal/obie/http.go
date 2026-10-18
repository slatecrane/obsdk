package obie

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

const maxBody = 16 << 20

// SDK operation names; error classification depends on them.
const (
	opToken        = "token"
	opRefresh      = "refresh"
	opConsent      = "consent"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opPayConsent   = "payment_consent"
	opPayment      = "payment"
	opPayStatus    = "payment_status"
)

type req struct {
	op     string
	method string
	path   string // "/path" relative to host, or an absolute URL on the host
	query  url.Values
	form   url.Values // sent as application/x-www-form-urlencoded (token endpoint)
	body   any        // sent as JSON
	raw    []byte     // sent as JSON exactly as given (signed bodies)
	header map[string]string
	bearer string
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
		raw = c.host + raw
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

	var body io.Reader
	var ctype string
	switch {
	case r.form != nil:
		body, ctype = strings.NewReader(r.form.Encode()), "application/x-www-form-urlencoded"
	case r.raw != nil:
		body, ctype = bytes.NewReader(r.raw), "application/json"
	case r.body != nil:
		b, err := json.Marshal(r.body)
		if err != nil {
			return nil, err
		}
		body, ctype = bytes.NewReader(b), "application/json"
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Accept", "application/json")
	if ctype != "" {
		hr.Header.Set("Content-Type", ctype)
	}
	if r.form == nil {
		hr.Header.Set("x-fapi-interaction-id", c.cfg.ID(obsdk.IDRequest))
		if c.p.Headers != nil {
			c.p.Headers(c.cfg, c.target, hr.Header)
		}
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if p := r.psu; p != nil && r.form == nil {
		if p.IP != "" {
			hr.Header.Set("x-fapi-customer-ip-address", p.IP)
		}
		if p.UserAgent != "" {
			hr.Header.Set("x-customer-user-agent", p.UserAgent)
		}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("obie request failed", "bank", c.target.Bank, "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("obie request", "bank", c.target.Bank, "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode,
		"interaction_id", res.Header.Get("x-fapi-interaction-id"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// ---- errors ----

// errorBody covers OBIE errors (Code, Message, Errors[]) and OAuth errors
// (error, error_description).
type errorBody struct {
	Code    string `json:"Code"`
	ID      string `json:"Id"`
	Message string `json:"Message"`
	Errors  []struct {
		ErrorCode string `json:"ErrorCode"`
		Message   string `json:"Message"`
	} `json:"Errors"`
	OAuthError string `json:"error"`
	OAuthDesc  string `json:"error_description"`
}

func parseError(b []byte) (code, text, id string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)])), ""
	}
	switch {
	case len(e.Errors) > 0:
		code, text = e.Errors[0].ErrorCode, e.Errors[0].Message
		if text == "" {
			text = e.Message
		}
	case e.OAuthError != "":
		code, text = e.OAuthError, e.OAuthDesc
	default:
		code, text = e.Code, e.Message
	}
	return code, text, e.ID
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, Body: r.body}
	e.Code, e.Text, e.RequestID = parseError(r.body)
	if e.RequestID == "" {
		e.RequestID = r.header.Get("x-fapi-interaction-id")
	}
	ais := op == opAccounts || op == opBalances || op == opTransactions
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case ais && r.status == http.StatusUnauthorized:
		return e.Classify(obsdk.ErrAccessExpired)
	case ais && e.Code == "UK.OBIE.Resource.InvalidConsentStatus":
		// Crosskey answers 400 with this code once the consent is deleted or revoked.
		return &obsdk.ReauthError{Reason: "consent_not_authorised", Consent: consentKind, Err: e}
	case ais && r.status == http.StatusForbidden:
		// A revoked or expired consent answers 403, and so does a range of
		// transactions the token's authentication level doesn't reach (OBIE
		// banks limit refreshed tokens to the last 90 days).
		return &obsdk.ReauthError{Reason: "access_not_granted", Err: e}
	case op == opRefresh && (e.Code == "invalid_grant" || r.status == http.StatusBadRequest || r.status == http.StatusUnauthorized):
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
	}
	return e
}

func retryAfter(h http.Header) time.Duration {
	for _, k := range []string{"Retry-After", "RateLimit-Reset"} {
		if v := h.Get(k); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}
