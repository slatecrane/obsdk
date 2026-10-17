package op

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
	opPayCreate    = "payment_create"
	opPaySubmit    = "payment_submit"
	opPayStatus    = "payment_status"
	opPayCancel    = "payment_cancel"
)

type req struct {
	op     string
	method string
	path   string // "/path" relative to the API host, or an absolute URL
	query  url.Values
	form   url.Values // sent as application/x-www-form-urlencoded
	raw    []byte     // sent as JSON exactly as given (signed bodies)
	body   any        // sent as JSON
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
		// Everything except the token endpoint.
		hr.Header.Set("x-api-key", c.cfg.Param(paramAPIKey))
		hr.Header.Set("x-fapi-interaction-id", c.cfg.ID(obsdk.IDRequest))
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if p := r.psu; p != nil {
		if p.IP != "" {
			hr.Header.Set("x-fapi-customer-ip-address", p.IP)
		}
		if p.UserAgent != "" {
			hr.Header.Set("x-customer-user-agent", p.UserAgent)
		}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("op request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("op request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode,
		"interaction_id", res.Header.Get("x-fapi-interaction-id"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// ---- errors ----

// errorBody covers OP's API errors (type, message, violations, id) and OAuth
// errors (error, error_description). Some failures come back as HTML pages.
type errorBody struct {
	Type       string      `json:"type"`
	Message    string      `json:"message"`
	ID         string      `json:"id"`
	Violations []violation `json:"violations"`
	OAuthError string      `json:"error"`
	OAuthDesc  string      `json:"error_description"`
}

type violation struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func parseError(b []byte) (e errorBody, code, text string) {
	if json.Unmarshal(b, &e) != nil {
		return e, "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	switch {
	case len(e.Violations) > 0:
		v := e.Violations[0]
		code, text = v.Type, v.Message
		if v.Path != "" {
			text = v.Path + ": " + text
		}
	case e.OAuthError != "":
		code, text = e.OAuthError, e.OAuthDesc
	default:
		code, text = e.Type, e.Message
	}
	return e, code, text
}

// rejection returns the violation that says the bank refused the payment
// itself (funds, limits, payee), as opposed to a malformed request.
func (e errorBody) rejection() *violation {
	for i, v := range e.Violations {
		switch v.Type {
		case "InsufficientFunds", "PaymentFail", "Payee", "ValidPayerAccount":
			return &e.Violations[i]
		}
	}
	return nil
}

// apiErr turns a failed response into the most specific error, using the
// status, OP's error type and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	body, code, text := parseError(r.body)
	e := &obsdk.APIError{Op: op, Status: r.status, Code: code, Text: text, RequestID: r.header.Get("x-fapi-interaction-id"), Body: r.body}
	if body.ID != "" && e.RequestID == "" {
		e.RequestID = body.ID
	}
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case r.status == http.StatusUnauthorized && (op == opAccounts || op == opBalances || op == opTransactions):
		return e.Classify(obsdk.ErrAccessExpired)
	case op == opRefresh && (code == "invalid_grant" || r.status == http.StatusUnauthorized):
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
	case op == opPayCreate || op == opPaySubmit:
		if v := body.rejection(); v != nil {
			return &obsdk.PaymentRejectedError{Reason: rejectReason(v), Err: e}
		}
	}
	return e
}

// rejectReason names a refused payment after OP's violation type.
func rejectReason(v *violation) string {
	switch v.Type {
	case "InsufficientFunds":
		return "insufficient_funds"
	case "Payee":
		return "invalid_payee"
	case "ValidPayerAccount":
		return "invalid_debtor_account"
	}
	return "payment_failed"
}

func retryAfter(h http.Header) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

func meta(r *resp) obsdk.Meta { return obsdk.Meta{RequestID: r.header.Get("x-fapi-interaction-id")} }
