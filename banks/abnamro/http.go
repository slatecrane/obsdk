package abnamro

import (
	"bytes"
	"context"
	"encoding/json"
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
	opToken        = "token"
	opRefresh      = "refresh"
	opRevoke       = "revoke"
	opConsentInfo  = "consent_info"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opPayToken     = "payment_token"
	opPayment      = "payment"
	opPayExecute   = "payment_execute"
	opPayStatus    = "payment_status"
	opPayCancel    = "payment_cancel"
)

type req struct {
	op     string
	method string
	url    string // absolute: the token and revocation endpoints live on their own hosts
	path   string // relative to the API base, starting with "/"
	query  url.Values
	form   url.Values // token and revocation endpoints: urlencoded, no API key
	body   []byte     // JSON
	bearer string
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	target := r.url
	if target == "" {
		if !strings.HasPrefix(r.path, "/") {
			return nil, fmt.Errorf("abnamro: refusing to call %q: not a path on the API host", r.path)
		}
		target = c.api + r.path
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if len(r.query) > 0 {
		u.RawQuery = r.query.Encode()
	}
	body := r.body
	if r.form != nil {
		body = []byte(r.form.Encode())
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		// Go then sends Content-Length: 0 on PUT, which ABN AMRO's edge
		// insists on (411 without it).
		hr.Body, hr.ContentLength = http.NoBody, 0
	}
	hr.Header.Set("Accept", "application/json")
	switch {
	case r.form != nil:
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
		if len(body) > 0 {
			hr.Header.Set("Content-Type", "application/json")
		}
		hr.Header.Set("API-Key", c.apiKey)
		if r.bearer != "" {
			hr.Header.Set("Authorization", "Bearer "+r.bearer)
		}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("abnamro request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("abnamro request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode)
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// ---- tokens ----

type tokenResponse struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    json.Number `json:"expires_in"`
	Scope        string      `json:"scope"`
}

func seconds(n json.Number) time.Duration {
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

// tokenCall posts to the token endpoint over mTLS. The client authenticates
// with its certificate and client_id; there is no secret. A nil
// tokenResponse with a nil error means the bank refused; r carries the reply.
func (c *client) tokenCall(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, url: c.token, form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("abnamro: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// applyToken stores a token response in the session.
func (c *client) applyToken(s *obsdk.Session, tr *tokenResponse) {
	now := c.now()
	s.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		s.RefreshToken = tr.RefreshToken
	}
	if tr.TokenType != "" {
		s.TokenType = tr.TokenType
	}
	if tr.Scope != "" {
		s.Scope = tr.Scope
	}
	s.AccessExpiresAt = nil
	if d := seconds(tr.ExpiresIn); d > 0 {
		t := now.Add(d).UTC()
		s.AccessExpiresAt = &t
	}
	s.Touch(now)
}

// ---- errors ----

// errorBody covers ABN AMRO's API errors ({"errors": [{code, message,
// category, status, traceId}]}) and OAuth errors (error, error_description).
type errorBody struct {
	Errors []struct {
		Code     string `json:"code"`
		Message  string `json:"message"`
		Category string `json:"category"`
		TraceID  string `json:"traceId"`
	} `json:"errors"`
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

func parseError(b []byte) (code, text, trace string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		// The CDN in front answers some malformed requests with an HTML page.
		return "", strings.TrimSpace(string(b[:min(len(b), 200)])), ""
	}
	switch {
	case len(e.Errors) > 0:
		return e.Errors[0].Code, e.Errors[0].Message, e.Errors[0].TraceID
	case e.Error != "":
		return e.Error, e.ErrorDesc, ""
	}
	return "", "", ""
}

// codeNoAccess: "No access to the account" (the token is for another account).
const codeNoAccess = "MESSAGE_RST560_0016"

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, Body: r.body}
	e.Code, e.Text, e.RequestID = parseError(r.body)
	ais := op == opAccounts || op == opBalances || op == opTransactions || op == opConsentInfo
	pis := op == opPayStatus || op == opPayCancel || op == opPayExecute
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case (ais || pis) && r.status == http.StatusUnauthorized:
		// ERR_2002_001: the access token is expired, or the consent was revoked
		// (which voids every token issued for it).
		return e.Classify(obsdk.ErrAccessExpired)
	case ais && e.Code == codeNoAccess:
		return &obsdk.ReauthError{Reason: "consent_invalid", Consent: consentKind, Err: e}
	case op == opRefresh && e.Code == "invalid_grant":
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
	case op == opToken && e.Code == "invalid_grant":
		// The authorization code is single-use and must be exchanged within 60 seconds.
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
