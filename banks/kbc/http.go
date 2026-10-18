package kbc

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
	opConsent      = "consent"
	opToken        = "token"
	opRefresh      = "refresh"
	opRevoke       = "revoke"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opPayment      = "payment"
	opPayStatus    = "payment_status"
)

type req struct {
	op     string
	method string
	path   string // relative to the API base, starting with "/"
	query  url.Values
	token  bool       // call the OAuth token endpoint instead (form only)
	form   url.Values // token endpoint: urlencoded
	body   []byte     // JSON
	header map[string]string
	bearer string
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	target := c.tokenURL
	if !r.token {
		if !strings.HasPrefix(r.path, "/") {
			return nil, fmt.Errorf("kbc: refusing to call %q: not a path on the API host", r.path)
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
		hr.Body, hr.ContentLength = http.NoBody, 0
	}
	hr.Header.Set("Accept", "application/json")
	switch {
	case r.form != nil:
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case len(body) > 0:
		hr.Header.Set("Content-Type", "application/json")
	}
	if !r.token {
		hr.Header.Set("X-Request-ID", c.cfg.ID(obsdk.IDRequest))
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("kbc request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("kbc request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode,
		"request_id", res.Header.Get("X-Request-ID"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

func psuHeaders(p *obsdk.PSUContext) map[string]string {
	h := map[string]string{}
	if p == nil {
		return h
	}
	if p.IP != "" {
		h["PSU-IP-Address"] = p.IP
	}
	if p.Port != "" {
		h["PSU-IP-Port"] = p.Port
	}
	if p.UserAgent != "" {
		h["PSU-User-Agent"] = p.UserAgent
	}
	return h
}

func meta(h http.Header) obsdk.Meta { return obsdk.Meta{RequestID: h.Get("X-Request-ID")} }

// ---- tokens ----

type tokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    json.Number `json:"expires_in"`
	RefreshToken string      `json:"refresh_token"`
	Scope        string      `json:"scope"`
}

func seconds(n json.Number) time.Duration {
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

// token posts to the OAuth token endpoint. With an eIDAS certificate the
// client is identified by its client_id (the organizationIdentifier) and the
// mTLS certificate; no secret is sent. A nil tokenResponse with a nil error
// means the bank refused; r carries the reply.
func (c *client) token(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, token: true, form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("kbc: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// ---- errors ----

// errorBody covers the shapes KBC answers with: Berlin Group tppMessages
// (the PSD2 APIs), OAuth errors (error, error_description) from the token
// endpoint, the API gateway's problem details (title, detail) and its bare
// {"status", "message"}.
type errorBody struct {
	TPPMessages []struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Text     string `json:"text"`
	} `json:"tppMessages"`
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Message   string `json:"message"`
}

func parseError(b []byte) (code, text string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	switch {
	case len(e.TPPMessages) > 0:
		return e.TPPMessages[0].Code, e.TPPMessages[0].Text
	case e.Error != "":
		return e.Error, e.ErrorDesc
	case e.Title != "":
		return e.Title, e.Detail
	}
	return "", e.Message
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, RequestID: r.header.Get("X-Request-ID"), Body: r.body}
	e.Code, e.Text = parseError(r.body)
	ais := op == opAccounts || op == opBalances || op == opTransactions
	switch {
	case r.status == http.StatusTooManyRequests || e.Code == "ACCESS_EXCEEDED":
		// ACCESS_EXCEEDED: the consent's frequencyPerDay is used up for today.
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case ais && e.Code == "CONSENT_EXPIRED":
		return &obsdk.ReauthError{Reason: "consent_expired", Consent: consentKind, Err: e}
	case ais && strings.HasPrefix(e.Code, "CONSENT_"):
		// CONSENT_INVALID, CONSENT_UNKNOWN: revoked by the user, or never authorised.
		return &obsdk.ReauthError{Reason: "consent_invalid", Consent: consentKind, Err: e}
	case ais && r.status == http.StatusUnauthorized:
		// TOKEN_INVALID or TOKEN_EXPIRED: the access token lasts 30 minutes.
		return e.Classify(obsdk.ErrAccessExpired)
	case op == opRefresh && (e.Code == "invalid_grant" || e.Code == "invalid_client" || e.Code == "unauthorized_client"):
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
	case op == opToken && e.Code == "invalid_grant":
		// The code is valid for two minutes and only once; a wrong code_verifier also lands here.
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
