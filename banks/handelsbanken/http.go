package handelsbanken

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
	opConsent      = "consent"
	opAuthorize    = "authorize"
	opDecoupled    = "decoupled"
	opRefresh      = "refresh"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
)

type req struct {
	op      string
	method  string
	url     string // absolute; built with c.api + path, or a link from the bank
	query   url.Values
	form    url.Values // application/x-www-form-urlencoded (token endpoints)
	body    any        // JSON
	bearer  string
	country string            // Country header (general API)
	header  map[string]string // extra headers (PSU-Corporate-ID, X-Sandbox-User, ...)
	psu     *obsdk.PSUContext
	api     bool // a PSD2 API call: send X-IBM-Client-Id and the TPP ids
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	u, err := url.Parse(r.url)
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
	var body []byte
	var ctype string
	switch {
	case r.form != nil:
		body, ctype = []byte(r.form.Encode()), "application/x-www-form-urlencoded"
	case r.body != nil:
		if body, err = json.Marshal(r.body); err != nil {
			return nil, err
		}
		ctype = "application/json"
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body == nil {
		hr.Body, hr.ContentLength = http.NoBody, 0
	}
	hr.Header.Set("Accept", "application/json")
	if ctype != "" {
		hr.Header.Set("Content-Type", ctype)
	}
	if r.api {
		hr.Header.Set("X-IBM-Client-Id", c.cfg.Credentials.ClientID)
		hr.Header.Set("TPP-Request-ID", c.cfg.ID(obsdk.IDRequest))
		hr.Header.Set("TPP-Transaction-ID", c.cfg.ID(obsdk.IDRequest))
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if r.country != "" {
		hr.Header.Set("Country", r.country)
	}
	if p := r.psu; p != nil && p.IP != "" {
		hr.Header.Set("PSU-IP-Address", p.IP)
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("handelsbanken request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("handelsbanken request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode)
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

func (c *client) apiURL(path string) string { return c.api + path }

// ---- errors ----

// errorBody covers the shapes Handelsbanken answers with: the gateway's
// {"httpCode", "httpMessage", "moreInformation"}, Berlin Group style
// {"tppMessages": [{"code", "text"}]}, and OAuth {"error", "error_description"}.
type errorBody struct {
	HTTPMessage     string `json:"httpMessage"`
	MoreInformation string `json:"moreInformation"`
	TPPMessages     []struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Text     string `json:"text"`
	} `json:"tppMessages"`
	Error     json.RawMessage `json:"error"`
	ErrorDesc string          `json:"error_description"`
}

func parseError(b []byte) (code, text string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	if len(e.TPPMessages) > 0 {
		return e.TPPMessages[0].Code, e.TPPMessages[0].Text
	}
	var oauth string
	if json.Unmarshal(e.Error, &oauth) == nil && oauth != "" {
		return oauth, e.ErrorDesc
	}
	return e.HTTPMessage, e.MoreInformation
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, Body: r.body}
	e.Code, e.Text = parseError(r.body)
	ais := op == opAccounts || op == opBalances || op == opTransactions
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case ais && r.status == http.StatusUnauthorized:
		return e.Classify(obsdk.ErrAccessExpired)
	case ais && r.status == http.StatusForbidden:
		return &obsdk.ReauthError{Reason: "access_not_granted", Err: e}
	case op == opRefresh && (r.status == http.StatusBadRequest || r.status == http.StatusUnauthorized):
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

// ---- tokens ----

type tokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    json.Number `json:"expires_in"`
	RefreshToken string      `json:"refresh_token"`
}

// token calls the OAuth token endpoint. A nil response with a nil error
// means the bank refused; the *resp says why.
func (c *client) token(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, url: c.tokenURL, form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("handelsbanken: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// clientToken gets a client credentials token for a scope (AIS, PIS). It is
// fetched per operation: clients are stateless.
func (c *client) clientToken(ctx context.Context, scope string) (string, error) {
	tr, r, err := c.token(ctx, opToken, url.Values{"grant_type": {"client_credentials"}, "scope": {scope}})
	if err != nil {
		return "", err
	}
	if tr == nil {
		return "", c.apiErr(opToken, r)
	}
	return tr.AccessToken, nil
}
