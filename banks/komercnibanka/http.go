package komercnibanka

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
	"github.com/slatecrane/obsdk/internal/cbs"
)

const maxBody = 16 << 20

// SDK operation names; error classification depends on them.
const (
	opToken        = "token"
	opRefresh      = "refresh"
	opRevoke       = "revoke"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opStanding     = "standing_orders"
	opPayment      = "payment"
	opPaySign      = "payment_sign"
	opPayStatus    = "payment_status"
)

type req struct {
	op     string
	method string
	url    string // absolute: the token endpoint, when overridden
	path   string // relative to the API base, starting with "/"
	query  url.Values
	form   url.Values // token endpoint: urlencoded
	body   []byte     // JSON
	bearer string
	// payment marks PIS calls, which want Date and User-Involved.
	payment bool
	// user says the PSU is present (User-Involved: true).
	user bool
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
			return nil, fmt.Errorf("komercnibanka: refusing to call %q: not a path on the API host", r.path)
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
	if r.form == nil {
		hr.Header.Set("TPP-Name", c.tppName)
		if c.tppID != "" {
			hr.Header.Set("TPP-Identification", c.tppID)
		}
		if r.payment {
			hr.Header.Set("Date", c.now().UTC().Format(http.TimeFormat))
			hr.Header.Set("User-Involved", strconv.FormatBool(r.user))
		} else if r.user {
			hr.Header.Set("User-Involved", "true")
		}
	}
	hr.Header.Set("X-Request-Id", c.cfg.ID(obsdk.IDRequest))
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("komercnibanka request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("komercnibanka request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode)
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

// tokenCall posts to the token endpoint with the client's id and secret in
// the body, over mTLS. KB's sandbox also wants redirect_uri on refresh. A nil
// tokenResponse with a nil error means the bank refused; r carries the reply.
func (c *client) tokenCall(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	if s := c.cfg.Credentials.ClientSecret.Reveal(); s != "" {
		form.Set("client_secret", s)
	}
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, url: c.token, form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("komercnibanka: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// applyToken stores a token response in the session. A refresh brings no new
// refresh token; the old one stays.
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

// codeNARR is KB's "narrative" code for refusals it explains in text; on the
// account resources it means access is denied ("Unauthorized access to
// account", "User is not in active state", ...).
const codeNARR = "NARR"

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, Body: r.body, RequestID: responseID(r.header)}
	e.Code, e.Text = cbs.ParseError(r.body)
	ais := op == opAccounts || op == opBalances || op == opTransactions || op == opStanding
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case (ais || op == opPayment || op == opPaySign) && r.status == http.StatusUnauthorized:
		// The access token expired or was revoked (or no certificate was sent).
		return e.Classify(obsdk.ErrAccessExpired)
	case ais && e.Code == codeNARR:
		return &obsdk.ReauthError{Reason: "access_denied", Consent: consentKind, Err: e}
	case op == opRefresh && (e.Code == "invalid_grant" || r.status == http.StatusUnauthorized):
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
	case op == opToken && (e.Code == "invalid_grant" || e.Code == "invalid_request"):
		return e.Classify(obsdk.ErrAuthFailed)
	}
	return e
}

// responseID is KB's id for a response, which its support asks for: the API
// sends x-response-id, the gateway gwcorrelationid.
func responseID(h http.Header) string {
	for _, k := range []string{"X-Response-Id", "Gwcorrelationid"} {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func retryAfter(h http.Header) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}
