package nordea

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const maxBody = 16 << 20

// SDK operation names; error classification depends on them.
const (
	opAuthorize    = "authorize"
	opToken        = "token"
	opRefresh      = "refresh"
	opRevoke       = "revoke"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
)

type req struct {
	op     string
	method string
	path   string // relative to the API host, query included
	query  url.Values
	form   url.Values // application/x-www-form-urlencoded (token endpoints)
	body   any        // JSON
	bearer string
	psu    *obsdk.PSUContext
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	u, err := url.Parse(c.host + r.path)
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

	var body, digestInput []byte
	var ctype string
	switch {
	case r.form != nil:
		body, ctype = []byte(r.form.Encode()), "application/x-www-form-urlencoded"
		digestInput = []byte(decodedForm(r.form))
	case r.body != nil:
		if body, err = json.Marshal(r.body); err != nil {
			return nil, err
		}
		ctype, digestInput = "application/json", body
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body == nil {
		hr.Body, hr.ContentLength = http.NoBody, 0
	}
	date := c.now().UTC().Format(http.TimeFormat)
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("X-IBM-Client-Id", c.cfg.Credentials.ClientID)
	hr.Header.Set("X-IBM-Client-Secret", c.cfg.Credentials.ClientSecret.Reveal())
	hr.Header.Set("X-Nordea-Originating-Host", u.Host)
	hr.Header.Set("X-Nordea-Originating-Date", date)
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if p := r.psu; p != nil {
		if p.IP != "" {
			hr.Header.Set("X-Nordea-Originating-User-Ip", p.IP)
		}
		if p.UserAgent != "" {
			hr.Header.Set("X-Nordea-Originating-User-Agent", p.UserAgent)
		}
	}
	lines := []string{
		"(request-target): " + strings.ToLower(r.method) + " " + u.RequestURI(),
		"x-nordea-originating-host: " + u.Host,
		"x-nordea-originating-date: " + date,
	}
	names := "(request-target) x-nordea-originating-host x-nordea-originating-date"
	if ctype != "" {
		digest := digestOf(digestInput)
		hr.Header.Set("Content-Type", ctype)
		hr.Header.Set("Digest", digest)
		lines = append(lines, "content-type: "+ctype, "digest: "+digest)
		names += " content-type digest"
	}
	sig, err := c.sign(strings.Join(lines, "\n"))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Signature", fmt.Sprintf(`keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"`, c.cfg.Credentials.ClientID, names, sig))

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("nordea request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("nordea request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode,
		"transaction_id", res.Header.Get("X-Global-Transaction-Id"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
}

// decodedForm is what Nordea hashes for a form body's Digest: the fields
// sorted by name, joined as name=value, with values NOT URL-encoded. A digest
// over the encoded body is rejected ("error.digest.invalid").
func decodedForm(f url.Values) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range f[k] {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "&")
}

// sign makes the rsa-sha256 (PKCS #1 v1.5) signature of the signing string.
func (c *client) sign(s string) (string, error) {
	sum := sha256.Sum256([]byte(s))
	sig, err := c.cfg.Seal.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("nordea: sign request: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ---- errors ----

// errorBody is Nordea's error envelope: {"group_header": ..., "error":
// {"failures": [{"code", "description"}]}}. Token endpoints may also answer
// OAuth style ({"error": "invalid_grant", "error_description"}).
type errorBody struct {
	GroupHeader struct {
		MessageID string `json:"message_identification"`
	} `json:"group_header"`
	Error     json.RawMessage `json:"error"`
	OAuthDesc string          `json:"error_description"`
	Message   string          `json:"message"`
}

func parseError(b []byte) (code, text, id string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)])), ""
	}
	id = e.GroupHeader.MessageID
	var oauth string
	if json.Unmarshal(e.Error, &oauth) == nil && oauth != "" {
		return oauth, e.OAuthDesc, id
	}
	var env struct {
		Failures []struct {
			Code        string `json:"code"`
			Description string `json:"description"`
		} `json:"failures"`
	}
	if json.Unmarshal(e.Error, &env) == nil && len(env.Failures) > 0 {
		return env.Failures[0].Code, env.Failures[0].Description, id
	}
	return "", e.Message, id
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, Body: r.body}
	e.Code, e.Text, e.RequestID = parseError(r.body)
	if e.RequestID == "" {
		e.RequestID = r.header.Get("X-Global-Transaction-Id")
	}
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
