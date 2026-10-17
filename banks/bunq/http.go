package bunq

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
	opInstall      = "installation"
	opDevice       = "device_server"
	opSession      = "session_server"
	opRefresh      = "refresh"
	opLogout       = "logout"
	opAccounts     = "accounts"
	opBalances     = "balances"
	opTransactions = "transactions"
	opPayment      = "payment"
	opPayStatus    = "payment_status"
	opPayCancel    = "payment_cancel"
)

type req struct {
	op     string
	method string
	path   string // relative to the API base, starting with "/"
	query  url.Values
	body   []byte // JSON, sent and signed exactly as given
	auth   string // X-Bunq-Client-Authentication: installation or session token
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

// do sends a request to the API host. Every request carries bunq's
// mandatory headers; a body is signed with the installation key.
func (c *client) do(ctx context.Context, r req) (*resp, error) {
	if !strings.HasPrefix(r.path, "/") || strings.HasPrefix(r.path, "//") {
		return nil, fmt.Errorf("bunq: refusing to call %q: not a path on the API host", r.path)
	}
	u, err := url.Parse(c.api + r.path)
	if err != nil {
		return nil, err
	}
	if len(r.query) > 0 {
		u.RawQuery = r.query.Encode()
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), bytes.NewReader(r.body))
	if err != nil {
		return nil, err
	}
	if len(r.body) == 0 {
		hr.Body, hr.ContentLength = http.NoBody, 0
	}
	h := hr.Header
	h.Set("Accept", "application/json")
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-cache")
	h.Set("User-Agent", "obsdk")
	h.Set("X-Bunq-Language", "en_US")
	h.Set("X-Bunq-Region", "nl_NL")
	h.Set("X-Bunq-Geolocation", "0 0 0 0 000")
	h.Set("X-Bunq-Client-Request-Id", c.cfg.ID(obsdk.IDRequest))
	if r.auth != "" {
		h.Set("X-Bunq-Client-Authentication", r.auth)
	}
	if len(r.body) > 0 {
		sig, err := c.sign(r.body)
		if err != nil {
			return nil, err
		}
		h.Set("X-Bunq-Client-Signature", sig)
	}
	return c.send(hr, r.op)
}

func (c *client) send(hr *http.Request, op string) (*resp, error) {
	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("bunq request failed", "op", op, "method", hr.Method, "url", hr.URL.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("bunq request", "op", op, "method", hr.Method, "path", hr.URL.Path, "status", res.StatusCode,
		"response_id", res.Header.Get("X-Bunq-Client-Response-Id"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// sign is X-Bunq-Client-Signature: RSA PKCS#1 v1.5 over SHA-256 of the body.
func (c *client) sign(body []byte) (string, error) {
	sum := sha256.Sum256(body)
	sig, err := c.cfg.Seal.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("bunq: sign request: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ---- envelope ----

// envelope is bunq's response shape: a list of single-key objects, each
// keyed by its type ("Id", "Token", "MonetaryAccountBank", ...), plus
// Pagination on listings.
type envelope struct {
	Response   []map[string]json.RawMessage `json:"Response"`
	Pagination *pagination                  `json:"Pagination"`
}

type pagination struct {
	OlderURL  string `json:"older_url"`
	NewerURL  string `json:"newer_url"`
	FutureURL string `json:"future_url"`
}

func parseEnvelope(b []byte) (*envelope, error) {
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("bunq: unreadable response: %w", err)
	}
	return &e, nil
}

// first returns the first object of the given type in a response.
func (e *envelope) first(typ string) json.RawMessage {
	for _, m := range e.Response {
		if v, ok := m[typ]; ok {
			return v
		}
	}
	return nil
}

// createdID reads {"Response":[{"Id":{"id":N}}]}.
func createdID(b []byte) (string, error) {
	e, err := parseEnvelope(b)
	if err != nil {
		return "", err
	}
	var id struct {
		ID json.Number `json:"id"`
	}
	if raw := e.first("Id"); raw == nil || json.Unmarshal(raw, &id) != nil || id.ID == "" {
		return "", fmt.Errorf("bunq: response has no id")
	}
	return id.ID.String(), nil
}

// ---- errors ----

// errorBody covers bunq's {"Error":[{"error_description": ...}]} and the
// OAuth server's {"error", "error_description"}.
type errorBody struct {
	Error json.RawMessage `json:"Error"`
	OAuth string          `json:"error"`
	Desc  string          `json:"error_description"`
}

func parseError(b []byte) (code, text string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	if e.OAuth != "" {
		return e.OAuth, e.Desc
	}
	var list []struct {
		Desc string `json:"error_description"`
	}
	if json.Unmarshal(e.Error, &list) == nil && len(list) > 0 {
		return "", list[0].Desc
	}
	return "", ""
}

// rateText is how bunq words a 429: "You can do a maximum of 2 calls per 3 second to this endpoint."
var rateText = regexp.MustCompile(`per (\d+) second`)

// apiErr turns a failed response into the most specific error, using the
// status, bunq's description and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, RequestID: r.header.Get("X-Bunq-Client-Response-Id"), Body: r.body}
	e.Code, e.Text = parseError(r.body)
	user := op == opAccounts || op == opBalances || op == opTransactions || op == opPayment || op == opPayStatus || op == opPayCancel
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header, e.Text), Err: e.Classify(obsdk.ErrRateLimited)}
	case user && (r.status == http.StatusUnauthorized || r.status == http.StatusForbidden) && strings.Contains(e.Text, "authentication"):
		// "Insufficient authentication.": the session token expired, was
		// deleted, or the user revoked the access. Refresh tells which.
		return e.Classify(obsdk.ErrAccessExpired)
	case (op == opRefresh || op == opSession || op == opDevice) && credentialsRefused(r, e.Text):
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
	case op == opToken && r.status == http.StatusBadRequest:
		return e.Classify(obsdk.ErrAuthFailed)
	}
	return e
}

// credentialsRefused: bunq answers a revoked or unknown token with 400
// "User credentials are incorrect. Incorrect API key or IP address."
func credentialsRefused(r *resp, text string) bool {
	if r.status == http.StatusUnauthorized || r.status == http.StatusForbidden {
		return true
	}
	return r.status == http.StatusBadRequest && strings.Contains(strings.ToLower(text), "credentials are incorrect")
}

func retryAfter(h http.Header, text string) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	if m := rateText.FindStringSubmatch(text); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}
