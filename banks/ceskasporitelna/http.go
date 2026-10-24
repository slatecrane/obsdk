package ceskasporitelna

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	opPayment      = "payment"
	opPaySign      = "payment_sign"
	opPayPoll      = "payment_poll"
	opPayStatus    = "payment_status"
)

// API roots under the API base.
const (
	aisRoot = "/account-information"
	pisRoot = "/payment-initiation"
)

type req struct {
	op     string
	method string
	url    string // absolute: the identity provider's endpoints
	path   string // relative to the API base, starting with "/"
	query  url.Values
	form   url.Values // identity provider: urlencoded
	body   []byte     // JSON
	bearer string
	header http.Header // extra headers (Callback-Uri)
	// pis marks payment calls, which are signed with the QSealC.
	pis bool
	// psu is set when the user is present (user-involved: true).
	psu *obsdk.PSUContext
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
			return nil, fmt.Errorf("ceskasporitelna: refusing to call %q: not a path on the API host", r.path)
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
	for k, vs := range r.header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	if r.url == "" {
		// The API; the identity provider takes no API key.
		hr.Header.Set("Web-Api-Key", c.apiKey)
		hr.Header.Set("User-Involved", strconv.FormatBool(r.psu != nil))
		hr.Header.Set("X-Request-Id", c.cfg.ID(obsdk.IDRequest))
		if r.psu != nil {
			if r.psu.IP != "" {
				hr.Header.Set("User-Ip-Address", r.psu.IP)
			}
			if r.psu.UserAgent != "" {
				hr.Header.Set("User-Agent", r.psu.UserAgent)
			}
		}
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if r.pis && c.cfg.Seal != nil {
		if err := c.sign(hr, body); err != nil {
			return nil, err
		}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("ceskasporitelna request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("ceskasporitelna request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode)
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// ---- signing ----

// signedHeaders are the headers ČS's payment API wants signed, in the order
// of its worked example ("How to use QSeal certificate").
var signedHeaders = []string{"authorization", "date", "digest", "web-api-key"}

// sign adds Date, Digest, Signature and TPP-Signature-Certificate: a
// draft-cavage HTTP signature (SHA256withRSA) made with the QSealC.
func (c *client) sign(hr *http.Request, body []byte) error {
	seal := c.cfg.Seal
	if seal.Key == nil || seal.Certificate == nil {
		return fmt.Errorf("%w: signing needs Config.Seal with a key and the QSealC certificate", obsdk.ErrInvalidConfig)
	}
	if _, ok := seal.Key.Public().(*rsa.PublicKey); !ok {
		return fmt.Errorf("%w: Česká spořitelna's signature needs an RSA QSealC key", obsdk.ErrInvalidConfig)
	}
	sum := sha256.Sum256(body)
	hr.Header.Set("Date", c.now().UTC().Format(http.TimeFormat))
	hr.Header.Set("Digest", "SHA-256="+base64.StdEncoding.EncodeToString(sum[:]))
	hr.Header.Set("TPP-Signature-Certificate", base64.StdEncoding.EncodeToString(seal.Certificate.Raw))
	var names, lines []string
	for _, n := range signedHeaders {
		if v := hr.Header.Get(n); v != "" {
			names = append(names, n)
			lines = append(lines, n+": "+v)
		}
	}
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	sig, err := seal.Key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("ceskasporitelna: sign request: %w", err)
	}
	keyID := seal.KeyID
	if keyID == "" {
		keyID = defaultKeyID(seal.Certificate)
	}
	hr.Header.Set("Signature", fmt.Sprintf(`keyId="%s",algorithm="SHA256withRSA",headers="%s",signature="%s"`,
		keyID, strings.Join(names, " "), base64.StdEncoding.EncodeToString(sig)))
	return nil
}

// defaultKeyID is ČS's keyId: the certificate's serial number in lower-case
// hexadecimal and its issuer's distinguished name, written as in ČS's
// example (unescaped, although the issuer may hold quotes).
func defaultKeyID(cert *x509.Certificate) string {
	return fmt.Sprintf("SN=%x,CA=%s", cert.SerialNumber, cert.Issuer.String())
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

// tokenCall posts to the identity provider's token endpoint with the
// client's id and secret in the body. A nil tokenResponse with a nil error
// means the bank refused; r carries the reply.
func (c *client) tokenCall(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	form.Set("client_id", c.cfg.Credentials.ClientID)
	form.Set("client_secret", c.cfg.Credentials.ClientSecret.Reveal())
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, url: c.idp + "/token", form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("ceskasporitelna: unreadable token response (HTTP %d)", r.status)
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

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running. ČS answers
// a missing, expired or revoked token with 403 TOKEN_INVALID (or
// TOKEN_MISSING), a bad web-api-key with 403 KEY_UNAUTHORIZED or 412
// KEY_DISABLED.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, Body: r.body, RequestID: r.header.Get("Web-Api-Correlation-Id")}
	e.Code, e.Text = cbs.ParseError(r.body)
	api := op != opToken && op != opRefresh && op != opRevoke
	switch {
	case r.status == http.StatusTooManyRequests || e.Code == "REQUEST_QUOTA_EXCEEDED":
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case api && (e.Code == "KEY_UNAUTHORIZED" || e.Code == "KEY_DISABLED" || e.Code == "CERTIFICATE_INVALID"):
		return e.Classify(obsdk.ErrInvalidConfig)
	case api && (r.status == http.StatusUnauthorized || e.Code == "TOKEN_INVALID" || e.Code == "TOKEN_MISSING"):
		return e.Classify(obsdk.ErrAccessExpired)
	case op == opRefresh && (e.Code == "invalid_grant" || e.Code == "request_error" || r.status == http.StatusUnauthorized):
		return &obsdk.ReauthError{Reason: "refresh_token_invalid", Err: e}
	case op == opToken && (e.Code == "invalid_grant" || e.Code == "invalid_request" || e.Code == "request_error"):
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
