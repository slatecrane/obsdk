package rabobank

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
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
	opPayStatus    = "payment_status"
	opPayCancel    = "payment_cancel"
)

type req struct {
	op     string
	method string
	oauth  bool   // call the OAuth host instead of the API host
	path   string // relative to the host's base, starting with "/"
	query  url.Values
	form   url.Values // token endpoint: urlencoded, HTTP Basic, not signed
	body   []byte     // JSON, sent and digested exactly as given
	header map[string]string
	bearer string
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	if !strings.HasPrefix(r.path, "/") {
		return nil, fmt.Errorf("rabobank: refusing to call %q: not a path on the API host", r.path)
	}
	base := c.api
	if r.oauth {
		base = c.oauth
	}
	u, err := url.Parse(base + r.path)
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
	if r.form != nil {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hr.SetBasicAuth(c.cfg.Credentials.ClientID, c.cfg.Credentials.ClientSecret.Reveal())
	} else {
		if len(body) > 0 {
			hr.Header.Set("Content-Type", "application/json")
		}
		if r.bearer != "" {
			hr.Header.Set("Authorization", "Bearer "+r.bearer)
		}
		hr.Header.Set("X-IBM-Client-Id", c.cfg.Credentials.ClientID)
		for k, v := range r.header {
			hr.Header.Set(k, v)
		}
		if err := c.sign(hr, body); err != nil {
			return nil, err
		}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("rabobank request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("rabobank request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode,
		"request_id", res.Header.Get("X-Request-ID"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// ---- signing ----

// digestOf is Rabobank's Digest header: SHA-512 of the exact body bytes (an
// empty body for GET and DELETE).
func digestOf(body []byte) string {
	sum := sha512.Sum512(body)
	return "sha-512=" + base64.StdEncoding.EncodeToString(sum[:])
}

// certHeader is TPP-Signature-Certificate: the PEM body without its armour
// and line breaks, i.e. the DER in standard base64.
func certHeader(der []byte) string { return base64.StdEncoding.EncodeToString(der) }

// signedHeaders lists what the signature covers, in signing-string order.
// TPP-Redirect-URI is covered whenever it is sent (payment creation requires it).
func signedHeaders(h http.Header) []string {
	names := []string{"date", "digest", "x-request-id"}
	if h.Get("TPP-Redirect-URI") != "" {
		names = append(names, "tpp-redirect-uri")
	}
	return names
}

// signingString joins "name: value" lines for the signed headers.
func signingString(h http.Header, names []string) string {
	lines := make([]string, len(names))
	for i, n := range names {
		lines[i] = n + ": " + h.Get(n)
	}
	return strings.Join(lines, "\n")
}

// sign adds Date, Digest, X-Request-ID, TPP-Signature-Certificate and the
// draft-cavage Signature (rsa-sha512; keyId is the certificate's serial
// number in decimal).
func (c *client) sign(hr *http.Request, body []byte) error {
	hr.Header.Set("Date", c.now().UTC().Format(http.TimeFormat))
	hr.Header.Set("Digest", digestOf(body))
	hr.Header.Set("X-Request-ID", c.cfg.ID(obsdk.IDRequest))
	hr.Header.Set("TPP-Signature-Certificate", c.cert)
	names := signedHeaders(hr.Header)
	sum := sha512.Sum512([]byte(signingString(hr.Header, names)))
	sig, err := c.cfg.Seal.Key.Sign(rand.Reader, sum[:], crypto.SHA512)
	if err != nil {
		return fmt.Errorf("rabobank: sign request: %w", err)
	}
	hr.Header.Set("Signature", fmt.Sprintf(`keyId="%s",algorithm="rsa-sha512",headers="%s",signature="%s"`,
		c.keyID, strings.Join(names, " "), base64.StdEncoding.EncodeToString(sig)))
	return nil
}

// ---- tokens ----

type tokenResponse struct {
	AccessToken           string      `json:"access_token"`
	TokenType             string      `json:"token_type"`
	ExpiresIn             json.Number `json:"expires_in"`
	RefreshToken          string      `json:"refresh_token"`
	RefreshTokenExpiresIn json.Number `json:"refresh_token_expires_in"`
	Scope                 string      `json:"scope"`
	ConsentedOn           json.Number `json:"consented_on"` // epoch seconds
	Metadata              string      `json:"metadata"`     // "a:consentId <id>"
}

func seconds(n json.Number) time.Duration {
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

// consentID reads the consent id from the token's metadata, which Rabobank
// sends as "a:consentId <id>".
func (t *tokenResponse) consentID() string {
	f := strings.Fields(t.Metadata)
	for i := 0; i+1 < len(f); i++ {
		if strings.HasSuffix(f[i], "consentId") {
			return f[i+1]
		}
	}
	return ""
}

// token posts to the OAuth token endpoint. A nil tokenResponse with a nil
// error means the bank refused; r carries the reply.
func (c *client) token(ctx context.Context, op string, form url.Values) (*tokenResponse, *resp, error) {
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, oauth: true, path: "/token", form: form})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("rabobank: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// ---- errors ----

// errorBody covers Rabobank's shapes: Berlin Group tppMessages (payments),
// problem details {"code", "title", "type"} (account information), OAuth
// errors (error, error_description) and the API gateway's
// {"httpCode", "httpMessage", "moreInformation"}.
type errorBody struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	TPPMessages []struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Text     string `json:"text"`
	} `json:"tppMessages"`
	Error           string `json:"error"`
	ErrorDesc       string `json:"error_description"`
	HTTPMessage     string `json:"httpMessage"`
	MoreInformation string `json:"moreInformation"`
}

func parseError(b []byte) (code, text string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	switch {
	case len(e.TPPMessages) > 0:
		return e.TPPMessages[0].Code, e.TPPMessages[0].Text
	case e.Code != "":
		return e.Code, e.Title
	case e.Error != "":
		return e.Error, e.ErrorDesc
	case e.MoreInformation != "":
		// The gateway puts a code (CONSENT_INVALID, FORBIDDEN) or a sentence here.
		if !strings.Contains(e.MoreInformation, " ") {
			return e.MoreInformation, e.HTTPMessage
		}
		return "", e.MoreInformation
	}
	return "", e.HTTPMessage
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, RequestID: r.header.Get("X-Request-ID"), Body: r.body}
	e.Code, e.Text = parseError(r.body)
	ais := op == opAccounts || op == opBalances || op == opTransactions
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case ais && r.status == http.StatusUnauthorized:
		// An expired token, or a revoked consent (which voids the tokens).
		return e.Classify(obsdk.ErrAccessExpired)
	case ais && r.status == http.StatusForbidden && strings.HasPrefix(e.Code, "CONSENT_"):
		return &obsdk.ReauthError{Reason: "consent_invalid", Consent: consentKind, Err: e}
	case op == opRefresh && e.Code == "invalid_grant":
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
