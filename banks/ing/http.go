package ing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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
	opAppToken     = "app_token"
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
	path   string // "/path?query" relative to the API host
	query  url.Values
	form   url.Values // token endpoints: application/x-www-form-urlencoded, no JWS
	body   []byte     // JSON, sent and signed exactly as given
	header map[string]string
	bearer string
	signed bool // add Digest and X-JWS-Signature
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(ctx context.Context, r req) (*resp, error) {
	if !strings.HasPrefix(r.path, "/") {
		return nil, fmt.Errorf("ing: refusing to call %q: not a path on the API host", r.path)
	}
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

	body := r.body
	ctype := "application/json" // ING wants Content-Type on GETs too: it is part of the signature
	if r.form != nil {
		body, ctype = []byte(r.form.Encode()), "application/x-www-form-urlencoded"
	}
	hr, err := http.NewRequestWithContext(ctx, r.method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		hr.Body, hr.ContentLength = http.NoBody, 0
	}
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("Content-Type", ctype)
	hr.Header.Set("Date", c.now().UTC().Format(http.TimeFormat))
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if r.form == nil {
		hr.Header.Set("X-Request-ID", c.cfg.ID(obsdk.IDRequest))
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	if r.signed {
		digest := digestOf(body)
		target := strings.ToLower(r.method) + " " + u.RequestURI()
		sig, err := c.signJWS(target, digest, ctype)
		if err != nil {
			return nil, err
		}
		hr.Header.Set("Digest", digest)
		// Set the name in lower case, bypassing Go's canonical "X-Jws-Signature":
		// ING's payment gateway matches the name case-sensitively and answers
		// "Missing required 'x-jws-signature' header" to any other spelling.
		hr.Header["x-jws-signature"] = []string{sig}
	}

	res, err := c.http.Do(hr)
	if err != nil {
		c.log.Debug("ing request failed", "op", r.op, "method", r.method, "url", u.Redacted(), "err", err)
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	c.log.Debug("ing request", "op", r.op, "method", r.method, "url", u.Redacted(), "status", res.StatusCode,
		"response_id", res.Header.Get("X-ING-Response-ID"))
	return &resp{status: res.StatusCode, header: res.Header, body: b}, nil
}

// ---- signing ----

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
}

var b64url = base64.RawURLEncoding

// jwsAlg picks the JWS algorithm for the seal key.
func jwsAlg(k crypto.Signer) (string, error) {
	switch pk := k.Public().(type) {
	case *rsa.PublicKey:
		return "PS256", nil
	case *ecdsa.PublicKey:
		if pk.Curve.Params().BitSize == 256 {
			return "ES256", nil
		}
		return "", fmt.Errorf("EC keys must be P-256")
	default:
		return "", fmt.Errorf("unsupported key type %T", pk)
	}
}

// signJWS builds ING's X-JWS-Signature: a detached JWS (protected header,
// empty payload, signature) over "(request-target)", "digest" and
// "content-type", in that order, following the ETSI JAdES HTTP-headers
// profile ING uses (b64=false, sigD with mId .../HttpHeaders).
func (c *client) signJWS(target, digest, ctype string) (string, error) {
	seal := c.cfg.Seal
	alg, err := jwsAlg(seal.Key)
	if err != nil {
		return "", err
	}
	fp := sha256.Sum256(seal.Certificate.Raw)
	// Field order matters only for readability; ING verifies the encoded header as sent.
	header := struct {
		B64  bool     `json:"b64"`
		X5t  string   `json:"x5t#S256"`
		Crit []string `json:"crit"`
		SigT string   `json:"sigT"`
		SigD struct {
			Pars []string `json:"pars"`
			MID  string   `json:"mId"`
		} `json:"sigD"`
		Alg string `json:"alg"`
	}{B64: false, X5t: b64url.EncodeToString(fp[:]), Crit: []string{"sigT", "sigD", "b64"},
		SigT: c.now().UTC().Format("2006-01-02T15:04:05Z"), Alg: alg}
	header.SigD.Pars = []string{"(request-target)", "digest", "content-type"}
	header.SigD.MID = "http://uri.etsi.org/19182/HttpHeaders"
	hj, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	protected := b64url.EncodeToString(hj)
	input := protected + ".(request-target): " + target + "\ndigest: " + digest + "\ncontent-type: " + ctype
	sum := sha256.Sum256([]byte(input))

	var sig []byte
	switch alg {
	case "PS256":
		sig, err = seal.Key.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case "ES256":
		var der []byte
		if der, err = seal.Key.Sign(rand.Reader, sum[:], crypto.SHA256); err == nil {
			sig, err = ecdsaRaw(der, 32)
		}
	}
	if err != nil {
		return "", fmt.Errorf("ing: sign request: %w", err)
	}
	return protected + ".." + b64url.EncodeToString(sig), nil
}

// ecdsaRaw converts an ASN.1 ECDSA signature to the r||s form JWS uses.
func ecdsaRaw(der []byte, size int) ([]byte, error) {
	var s struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &s); err != nil {
		return nil, err
	}
	out := make([]byte, 2*size)
	s.R.FillBytes(out[:size])
	s.S.FillBytes(out[size:])
	return out, nil
}

// ---- application token ----

type tokenResponse struct {
	AccessToken           string      `json:"access_token"`
	TokenType             string      `json:"token_type"`
	ExpiresIn             json.Number `json:"expires_in"` // ING sends it as a number or a string
	RefreshToken          string      `json:"refresh_token"`
	RefreshTokenExpiresIn json.Number `json:"refresh_token_expires_in"`
	Scope                 string      `json:"scope"`
	ClientID              string      `json:"client_id"`
}

func seconds(n json.Number) time.Duration {
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

// token posts to /oauth2/token. A nil tokenResponse with a nil error means
// the bank refused; r carries the reply.
func (c *client) token(ctx context.Context, op string, form url.Values, bearer string) (*tokenResponse, *resp, error) {
	r, err := c.do(ctx, req{op: op, method: http.MethodPost, path: "/oauth2/token", form: form, bearer: bearer})
	if err != nil {
		return nil, nil, err
	}
	if r.status != http.StatusOK {
		return nil, r, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		return nil, r, fmt.Errorf("ing: unreadable token response (HTTP %d)", r.status)
	}
	return &tr, r, nil
}

// applicationToken returns an application access token (client credentials
// over mTLS), cached until shortly before it expires.
func (c *client) applicationToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.appToken != "" && now.Before(c.appExp) {
		return c.appToken, nil
	}
	tr, r, err := c.token(ctx, opAppToken, url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.Credentials.ClientID}}, "")
	if err != nil {
		return "", err
	}
	if tr == nil {
		return "", c.apiErr(opAppToken, r)
	}
	ttl := seconds(tr.ExpiresIn)
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	c.appToken, c.appExp = tr.AccessToken, now.Add(ttl-time.Minute)
	return c.appToken, nil
}

// ---- errors ----

// errorBody covers ING's shapes: Berlin Group style tppMessages, OAuth
// errors (error, error_description), the gateway's {"error": {"code",
// "message"}} and plain {"message": ...}.
type errorBody struct {
	TPPMessages []struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Text     string `json:"text"`
	} `json:"tppMessages"`
	Error     json.RawMessage `json:"error"` // a string (OAuth) or an object (gateway)
	OAuthDesc string          `json:"error_description"`
	Message   string          `json:"message"`
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
		return oauth, e.OAuthDesc
	}
	var gw struct{ Code, Message string }
	if json.Unmarshal(e.Error, &gw) == nil && gw.Code != "" {
		return gw.Code, gw.Message
	}
	return "", e.Message
}

// apiErr turns a failed response into the most specific error, using the
// status, the bank's code and the operation that was running.
func (c *client) apiErr(op string, r *resp) error {
	e := &obsdk.APIError{Op: op, Status: r.status, RequestID: r.header.Get("X-ING-Response-ID"), Body: r.body}
	e.Code, e.Text = parseError(r.body)
	ais := op == opAccounts || op == opBalances || op == opTransactions
	switch {
	case r.status == http.StatusTooManyRequests:
		return &obsdk.RateLimitedError{RetryAfter: retryAfter(r.header), Err: e.Classify(obsdk.ErrRateLimited)}
	case ais && r.status == http.StatusUnauthorized:
		return e.Classify(obsdk.ErrAccessExpired)
	case ais && r.status == http.StatusForbidden && e.Code == "SERVICE_BLOCKED":
		// The grant no longer covers the account, or more than 90 days of
		// history was asked for after the first read: either way the user
		// has to authorise again.
		return &obsdk.ReauthError{Reason: "grant_not_valid", Err: e}
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
