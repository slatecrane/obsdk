package obsdktest

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/url"
	"strings"
)

// Redactor removes secrets and personal data from recorded exchanges so that
// fixtures are safe to commit. Redaction is deterministic and consistent: the
// same input always gives the same output, so values that the SDK copies from a
// response into a later request still match during replay.
//
// There are three kinds of rule:
//
//   - Literal secrets (your client id and secret) are replaced wherever they appear.
//   - Secret keys (tokens, codes) become "REDACTED:<key>:<digest>".
//   - Personal-data keys (names, IBANs, remittance text) become stable pseudonyms.
//
// Always skim a new fixture before committing it: no automatic redaction is complete.
type Redactor struct {
	// Literals maps a secret value to the label used in its placeholder.
	Literals map[string]string
	// SecretKeys are header, query and JSON key names (case-insensitive) whose values are replaced.
	SecretKeys map[string]bool
	// PIIKeys are JSON key names whose string values are pseudonymized.
	PIIKeys map[string]bool
	// KeepQueryInURLs are query parameters preserved when redacting URLs in Location headers and callbacks.
	KeepQueryInURLs map[string]bool
}

// DefaultRedactor covers common secret and personal-data fields. literals maps
// known secret values (client id, client secret, ...) to labels.
func DefaultRedactor(literals map[string]string) *Redactor {
	r := &Redactor{Literals: map[string]string{}, SecretKeys: set(
		"authorization", "cookie", "set-cookie", "x-api-key", "psu-id", "psu-corporate-id", "psu-ip-address", "x-fapi-customer-ip-address",
		"client_secret", "client_id", "app-id", "apikey", "refresh_token", "access_token", "id_token",
		"code", "access_code", "authorizationcode", "authorization_code", "otp", "password",
		"personalid", "personal_id", "phonenumber", "phone_number", "psu_id", "psuid", "clientid",
	), PIIKeys: set(
		"ownername", "name", "creditorname", "debtorname", "ultimatecreditor", "ultimatedebtor", "creditorid", "debtorid",
		"iban", "bban", "remittanceinformationunstructured", "remittanceinformationstructured", "remittanceinformationunstructuredarray",
		"messagetoreceiver", "notetoself", "receiver", "reference", "numbergiro", "accountfrom", "accountto", "unstructured",
		// UK OBIE style (Revolut)
		"identification", "secondaryidentification", "transactioninformation", "nickname",
	), KeepQueryInURLs: set("state", "response_type", "scope", "bic", "redirect_uri", "language")}
	for v, label := range literals {
		if v != "" {
			r.Literals[v] = label
		}
	}
	return r
}

func set(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func placeholder(label string) string { return "REDACTED:" + label }

// mask hides a secret value. Literals map to their plain label so that the
// credentials a test configures ("REDACTED:client_id") match what was
// recorded. Other secrets get a short stable digest, so two different tokens
// stay distinguishable in fixtures and golden files (a rotated refresh token
// must not look like the old one). Masking is idempotent: a placeholder passes
// through unchanged, which is what lets replayed values match recorded ones.
func (r *Redactor) mask(label, value string) string {
	if value == "" || strings.HasPrefix(value, "REDACTED:") {
		return value
	}
	if l, ok := r.Literals[value]; ok {
		return placeholder(l)
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	return fmt.Sprintf("%s:%06x", placeholder(label), h.Sum32()&0xffffff)
}

// Text replaces literal secrets inside any string.
func (r *Redactor) Text(s string) string {
	for v, label := range r.Literals {
		s = strings.ReplaceAll(s, v, placeholder(label))
	}
	return s
}

// Header redacts a header value.
func (r *Redactor) Header(name, value string) string {
	if r.SecretKeys[strings.ToLower(name)] {
		return r.mask(strings.ToLower(name), value)
	}
	if strings.EqualFold(name, "location") {
		return r.URL(value)
	}
	return r.Text(value)
}

// QueryValue redacts a query parameter value.
func (r *Redactor) QueryValue(key, value string) string {
	if r.SecretKeys[strings.ToLower(key)] {
		return r.mask(strings.ToLower(key), value)
	}
	return r.Text(value)
}

// Form redacts an application/x-www-form-urlencoded body: secret keys are
// masked, other values only lose literal secrets.
func (r *Redactor) Form(body string) string {
	vals, err := url.ParseQuery(body)
	if err != nil {
		return r.Text(body)
	}
	for k, vs := range vals {
		for i, v := range vs {
			vs[i] = r.QueryValue(k, v)
		}
	}
	return vals.Encode()
}

// URL redacts the query of a URL, a path with query, or a bare query string
// (callbacks). Parameters in KeepQueryInURLs survive, except secret keys.
func (r *Redactor) URL(raw string) string {
	prefix, query, frag := raw, "", ""
	if i := strings.Index(prefix, "#"); i >= 0 {
		prefix, frag = prefix[:i], prefix[i+1:]
	}
	hasQuestion := strings.Contains(prefix, "?")
	switch {
	case hasQuestion:
		i := strings.Index(prefix, "?")
		prefix, query = prefix[:i], prefix[i+1:]
	case !strings.Contains(prefix, "://") && !strings.HasPrefix(prefix, "/") && strings.Contains(prefix, "="):
		prefix, query = "", prefix // bare query string
	}
	redactQS := func(qs string) string {
		vals, err := url.ParseQuery(qs)
		if err != nil {
			return r.Text(qs)
		}
		for k, vs := range vals {
			for i, v := range vs {
				switch {
				case r.SecretKeys[strings.ToLower(k)]:
					vs[i] = r.mask(strings.ToLower(k), v)
				case r.KeepQueryInURLs[strings.ToLower(k)]:
					vs[i] = r.Text(v)
				default:
					vs[i] = r.mask(strings.ToLower(k), v)
				}
			}
		}
		return vals.Encode()
	}
	out := r.Text(prefix)
	if query != "" {
		out += map[bool]string{true: "?", false: ""}[prefix != ""] + redactQS(query)
	}
	if frag != "" {
		out += "#" + redactQS(frag)
	}
	return out
}

// JSON redacts a JSON document. Invalid JSON is returned unchanged except for literal secrets.
func (r *Redactor) JSON(b []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []byte(r.Text(string(b)))
	}
	out, err := json.MarshalIndent(r.walk("", v, false), "", "  ")
	if err != nil {
		return []byte(r.Text(string(b)))
	}
	return out
}

// jsonPlain lists keys that are secret in queries and headers but, inside JSON
// bodies, usually carry harmless values: "code" is an OAuth authorization code
// in a callback query but an error code ("MISSING_BANK_ID") in a response, and
// the SDK's behaviour depends on error codes. Add a literal if a bank puts a
// real secret under such a key.
var jsonPlain = set("code")

func (r *Redactor) walk(key string, v any, pii bool) any {
	lk := strings.ToLower(key)
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = r.walk(k, x, pii || r.PIIKeys[strings.ToLower(k)])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = r.walk(key, x, pii)
		}
		return out
	case string:
		switch {
		case r.SecretKeys[lk] && !jsonPlain[lk]:
			return r.mask(lk, t)
		case pii && r.PIIKeys[lk]:
			return pseudonym(lk, t)
		}
		return r.Text(t)
	case json.Number, bool, nil:
		if r.SecretKeys[lk] && !jsonPlain[lk] && v != nil {
			return r.mask(lk, fmt.Sprint(v))
		}
		return v
	}
	return v
}

// pseudonym is a stable, readable stand-in for personal data. IBANs keep their
// country code because it can matter to the logic being tested.
func pseudonym(kind, s string) string {
	if s == "" {
		return s
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	sum := fmt.Sprintf("%016x", h.Sum64())
	switch kind {
	case "iban":
		if len(s) >= 2 {
			return s[:2] + "00PSEUDO" + strings.ToUpper(sum[:10])
		}
	case "bban":
		return "00PSEUDO" + strings.ToUpper(sum[:8])
	}
	return kind + "-" + sum[:6]
}

// Zip redacts every JSON file inside a ZIP archive and rebuilds it. Other
// files are dropped, since their content can't be checked.
func (r *Redactor) Zip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if err != nil {
			return nil, err
		}
		w, err := zw.Create(r.Text(f.Name))
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(r.JSON(b)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
