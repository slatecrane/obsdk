package obsdktest

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"sync"
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

	// seen maps account numbers already pseudonymized under a key to their
	// pseudonym, so the same number is also replaced inside free text (banks
	// echo the payee's IBAN in messages such as Swedbank's psuMessage).
	mu   sync.Mutex
	seen map[string]string
}

// DefaultRedactor covers common secret and personal-data fields. literals maps
// known secret values (client id, client secret, ...) to labels.
func DefaultRedactor(literals map[string]string) *Redactor {
	r := &Redactor{Literals: map[string]string{}, SecretKeys: set(
		"authorization", "cookie", "set-cookie", "x-api-key", "ocp-apim-subscription-key", "subscription_key", "psu-id", "psu-corporate-id", "psu-ip-address", "x-fapi-customer-ip-address",
		"client_secret", "client_id", "client_assertion", "x-jws-signature", "app-id", "apikey", "refresh_token", "access_token", "id_token", "token",
		"code", "access_code", "authorizationcode", "authorization_code", "auth_code", "otp", "password", "scaauthenticationdata",
		"personalid", "personal_id", "phonenumber", "phone_number", "psu_id", "psuid", "clientid",
		// bunq: tokens travel in X-Bunq-Client-Authentication, API keys and OAuth tokens as "secret"
		"x-bunq-client-authentication", "x-bunq-client-signature", "x-bunq-server-signature", "secret", "api_key", "login_code",
		// ABN AMRO: the application's API key
		"api-key",
		// Česká spořitelna: the portal application's API key
		"web-api-key",
	), PIIKeys: set(
		"ownername", "name", "creditorname", "debtorname", "ultimatecreditor", "ultimatedebtor", "creditorid", "debtorid",
		"iban", "bban", "remittanceinformationunstructured", "remittanceinformationstructured", "remittanceinformationunstructuredarray",
		"messagetoreceiver", "notetoself", "receiver", "reference", "numbergiro", "accountfrom", "accountto", "unstructured",
		// UK OBIE style (Revolut)
		"identification", "secondaryidentification", "transactioninformation", "nickname",
		// ING card accounts
		"maskedpan", "transactiondetails",
		// bunq users, labels and payment descriptions
		"display_name", "public_nick_name", "first_name", "middle_name", "last_name", "legal_name", "description",
		"date_of_birth", "place_of_birth", "country_of_birth", "street", "house_number", "po_box", "postal_code", "city",
		"tax_number", "document_number", "chamber_of_commerce_number", "swift_account_number", "mailbox_name", "gender",
		// ABN AMRO account details and activities
		"accountnumber", "accountholdername", "counterpartyaccountnumber", "counterpartyname", "descriptionlines",
	), KeepQueryInURLs: set("state", "response_type", "scope", "bic", "redirect_uri", "language", "success")}
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

// labelAliases gives one label to keys that carry the same secret under
// different names, so a value recorded in one place matches it in another
// (Nordea returns ?auth_code=... and takes it back as code=...).
var labelAliases = map[string]string{"auth_code": "code", "authorization_code": "code", "authorizationcode": "code", "access_code": "code"}

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
	if l, ok := labelAliases[label]; ok {
		label = l
	}
	if l, ok := r.Literals[value]; ok {
		return placeholder(l)
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	return fmt.Sprintf("%s:%06x", placeholder(label), h.Sum32()&0xffffff)
}

// Text replaces literal secrets, and account numbers seen earlier, inside any string.
func (r *Redactor) Text(s string) string {
	for v, label := range r.Literals {
		s = strings.ReplaceAll(s, v, placeholder(label))
	}
	r.mu.Lock()
	for raw, p := range r.seen {
		s = strings.ReplaceAll(s, raw, p)
	}
	r.mu.Unlock()
	return s
}

// account pseudonymizes an account number and remembers it for Text.
func (r *Redactor) account(kind, raw string) string {
	p := pseudonym(kind, raw)
	if len(raw) >= 8 && p != raw {
		r.mu.Lock()
		if r.seen == nil {
			r.seen = map[string]string{}
		}
		r.seen[raw] = p
		r.mu.Unlock()
	}
	return p
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
		r.pointer(t, out)
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
		case pii && (lk == "iban" || lk == "bban"):
			return r.account(lk, t)
		case pii && (lk == "accountnumber" || lk == "counterpartyaccountnumber"):
			// ABN AMRO: an IBAN, or a domestic number for foreign counterparties.
			if ibanLike(t) {
				return r.account("iban", t)
			}
			return r.account("bban", t)
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

var ibanLikeRE = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)

func ibanLike(s string) bool { return ibanLikeRE.MatchString(s) }

// pointer pseudonymizes the value of an alias such as bunq's
// {"type": "EMAIL", "value": "...", "name": "..."}, whose key ("value") is
// too generic to list: amounts use it too.
func (r *Redactor) pointer(in, out map[string]any) {
	typ, _ := in["type"].(string)
	v, ok := in["value"].(string)
	if !ok || v == "" {
		return
	}
	switch typ {
	case "IBAN":
		out["value"] = r.account("iban", v)
	case "EMAIL":
		out["value"] = pseudonym("email", v) + "@example.com"
	case "PHONE_NUMBER":
		out["value"] = pseudonym("phone", v)
	}
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
			// Valid check digits, so the payment validation accepts it.
			return pseudoIBAN(s[:2], "PSEUDO"+strings.ToUpper(sum[:10]))
		}
	case "bban":
		// A number written with digits and separators (6154923450017,
		// 8327-9,123456789) gets digits of the same count, first digit kept:
		// the stand-in still passes format checks, and a Swedish clearing
		// range (6xxx Handelsbanken, 8xxx Swedbank) still routes the same.
		if d := strings.Map(digitOnly, s); len(d) >= 6 && strings.Trim(s, "0123456789 -,.") == "" {
			digits := fmt.Sprintf("%020d", h.Sum64())
			return d[:1] + digits[len(digits)-len(d)+1:]
		}
		return "00PSEUDO" + strings.ToUpper(sum[:8])
	case "sortcode":
		// 14 digits, so it still passes as a UK sort code and account number.
		return fmt.Sprintf("%014d", h.Sum64()%100000000000000)
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

// pseudoIBAN builds an IBAN with ISO 7064 check digits.
func pseudoIBAN(country, bban string) string {
	var b strings.Builder
	for _, c := range bban + country + "00" {
		if c >= 'A' && c <= 'Z' {
			fmt.Fprintf(&b, "%d", c-'A'+10)
		} else {
			b.WriteRune(c)
		}
	}
	n, _ := new(big.Int).SetString(b.String(), 10)
	return fmt.Sprintf("%s%02d%s", country, 98-new(big.Int).Mod(n, big.NewInt(97)).Int64(), bban)
}

func digitOnly(r rune) rune {
	if r >= '0' && r <= '9' {
		return r
	}
	return -1
}
