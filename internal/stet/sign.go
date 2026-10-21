package stet

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// Signing configures STET's http-signature (framework §3.5.1): a SHA-256
// Digest of the body and a draft-cavage-http-signatures Signature made with
// the QSealC over (request-target), Date, Content-Type and Content-Length
// when there is a body, Digest, X-Request-ID and every PSU-* header.
type Signing struct {
	// Required: refuse to build a client without Config.Seal. When false the
	// requests are signed only if a Seal is configured.
	Required bool

	// KeyID builds the keyId parameter. nil uses Seal.KeyID, which STET
	// wants to be either the key id the bank assigned at registration or a
	// URL of the QSealC ending in "_" plus its SHA-256 fingerprint.
	KeyID func(seal *obsdk.Seal) string

	// Algorithm is the algorithm parameter; empty is "rsa-sha256".
	Algorithm string

	// Headers is the list of signed headers, in order, when the bank wants
	// its own instead of the specification's. Besides header names (host is
	// the request's host) it may hold "(request-target)", "(created)" and
	// "(expires)"; the latter two also add the created and expires
	// parameters to the Signature header.
	Headers []string

	// Expires is how long a signature with "(expires)" is valid; default 30s.
	Expires time.Duration

	// SandboxValue is sent as the Signature header in the sandbox when no
	// Seal is configured, for banks whose sandbox wants the header but does
	// not check it. Required then applies to production only.
	SandboxValue string
}

// required reports whether the environment needs a Seal.
func (s *Signing) required(env obsdk.Env) bool {
	return s.Required && (s.SandboxValue == "" || env != obsdk.Sandbox)
}

func (s *Signing) keyID(seal *obsdk.Seal) string {
	if s.KeyID != nil {
		return s.KeyID(seal)
	}
	return seal.KeyID
}

// check reports a configured Seal that cannot sign.
func (s *Signing) check(seal *obsdk.Seal) error {
	if seal == nil || seal.Key == nil {
		return nil
	}
	if _, ok := seal.Key.Public().(*rsa.PublicKey); !ok {
		return fmt.Errorf("seal: the STET signature needs an RSA key (rsa-sha256)")
	}
	if s.keyID(seal) == "" {
		return fmt.Errorf("seal: no key id (Seal.KeyID: the URL of the QSealC or the id the bank assigned)")
	}
	return nil
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
}

// sign adds Digest and Signature to a request whose other headers are set.
func (s *Signing) sign(hr *http.Request, body []byte, seal *obsdk.Seal, env obsdk.Env, now time.Time) error {
	if seal == nil || seal.Key == nil {
		if s.SandboxValue != "" && env == obsdk.Sandbox {
			hr.Header.Set("Signature", s.SandboxValue)
			return nil
		}
		if s.required(env) {
			return fmt.Errorf("%w: signing needs Config.Seal", obsdk.ErrInvalidConfig)
		}
		return nil
	}
	if err := s.check(seal); err != nil {
		return fmt.Errorf("%w: %v", obsdk.ErrInvalidConfig, err)
	}
	hr.Header.Set("Digest", bodyDigest(body))

	target := hr.URL.EscapedPath()
	if hr.URL.RawQuery != "" {
		target += "?" + hr.URL.RawQuery
	}
	requestTarget := strings.ToLower(hr.Method) + " " + target
	var names, lines []string
	add := func(name, value string) {
		names = append(names, name)
		lines = append(lines, name+": "+value)
	}
	created, expires := now.Unix(), now.Add(s.expires()).Unix()
	var timeParams string
	if len(s.Headers) > 0 {
		for _, name := range s.Headers {
			switch name = strings.ToLower(name); name {
			case "(request-target)":
				add(name, requestTarget)
			case "(created)":
				add(name, strconv.FormatInt(created, 10))
				timeParams += ",created=" + strconv.FormatInt(created, 10)
			case "(expires)":
				add(name, strconv.FormatInt(expires, 10))
				timeParams += ",expires=" + strconv.FormatInt(expires, 10)
			case "host":
				add(name, strings.ToLower(hr.URL.Host))
			case "content-length":
				add(name, strconv.Itoa(len(body)))
			default:
				add(name, hr.Header.Get(name))
			}
		}
	} else {
		add("(request-target)", requestTarget)
		if v := hr.Header.Get("Date"); v != "" {
			add("date", v)
		}
		if len(body) > 0 {
			add("content-type", hr.Header.Get("Content-Type"))
			add("content-length", strconv.Itoa(len(body)))
		}
		add("digest", hr.Header.Get("Digest"))
		add("x-request-id", hr.Header.Get("X-Request-ID"))
		var psu []string
		for k := range hr.Header {
			if lk := strings.ToLower(k); strings.HasPrefix(lk, "psu-") {
				psu = append(psu, lk)
			}
		}
		sort.Strings(psu)
		for _, k := range psu {
			add(k, hr.Header.Get(k))
		}
	}

	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	sig, err := seal.Key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("stet: sign request: %w", err)
	}
	alg := firstNonEmpty(s.Algorithm, "rsa-sha256")
	hr.Header.Set("Signature", fmt.Sprintf(`keyId="%s",algorithm="%s",headers="%s"%s,signature="%s"`,
		strings.ReplaceAll(s.keyID(seal), `"`, "%22"), alg, strings.Join(names, " "), timeParams, base64.StdEncoding.EncodeToString(sig)))
	return nil
}

func (s *Signing) expires() time.Duration {
	if s.Expires > 0 {
		return s.Expires
	}
	return 30 * time.Second
}
