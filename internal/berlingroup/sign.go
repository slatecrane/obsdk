package berlingroup

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
)

// Signing configures the Berlin Group request signature (NextGenPSD2
// Implementation Guidelines, "Signatures"): a Digest of the body, a
// draft-cavage-http-signatures Signature made with the QSealC, and the QSealC
// itself in TPP-Signature-Certificate. Banks that want it say so in their
// documentation; most do not.
type Signing struct {
	// Required: refuse to build a client without Config.Seal. When false the
	// requests are signed only if a Seal is configured.
	Required bool

	// SHA512 uses SHA-512 for the Digest and the signature instead of SHA-256.
	SHA512 bool

	// Algorithm is the value of the signature's algorithm parameter. Empty is
	// "SHA-256" (or "SHA-512"), as in the guidelines' examples; banks differ
	// ("rsa-sha256", "SHA256withRSA").
	Algorithm string

	// KeyID builds the keyId parameter. Empty uses the guidelines' format:
	// SN=<serial in hex>,CA=<issuer DN>.
	KeyID func(cert *x509.Certificate) string

	// Date adds a Date header and signs it.
	Date bool
}

// signedHeaderNames are the headers the guidelines require (digest,
// x-request-id) or require when present.
var signedHeaderNames = []string{"date", "digest", "x-request-id", "psu-id", "psu-corporate-id", "tpp-redirect-uri"}

// DefaultKeyID is the guidelines' keyId: the certificate's serial number in
// hexadecimal and its issuer's distinguished name.
func DefaultKeyID(cert *x509.Certificate) string {
	return fmt.Sprintf("SN=%X,CA=%s", cert.SerialNumber, cert.Issuer.String())
}

func (s *Signing) hash() crypto.Hash {
	if s.SHA512 {
		return crypto.SHA512
	}
	return crypto.SHA256
}

func (s *Signing) digest(body []byte) string {
	if s.SHA512 {
		sum := sha512.Sum512(body)
		return "SHA-512=" + base64.StdEncoding.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(body)
	return "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
}

func (s *Signing) algorithm() string {
	switch {
	case s.Algorithm != "":
		return s.Algorithm
	case s.SHA512:
		return "SHA-512"
	}
	return "SHA-256"
}

// sign adds Digest, Signature and TPP-Signature-Certificate (and Date when
// configured) to a request whose other headers, X-Request-ID included, are
// already set.
func (s *Signing) sign(hr *http.Request, body []byte, seal *obsdk.Seal, date string) error {
	if seal == nil || seal.Key == nil || seal.Certificate == nil {
		return fmt.Errorf("%w: signing needs Config.Seal with a key and the QSealC certificate", obsdk.ErrInvalidConfig)
	}
	if _, ok := seal.Key.Public().(*rsa.PublicKey); !ok {
		return fmt.Errorf("%w: the Berlin Group signature needs an RSA QSealC key", obsdk.ErrInvalidConfig)
	}
	if s.Date {
		hr.Header.Set("Date", date)
	}
	hr.Header.Set("Digest", s.digest(body))
	hr.Header.Set("TPP-Signature-Certificate", base64.StdEncoding.EncodeToString(seal.Certificate.Raw))

	var names, lines []string
	for _, n := range signedHeaderNames {
		if v := hr.Header.Get(n); v != "" {
			names = append(names, n)
			lines = append(lines, n+": "+v)
		}
	}
	h := s.hash().New()
	h.Write([]byte(strings.Join(lines, "\n")))
	sig, err := seal.Key.Sign(rand.Reader, h.Sum(nil), s.hash())
	if err != nil {
		return fmt.Errorf("berlingroup: sign request: %w", err)
	}
	keyID := seal.KeyID
	if keyID == "" {
		f := s.KeyID
		if f == nil {
			f = DefaultKeyID
		}
		keyID = f(seal.Certificate)
	}
	hr.Header.Set("Signature", fmt.Sprintf(`keyId="%s",algorithm="%s",headers="%s",signature="%s"`,
		escapeKeyID(keyID), s.algorithm(), strings.Join(names, " "), base64.StdEncoding.EncodeToString(sig)))
	return nil
}

// escapeKeyID keeps the quoted keyId parameter well formed: issuer names can
// contain quotes, and the guidelines' examples percent-encode spaces.
func escapeKeyID(s string) string {
	return strings.NewReplacer(`"`, url.QueryEscape(`"`), " ", "%20").Replace(s)
}
