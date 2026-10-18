package obie

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const (
	// defaultRequestObjectTTL is how long the signed request object is valid
	// unless the profile says otherwise.
	defaultRequestObjectTTL = 10 * time.Minute
	// assertionTTL is the lifetime of a private_key_jwt client assertion.
	assertionTTL = 5 * time.Minute

	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// kid is the key id of every JWS: Profile.KeyID, else Seal.KeyID.
func (c *client) kid() string {
	if c.p.KeyID != nil {
		return c.p.KeyID(c.cfg.Seal)
	}
	return c.cfg.Seal.KeyID
}

// SerialKeyID is a Profile.KeyID for banks that identify the signing
// certificate by its serial number in decimal. Seal.KeyID, when set, wins.
func SerialKeyID(seal *obsdk.Seal) string {
	if seal.KeyID != "" {
		return seal.KeyID
	}
	if seal.Certificate != nil && seal.Certificate.SerialNumber != nil {
		return seal.Certificate.SerialNumber.String()
	}
	return ""
}

// certDN is the signing certificate's subject DN, or "".
func (c *client) certDN() string {
	if c.cfg.Seal.Certificate == nil {
		return ""
	}
	return RFC2253(c.cfg.Seal.Certificate.RawSubject)
}

// clientAssertion signs the private_key_jwt that authenticates the client at
// the token endpoint (iss = sub = client id, aud = the token endpoint).
func (c *client) clientAssertion() (string, error) {
	now := c.now()
	claims := map[string]any{
		"iss": c.cfg.Credentials.ClientID, "sub": c.cfg.Credentials.ClientID,
		"aud": c.host + c.p.TokenPath, "jti": c.cfg.ID(obsdk.IDRequest),
		"iat": now.Unix(), "exp": now.Add(assertionTTL).Unix(),
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return c.signJWS(map[string]any{"alg": "PS256", "kid": c.kid(), "typ": "JWT"}, p, false)
}

type intentClaim struct {
	Value     string `json:"value"`
	Essential bool   `json:"essential"`
}

// signRequestObject builds the JWT that carries the consent to the
// authorisation page. scope is "accounts" or "payments".
func (c *client) signRequestObject(intentID, redirectURI, state, nonce, scope string) (string, error) {
	now := c.now()
	ttl := c.p.RequestObjectTTL
	if ttl <= 0 {
		ttl = defaultRequestObjectTTL
	}
	iss := c.cfg.Credentials.ClientID
	if c.p.RequestObjectIssuer == IssuerCertDN {
		iss = c.certDN()
	}
	claims := map[string]any{
		"iss": iss, "aud": c.host,
		"response_type": "code id_token", "client_id": c.cfg.Credentials.ClientID,
		"redirect_uri": redirectURI, "scope": "openid " + scope, "state": state, "nonce": nonce,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": c.cfg.ID(obsdk.IDRequest),
		"claims": map[string]any{
			"userinfo": map[string]any{"openbanking_intent_id": intentClaim{Value: intentID, Essential: true}},
			"id_token": map[string]any{"openbanking_intent_id": intentClaim{Value: intentID, Essential: true}},
		},
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return c.signJWS(map[string]any{"alg": "PS256", "kid": c.kid(), "typ": "JWT"}, p, false)
}

// OBIE JWS header claims for x-jws-signature.
const (
	claimIAT = "http://openbanking.org.uk/iat"
	claimISS = "http://openbanking.org.uk/iss"
	claimTAN = "http://openbanking.org.uk/tan"
)

// signBody returns the detached JWS of a request body for x-jws-signature.
// iss is the signing certificate's subject DN. body must be the exact bytes sent.
func (c *client) signBody(body []byte) (string, error) {
	sig := c.p.Signature
	if c.cfg.Seal.Certificate == nil {
		return "", &obsdk.ConfigError{Bank: c.target.Bank, Env: c.cfg.Env, Missing: []string{"seal.Certificate (its subject DN is signed into x-jws-signature)"}}
	}
	tan := "openbanking.org.uk"
	if sig.TAN != nil {
		tan = sig.TAN(c.cfg, c.hostName())
	}
	crit := []string{claimIAT, claimISS, claimTAN}
	h := map[string]any{"alg": "PS256", "kid": c.kid(), claimIAT: c.now().Unix(), claimISS: c.certDN(), claimTAN: tan}
	if sig.Unencoded {
		h["b64"] = false
		crit = append([]string{"b64"}, crit...)
	}
	h["crit"] = crit
	if sig.Typ != "" {
		h["typ"] = sig.Typ
	}
	if sig.Cty != "" {
		h["cty"] = sig.Cty
	}
	return c.signJWS(h, body, true)
}

// signJWS signs PS256. detached leaves the payload out ("header..signature").
// A header with "b64": false signs the payload unencoded (RFC 7797).
func (c *client) signJWS(header map[string]any, payload []byte, detached bool) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	hp := enc.EncodeToString(h)
	pp := enc.EncodeToString(payload)
	input := hp + "." + pp
	if b64, ok := header["b64"].(bool); ok && !b64 {
		input = hp + "." + string(payload)
	}
	sum := sha256.Sum256([]byte(input))
	sig, err := c.cfg.Seal.Key.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return "", fmt.Errorf("obie: signing: %w", err)
	}
	if detached {
		pp = ""
	}
	return hp + "." + pp + "." + enc.EncodeToString(sig), nil
}

// attrNames are the short names openssl uses for subject attributes.
var attrNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
	"2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.97": "organizationIdentifier",
	"0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "emailAddress",
}

// RFC2253 formats a DER subject like `openssl x509 -subject -nameopt
// RFC2253`: the RDNs in reverse order, attributes by their short names. It
// works on the raw subject because pkix.Name does not keep the order.
func RFC2253(raw []byte) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		return ""
	}
	var parts []string
	for i := len(rdns) - 1; i >= 0; i-- {
		var atvs []string
		for _, atv := range rdns[i] {
			name, ok := attrNames[atv.Type.String()]
			if !ok {
				name = atv.Type.String()
			}
			atvs = append(atvs, name+"="+escapeDN(fmt.Sprint(atv.Value)))
		}
		parts = append(parts, strings.Join(atvs, "+"))
	}
	return strings.Join(parts, ",")
}

func escapeDN(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case strings.ContainsRune(`,+"\<>;`, r), r == '#' && i == 0, r == ' ' && (i == 0 || i == len(s)-1):
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
