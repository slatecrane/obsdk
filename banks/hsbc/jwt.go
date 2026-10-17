package hsbc

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
	// requestObjectTTL is how long the signed request object is valid. HSBC
	// wants exp at most 30 minutes ahead.
	requestObjectTTL = 10 * time.Minute
	// assertionTTL is the lifetime of a private_key_jwt client assertion.
	assertionTTL = 5 * time.Minute

	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	scaACR        = "urn:openbanking:psd2:sca"
)

// tokenPath is the token endpoint on every brand's API host.
const tokenPath = "/obie/open-banking/v1.1/oauth2/token"

// clientAssertion signs the private_key_jwt that authenticates the client at
// the token endpoint (iss = sub = client id, aud = the token endpoint).
func (c *client) clientAssertion() (string, error) {
	now := c.now()
	claims := map[string]any{
		"iss": c.cfg.Credentials.ClientID, "sub": c.cfg.Credentials.ClientID,
		"aud": c.brand.apiHost(c.cfg.Env) + tokenPath, "jti": c.cfg.ID(obsdk.IDRequest),
		"iat": now.Unix(), "exp": now.Add(assertionTTL).Unix(),
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return signJWS(c.cfg.Seal, map[string]any{"alg": "PS256", "kid": c.cfg.Seal.KeyID, "typ": "JWT"}, p, false)
}

type intentClaim struct {
	Value     string `json:"value"`
	Essential bool   `json:"essential"`
}

type acrClaim struct {
	Essential bool     `json:"essential"`
	Values    []string `json:"values"`
}

// signRequestObject builds the JWT that carries the consent id to the
// authorisation page. scope is "accounts" or "payments"; aud is the issuer
// (the brand's API host).
func (c *client) signRequestObject(consentID, redirectURI, state, nonce, scope string) (string, error) {
	now := c.now()
	claims := map[string]any{
		"iss": c.cfg.Credentials.ClientID, "aud": c.brand.apiHost(c.cfg.Env),
		"response_type": "code id_token", "client_id": c.cfg.Credentials.ClientID,
		"redirect_uri": redirectURI, "scope": "openid " + scope, "state": state, "nonce": nonce,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(requestObjectTTL).Unix(), "jti": c.cfg.ID(obsdk.IDRequest),
		"claims": map[string]any{
			"userinfo": map[string]any{"openbanking_intent_id": intentClaim{Value: consentID, Essential: true}},
			"id_token": map[string]any{
				"openbanking_intent_id": intentClaim{Value: consentID, Essential: true},
				"acr":                   acrClaim{Essential: true, Values: []string{scaACR}},
			},
		},
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return signJWS(c.cfg.Seal, map[string]any{"alg": "PS256", "kid": c.cfg.Seal.KeyID, "typ": "JWT"}, p, false)
}

// OBIE JWS header claims for x-jws-signature.
const (
	claimIAT = "http://openbanking.org.uk/iat"
	claimISS = "http://openbanking.org.uk/iss"
	claimTAN = "http://openbanking.org.uk/tan"
)

// defaultTAN is the trust anchor of OBIE-issued certificates.
const defaultTAN = "openbanking.org.uk"

// signBody returns the detached JWS of a request body for x-jws-signature.
// HSBC wants iss to be the full subject DN of the signing certificate
// (RFC 2253, as openssl prints it). body must be the exact bytes sent.
func (c *client) signBody(body []byte) (string, error) {
	seal := c.cfg.Seal
	if seal.Certificate == nil {
		return "", &obsdk.ConfigError{Bank: c.brand.bank, Env: c.cfg.Env, Missing: []string{"seal.Certificate (its subject DN is signed into x-jws-signature)"}}
	}
	tan := c.cfg.Param(paramJWSTan)
	if tan == "" {
		tan = defaultTAN
	}
	h := map[string]any{
		"alg": "PS256", "kid": seal.KeyID, "typ": "JOSE", "cty": "application/json",
		"crit":   []string{claimIAT, claimISS, claimTAN},
		claimIAT: c.now().Unix(), claimISS: rfc2253(seal.Certificate.RawSubject), claimTAN: tan,
	}
	return signJWS(seal, h, body, true)
}

// attrNames are the short names openssl uses for subject attributes.
var attrNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
	"2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.97": "organizationIdentifier",
	"0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "emailAddress",
}

// rfc2253 formats a DER subject like `openssl x509 -subject -nameopt
// RFC2253`: the RDNs in reverse order, attributes by their short names. It
// works on the raw subject because pkix.Name does not keep the order.
func rfc2253(raw []byte) string {
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

// signJWS signs PS256. detached leaves the payload out ("header..signature").
func signJWS(seal *obsdk.Seal, header map[string]any, payload []byte, detached bool) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	hp := enc.EncodeToString(h)
	pp := enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(hp + "." + pp))
	sig, err := seal.Key.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return "", fmt.Errorf("hsbc: signing: %w", err)
	}
	if detached {
		pp = ""
	}
	return hp + "." + pp + "." + enc.EncodeToString(sig), nil
}
