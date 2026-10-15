package revolut

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// requestObjectTTL is how long the signed request object is valid. Revolut
// rejects exp more than 60 minutes after nbf.
const requestObjectTTL = 30 * time.Minute

type idTokenClaims struct {
	IDToken struct {
		Intent struct {
			Value string `json:"value"`
		} `json:"openbanking_intent_id"`
	} `json:"id_token"`
}

type requestObject struct {
	ResponseType string        `json:"response_type"`
	ClientID     string        `json:"client_id"`
	RedirectURI  string        `json:"redirect_uri"`
	Aud          string        `json:"aud"`
	Scope        string        `json:"scope"`
	State        string        `json:"state"`
	Nbf          int64         `json:"nbf"`
	Exp          int64         `json:"exp"`
	Claims       idTokenClaims `json:"claims"`
}

// seal returns the signing key, checked for what Revolut accepts.
func (c *client) seal() (*obsdk.Seal, error) {
	seal := c.cfg.Seal
	if seal == nil || seal.Key == nil {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{"seal (request object signing key)"}}
	}
	if _, ok := seal.Key.Public().(*rsa.PublicKey); !ok {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Invalid: []string{"seal: Revolut needs an RSA key (PS256)"}}
	}
	if seal.KeyID == "" {
		return nil, &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{"seal.KeyID (the kid in the JWKS registered in the portal)"}}
	}
	return seal, nil
}

// signRequestObject builds the JWT that carries the consent id to the
// authorisation page, signed PS256 with the seal key. scope is "accounts" or "payments".
func (c *client) signRequestObject(consentID, redirectURI, state, scope string) (string, error) {
	seal, err := c.seal()
	if err != nil {
		return "", err
	}
	now := c.now()
	ro := requestObject{
		ResponseType: "code id_token", ClientID: c.cfg.Credentials.ClientID, RedirectURI: redirectURI,
		Aud: c.host, Scope: scope, State: state,
		Nbf: now.Unix(), Exp: now.Add(requestObjectTTL).Unix(),
	}
	ro.Claims.IDToken.Intent.Value = consentID
	p, err := json.Marshal(ro)
	if err != nil {
		return "", err
	}
	return signJWS(seal, map[string]any{"alg": "PS256", "kid": seal.KeyID, "typ": "JWT"}, p, false)
}

// tanClaim is the OBIE trust-anchor header Revolut requires in body signatures.
const tanClaim = "http://openbanking.org.uk/tan"

// signBody returns the detached JWS of a request body for x-jws-signature.
// body must be the exact bytes sent.
func (c *client) signBody(body []byte) (string, error) {
	seal, err := c.seal()
	if err != nil {
		return "", err
	}
	tan := c.cfg.Param(paramJWSTan)
	if tan == "" {
		return "", &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{paramJWSTan + " (host of the JWKS URL, needed for payments)"}}
	}
	h := map[string]any{"typ": "JOSE", "alg": "PS256", "kid": seal.KeyID, "crit": []string{tanClaim}, tanClaim: tan}
	return signJWS(seal, h, body, true)
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
		return "", fmt.Errorf("revolut: signing: %w", err)
	}
	if detached {
		pp = ""
	}
	return hp + "." + pp + "." + enc.EncodeToString(sig), nil
}
