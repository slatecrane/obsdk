package op

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// requestObjectTTL is how long the signed request object is valid.
const requestObjectTTL = 15 * time.Minute

// acrSCA asks for strong customer authentication, the only value OP accepts
// in the redirect flows.
const acrSCA = "urn:openbanking:psd2:sca"

// acrCA is added for cancellations, which OP documents with both values.
const acrCA = "urn:openbanking:psd2:ca"

type essential struct {
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
	Essential bool     `json:"essential"`
}

type requestObject struct {
	Aud          string `json:"aud"`
	Iss          string `json:"iss"`
	ClientID     string `json:"client_id"`
	ResponseType string `json:"response_type"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	MaxAge       int    `json:"max_age"`
	Iat          int64  `json:"iat"`
	Exp          int64  `json:"exp"`
	Claims       struct {
		Userinfo map[string]essential `json:"userinfo"`
		IDToken  map[string]essential `json:"id_token"`
	} `json:"claims"`
}

// alg returns the JWS algorithm for the seal key, after checking that OP
// accepts it.
func (c *client) alg() (*obsdk.Seal, string, error) {
	seal := c.cfg.Seal
	if seal == nil || seal.Key == nil {
		return nil, "", &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{"seal (QSealC signing key)"}}
	}
	if seal.KeyID == "" {
		return nil, "", &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{"seal.KeyID (the key's kid in the registered JWKS)"}}
	}
	switch k := seal.Key.Public().(type) {
	case *rsa.PublicKey:
		return seal, "RS256", nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return seal, "ES256", nil
		}
	}
	return nil, "", &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Invalid: []string{"seal: OP accepts RSA (RS256) or P-256 (ES256) keys"}}
}

// signRequestObject builds the JWT that carries the authorization id to
// OP's authorisation page. scope is "accounts", "payments" or
// "payments:delete"; a cancellation also names the payment.
func (c *client) signRequestObject(authorizationID, paymentID, redirectURI, state, nonce, scope string) (string, error) {
	seal, alg, err := c.alg()
	if err != nil {
		return "", err
	}
	now := c.now()
	ro := requestObject{
		Aud: c.aud, Iss: c.cfg.Credentials.ClientID, ClientID: c.cfg.Credentials.ClientID,
		ResponseType: "code id_token", RedirectURI: redirectURI, Scope: "openid " + scope,
		State: state, Nonce: nonce, MaxAge: 86400, Iat: now.Unix(), Exp: now.Add(requestObjectTTL).Unix(),
	}
	acr := []string{acrSCA}
	ro.Claims.Userinfo = map[string]essential{"authorizationId": {Value: authorizationID, Essential: true}}
	ro.Claims.IDToken = map[string]essential{"authorizationId": {Value: authorizationID, Essential: true}}
	if paymentID != "" {
		ro.Claims.Userinfo["paymentId"] = essential{Value: paymentID, Essential: true}
		ro.Claims.IDToken["paymentId"] = essential{Value: paymentID, Essential: true}
		acr = append(acr, acrCA)
	}
	ro.Claims.IDToken["acr"] = essential{Values: acr, Essential: true}
	p, err := json.Marshal(ro)
	if err != nil {
		return "", err
	}
	return signJWS(seal, alg, map[string]any{"alg": alg, "typ": "JWT", "kid": seal.KeyID}, p, false)
}

// signBody returns the detached JWS of a payment body for x-jws-signature.
// body must be the exact bytes sent.
func (c *client) signBody(body []byte) (string, error) {
	seal, alg, err := c.alg()
	if err != nil {
		return "", err
	}
	return signJWS(seal, alg, map[string]any{"alg": alg, "kid": seal.KeyID}, body, true)
}

// signJWS signs RS256 or ES256. detached leaves the payload out ("header..signature").
func signJWS(seal *obsdk.Seal, alg string, header map[string]any, payload []byte, detached bool) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	hp := enc.EncodeToString(h)
	pp := enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(hp + "." + pp))
	sig, err := seal.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("op: signing: %w", err)
	}
	if alg == "ES256" {
		// crypto.Signer returns ASN.1; JWS wants r and s as 32 bytes each.
		if sig, err = rawECDSA(sig); err != nil {
			return "", err
		}
	}
	if detached {
		pp = ""
	}
	return hp + "." + pp + "." + enc.EncodeToString(sig), nil
}

func rawECDSA(der []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		return nil, fmt.Errorf("op: unreadable ECDSA signature: %w", err)
	}
	out := make([]byte, 64)
	rs.R.FillBytes(out[:32])
	rs.S.FillBytes(out[32:])
	return out, nil
}
