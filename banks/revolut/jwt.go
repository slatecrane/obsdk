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

// signRequestObject builds the JWT that carries the consent id to the
// authorisation page, signed PS256 with the seal key.
func (c *client) signRequestObject(consentID, redirectURI, state string) (string, error) {
	seal := c.cfg.Seal
	if seal == nil || seal.Key == nil {
		return "", &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{"seal (request object signing key)"}}
	}
	if _, ok := seal.Key.Public().(*rsa.PublicKey); !ok {
		return "", &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Invalid: []string{"seal: Revolut needs an RSA key (PS256)"}}
	}
	if seal.KeyID == "" {
		return "", &obsdk.ConfigError{Bank: bankKey, Env: c.cfg.Env, Missing: []string{"seal.KeyID (the kid in the JWKS registered in the portal)"}}
	}
	now := c.now()
	ro := requestObject{
		ResponseType: "code id_token", ClientID: c.cfg.Credentials.ClientID, RedirectURI: redirectURI,
		Aud: c.host, Scope: "accounts", State: state,
		Nbf: now.Unix(), Exp: now.Add(requestObjectTTL).Unix(),
	}
	ro.Claims.IDToken.Intent.Value = consentID
	return signJWT(seal, map[string]string{"alg": "PS256", "kid": seal.KeyID, "typ": "JWT"}, ro)
}

func signJWT(seal *obsdk.Seal, header map[string]string, claims any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	sum := sha256.Sum256([]byte(input))
	sig, err := seal.Key.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return "", fmt.Errorf("revolut: signing request object: %w", err)
	}
	return input + "." + enc.EncodeToString(sig), nil
}
