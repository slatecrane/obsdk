package obie

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var frozen = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func testSeal(t *testing.T) (*obsdk.Seal, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4711), Subject: pkix.Name{CommonName: "tpp", Organization: []string{"obsdk"}, Country: []string{"FI"}},
		NotBefore: frozen, NotAfter: frozen.AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &obsdk.Seal{Key: key, Certificate: cert}, key
}

func testClient(t *testing.T, p Profile) (*client, *rsa.PrivateKey) {
	t.Helper()
	seal, key := testSeal(t)
	if p.APIHost == nil {
		p.APIHost = func(obsdk.Env, obsdk.Target) string { return "https://api.bank.example" }
		p.AuthURL = func(obsdk.Env, obsdk.Target) string { return "https://bank.example/auth" }
	}
	cfg := obsdk.Config{Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "cid"}, HTTPClient: http.DefaultClient, Seal: seal,
		Now: func() time.Time { return frozen }, NewID: func(p string) string { return p + "-1" }}
	c, err := newClient(&p, cfg, obsdk.Target{Bank: "bank", Country: "FI"})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client), key
}

func decodePart(t *testing.T, s string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestUnencodedDetachedSignature(t *testing.T) {
	c, key := testClient(t, Profile{KeyID: SerialKeyID, Signature: Signature{Unencoded: true, TAN: func(_ obsdk.Config, h string) string { return h }}})
	body := []byte(`{"Data":{"Initiation":{}},"Risk":{}}`)
	jws, err := c.signBody(body)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("not a detached JWS: %q", jws)
	}
	h := decodePart(t, parts[0])
	if h["kid"] != "4711" || h["b64"] != false || h[claimTAN] != "api.bank.example" || h[claimISS] != "CN=tpp,O=obsdk,C=FI" {
		t.Errorf("header = %v", h)
	}
	if crit, _ := h["crit"].([]any); len(crit) != 4 || crit[0] != "b64" {
		t.Errorf("crit = %v", h["crit"])
	}
	// RFC 7797: the signing input carries the body unencoded.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + string(body)))
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Errorf("signature does not verify over the unencoded body: %v", err)
	}
}

func TestEncodedDetachedSignature(t *testing.T) {
	c, key := testClient(t, Profile{KeyID: SerialKeyID})
	body := []byte(`{"a":1}`)
	jws, err := c.signBody(body)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jws, ".")
	h := decodePart(t, parts[0])
	if _, ok := h["b64"]; ok || h[claimTAN] != "openbanking.org.uk" {
		t.Errorf("header = %v", h)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString(body)))
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestRequestObject(t *testing.T) {
	c, _ := testClient(t, Profile{KeyID: SerialKeyID, RequestObjectIssuer: IssuerCertDN,
		IntentID: func(k, id string) string { return "urn:bank:" + k + ":" + id }})
	f := &flow{RedirectURL: "https://app.example/cb", OAuthState: "st"}
	u, err := c.authorizeURL(f, c.p.intentID(KindAccount, "c1"), "accounts", "fi")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "https://bank.example/auth?") || !strings.Contains(u, "ui_locales=fi") || !strings.Contains(u, "scope=openid+accounts") {
		t.Errorf("url = %s", u)
	}
	jwt := u[strings.Index(u, "request=")+8:]
	jwt = jwt[:strings.Index(jwt, "&")]
	parts := strings.Split(jwt, ".")
	claims := decodePart(t, parts[1])
	if claims["iss"] != "CN=tpp,O=obsdk,C=FI" || claims["client_id"] != "cid" || claims["nonce"] != "state-1" {
		t.Errorf("claims = %v", claims)
	}
	exp, nbf := claims["exp"].(float64), claims["nbf"].(float64)
	if exp-nbf > 3600 {
		t.Errorf("exp is more than 60 minutes after nbf")
	}
	intent := claims["claims"].(map[string]any)["id_token"].(map[string]any)["openbanking_intent_id"].(map[string]any)
	if intent["value"] != "urn:bank:account:c1" || intent["essential"] != true {
		t.Errorf("intent = %v", intent)
	}
	if h := decodePart(t, parts[0]); h["kid"] != "4711" || h["alg"] != "PS256" {
		t.Errorf("header = %v", h)
	}
}

func TestSerialKeyIDPrefersExplicit(t *testing.T) {
	seal, _ := testSeal(t)
	if SerialKeyID(seal) != "4711" {
		t.Error("serial not used")
	}
	seal.KeyID = "explicit"
	if SerialKeyID(seal) != "explicit" {
		t.Error("KeyID not preferred")
	}
}

func TestIDField(t *testing.T) {
	for in, want := range map[string]string{
		"domestic": "DomesticPaymentId", "international-scheduled": "InternationalScheduledPaymentId",
	} {
		if got := idField(in); got != want {
			t.Errorf("idField(%q) = %q", in, got)
		}
	}
}

func TestTokenExpiresInString(t *testing.T) {
	var tr tokenResponse
	if err := json.Unmarshal([]byte(`{"access_token":"a","expires_in":"300"}`), &tr); err != nil || tr.ExpiresIn != 300 || tr.AccessToken != "a" {
		t.Errorf("tr = %+v, err %v", tr, err)
	}
	if err := json.Unmarshal([]byte(`{"access_token":"a","expires_in":180}`), &tr); err != nil || tr.ExpiresIn != 180 {
		t.Errorf("tr = %+v, err %v", tr, err)
	}
}

func TestRequiredParams(t *testing.T) {
	seal, _ := testSeal(t)
	p := &Profile{RequiredParams: []string{"api_key"},
		APIHost: func(obsdk.Env, obsdk.Target) string { return "https://x" }, AuthURL: func(obsdk.Env, obsdk.Target) string { return "https://x" }}
	_, err := newClient(p, obsdk.Config{Env: obsdk.Sandbox, HTTPClient: http.DefaultClient, Seal: seal}, obsdk.Target{Bank: "b", Country: "FI"})
	if ce, ok := err.(*obsdk.ConfigError); !ok || len(ce.Missing) != 1 || ce.Missing[0] != "api_key" {
		t.Errorf("err = %v", err)
	}
}
