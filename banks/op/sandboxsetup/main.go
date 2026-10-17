// Command sandboxsetup prepares OP's PSD2 sandbox for obdev: with the API key
// of an OP Developer app it has OP generate a sandbox TPP with test QWAC and
// QSealC certificates, registers a client for it (dynamic client
// registration) and prints the values for banks/op/sandbox.env. Keys,
// certificates and the registration response go to banks/op/cert/, which
// git ignores.
//
//	OP_API_KEY=... go run ./banks/op/sandboxsetup [-redirect https://example.com/cb] [-name obsdk-test] [-ec]
//
// OP cleans up generated TPPs now and then; run it again when the sandbox
// stops accepting the certificate.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	generator = "https://sandbox.apis.op.fi/psd2-sandbox-tpp-generator/sandbox-tpp"
	register  = "https://psd2.mtls.sandbox.apis.op.fi/tpp-registration/register"
	certDir   = "banks/op/cert"
)

func main() {
	redirect := flag.String("redirect", "https://example.com/cb", "comma-separated redirect URIs to register")
	name := flag.String("name", "obsdk-test", "name of the generated sandbox TPP")
	ec := flag.Bool("ec", false, "use the P-256 keys (ES256) instead of the RSA ones (RS256)")
	email := flag.String("email", "dev@example.com", "contact e-mail in the software statement")
	flag.Parse()
	apiKey := os.Getenv("OP_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "sandboxsetup: set OP_API_KEY to the API key of your OP Developer app")
		os.Exit(2)
	}
	if err := run(apiKey, *name, *email, strings.Split(*redirect, ","), *ec); err != nil {
		fmt.Fprintln(os.Stderr, "sandboxsetup:", err)
		os.Exit(1)
	}
}

type jwk struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	X5c []string `json:"x5c"`
	// RSA
	N, E, D, P, Q string
	// EC
	Crv, X, Y string
}

func (k *jwk) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s := func(n string) string { v, _ := m[n].(string); return v }
	k.Kty, k.Kid, k.Alg = s("kty"), s("kid"), s("alg")
	k.N, k.E, k.D, k.P, k.Q = s("n"), s("e"), s("d"), s("p"), s("q")
	k.Crv, k.X, k.Y = s("crv"), s("x"), s("y")
	if xs, ok := m["x5c"].([]any); ok {
		for _, x := range xs {
			if v, ok := x.(string); ok {
				k.X5c = append(k.X5c, v)
			}
		}
	}
	return nil
}

type generated struct {
	PrivateJWKS struct {
		Keys []jwk `json:"keys"`
	} `json:"privateJwks"`
	TPPID         string `json:"tppId"`
	PublicJWKSURL string `json:"publicJwksUrl"`
}

func run(apiKey, name, email string, redirects []string, ec bool) error {
	// 1. Sandbox TPP and certificates.
	q := url.Values{"c": {"FI"}, "cn": {name}, "roles": {"AIS,PIS,CBPII"}}
	req, _ := http.NewRequest(http.MethodPost, generator+"?"+q.Encode(), nil)
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("Accept", "application/json")
	body, err := call(http.DefaultClient, req)
	if err != nil {
		return fmt.Errorf("generating sandbox TPP: %w", err)
	}
	var g generated
	if err := json.Unmarshal(body, &g); err != nil || g.TPPID == "" {
		return fmt.Errorf("unreadable generator response: %s", trim(body))
	}
	kty := "RSA"
	if ec {
		kty = "EC"
	}
	qwac, err := pick(g.PrivateJWKS.Keys, "qwac", kty)
	if err != nil {
		return err
	}
	seal, err := pick(g.PrivateJWKS.Keys, "qseal", kty)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "generated.json"), body, 0o600); err != nil {
		return err
	}
	qwacKey, err := writeKeyAndCert(qwac, "qwac")
	if err != nil {
		return err
	}
	sealKey, err := writeKeyAndCert(seal, "qseal")
	if err != nil {
		return err
	}

	// 2. Software statement and registration request, both signed with the QSealC key.
	alg := "RS256"
	if ec {
		alg = "ES256"
	}
	now := time.Now()
	ssa, err := sign(sealKey, alg, seal.Kid, map[string]any{
		"iss": g.TPPID, "iat": now.Unix(), "exp": now.Add(365 * 24 * time.Hour).Unix(), "jti": uuid(),
		"software_client_id": uuid(), "software_roles": []string{"AIS", "PIS", "CBPII"},
		"software_jwks_endpoint": g.PublicJWKSURL, "software_jwks_revoked_endpoint": g.PublicJWKSURL,
		"software_client_name": name, "software_redirect_uris": redirects, "software_client_uri": "https://example.com",
		"org_name": name, "org_id": g.TPPID,
		"org_contacts": []map[string]string{{"name": name, "email": email, "phone": "+358000000", "type": "Support"}},
	})
	if err != nil {
		return err
	}
	reg, err := sign(sealKey, alg, seal.Kid, map[string]any{
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "aud": "https://op.fi/", "jti": uuid(),
		"redirect_uris": redirects, "grant_types": []string{"client_credentials", "authorization_code", "refresh_token"},
		"software_statement": ssa,
	})
	if err != nil {
		return err
	}

	// 3. Register over mTLS with the generated QWAC.
	leaf, err := cert(qwac.X5c[0])
	if err != nil {
		return err
	}
	tc := &tls.Config{Certificates: []tls.Certificate{{Certificate: chain(qwac.X5c), PrivateKey: qwacKey, Leaf: leaf}}, MinVersion: tls.VersionTLS12}
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
	req, _ = http.NewRequest(http.MethodPost, register, strings.NewReader(reg))
	req.Header.Set("Content-Type", "application/jwt")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", apiKey)
	body, err = call(hc, req)
	if err != nil {
		return fmt.Errorf("registering client: %w", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "registration.json"), body, 0o600); err != nil {
		return err
	}
	var r struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.ClientID == "" {
		return fmt.Errorf("unreadable registration response: %s", trim(body))
	}

	fmt.Printf("# sandbox TPP %s, registered %s\n", g.TPPID, now.UTC().Format(time.RFC3339))
	fmt.Printf("OBSDK_CLIENT_ID=%s\nOBSDK_CLIENT_SECRET=%s\nOBSDK_REDIRECT_URL=%s\n", r.ClientID, r.ClientSecret, redirects[0])
	fmt.Printf("OBSDK_TLS_CERT=%s/qwac.pem\nOBSDK_TLS_KEY=%s/qwac.key\n", certDir, certDir)
	fmt.Printf("OBSDK_SEAL_KEY=%s/qseal.key\nOBSDK_SEAL_CERT=%s/qseal.pem\nOBSDK_SEAL_KID=%s\n", certDir, certDir, seal.Kid)
	fmt.Printf("OBSDK_EXTRA=api_key=%s\n", apiKey)
	return nil
}

func call(hc *http.Client, req *http.Request) ([]byte, error) {
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, trim(body))
	}
	return body, nil
}

func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// pick finds the generated key of a kind ("qwac", "qseal") and type.
func pick(keys []jwk, kind, kty string) (jwk, error) {
	for _, k := range keys {
		if strings.HasPrefix(strings.ReplaceAll(k.Kid, "qeseal", "qseal"), kind) && k.Kty == kty && len(k.X5c) > 0 {
			return k, nil
		}
	}
	var kids []string
	for _, k := range keys {
		kids = append(kids, k.Kid+" ("+k.Kty+")")
	}
	return jwk{}, fmt.Errorf("no %s %s key among %s", kty, kind, strings.Join(kids, ", "))
}

func b64int(s string) *big.Int {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return new(big.Int).SetBytes(b)
}

func privateKey(k jwk) (crypto.Signer, error) {
	switch k.Kty {
	case "RSA":
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: b64int(k.N), E: int(b64int(k.E).Int64())},
			D:         b64int(k.D), Primes: []*big.Int{b64int(k.P), b64int(k.Q)},
		}
		key.Precompute()
		return key, key.Validate()
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("curve %s not supported", k.Crv)
		}
		key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: b64int(k.X), Y: b64int(k.Y)}, D: b64int(k.D)}
		return key, nil
	}
	return nil, fmt.Errorf("key type %s not supported", k.Kty)
}

func cert(x5c string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(x5c)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func chain(x5c []string) [][]byte {
	var out [][]byte
	for _, c := range x5c {
		if der, err := base64.StdEncoding.DecodeString(c); err == nil {
			out = append(out, der)
		}
	}
	return out
}

// writeKeyAndCert saves <name>.key (PKCS#8) and <name>.pem (the leaf, then the chain).
func writeKeyAndCert(k jwk, name string) (crypto.Signer, error) {
	key, err := privateKey(k)
	if err != nil {
		return nil, fmt.Errorf("%s key: %w", name, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(certDir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, c := range chain(k.X5c) {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	return key, os.WriteFile(filepath.Join(certDir, name+".pem"), buf.Bytes(), 0o600)
}

func sign(key crypto.Signer, alg, kid string, claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	if alg == "ES256" {
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			return "", err
		}
		raw := make([]byte, 64)
		rs.R.FillBytes(raw[:32])
		rs.S.FillBytes(raw[32:])
		sig = raw
	}
	return in + "." + enc.EncodeToString(sig), nil
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
