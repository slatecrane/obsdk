package obsdktest

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// Environment variables read by LiveFromEnv. Live runs hit real bank APIs and
// exist only for development; automated tests never depend on them.
//
//	OBSDK_BANK, OBSDK_COUNTRY       required   e.g. swedbank, SE
//	OBSDK_SEGMENT                   optional   personal | business
//	OBSDK_ENV                       sandbox (default) | production
//	OBSDK_ALLOW_PRODUCTION=1        required for production
//	OBSDK_CLIENT_ID, OBSDK_CLIENT_SECRET, OBSDK_REDIRECT_URL
//	OBSDK_EXTRA                     comma separated k=v pairs for Config.Extra
//	OBSDK_SESSION_FILE              where the session is read from / saved to
//	OBSDK_PSU_IP, OBSDK_PSU_USER_AGENT
//	OBSDK_TLS_CERT, OBSDK_TLS_KEY   mTLS client certificate and key (PEM or DER files)
//	OBSDK_TLS_CA                    extra root CA(s) for the bank's server certificate (PEM)
//	OBSDK_SEAL_KEY, OBSDK_SEAL_KID  request-signing key (PEM) and its key id
//	OBSDK_SEAL_CERT                 optional certificate of the signing key (PEM or DER)
//
// Each bank keeps a template of what it needs in banks/<bank>/sandbox.env.example.
const (
	EnvBank        = "OBSDK_BANK"
	EnvCountry     = "OBSDK_COUNTRY"
	EnvSegment     = "OBSDK_SEGMENT"
	EnvEnv         = "OBSDK_ENV"
	EnvAllowProd   = "OBSDK_ALLOW_PRODUCTION"
	EnvClientID    = "OBSDK_CLIENT_ID"
	EnvSecret      = "OBSDK_CLIENT_SECRET"
	EnvRedirect    = "OBSDK_REDIRECT_URL"
	EnvExtra       = "OBSDK_EXTRA"
	EnvSessionFile = "OBSDK_SESSION_FILE"
	EnvPSUIP       = "OBSDK_PSU_IP"
	EnvPSUAgent    = "OBSDK_PSU_USER_AGENT"
	EnvTLSCert     = "OBSDK_TLS_CERT"
	EnvTLSKey      = "OBSDK_TLS_KEY"
	EnvTLSCA       = "OBSDK_TLS_CA"
	EnvSealKey     = "OBSDK_SEAL_KEY"
	EnvSealKID     = "OBSDK_SEAL_KID"
	EnvSealCert    = "OBSDK_SEAL_CERT"
)

// Live is a development setup that talks to a real bank.
type Live struct {
	Target      obsdk.Target
	Config      obsdk.Config
	SessionFile string
	PSU         obsdk.PSUContext
}

// LiveFromEnv reads the setup from the environment. The error lists what is missing.
func LiveFromEnv() (*Live, error) {
	var missing []string
	need := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			missing = append(missing, k)
		}
		return v
	}
	l := &Live{}
	l.Target = obsdk.Target{Bank: need(EnvBank), Country: obsdk.Country(strings.ToUpper(need(EnvCountry))), Segment: obsdk.Segment(os.Getenv(EnvSegment))}
	env := obsdk.Env(os.Getenv(EnvEnv))
	if env == "" {
		env = obsdk.Sandbox
	}
	if env == obsdk.Production && os.Getenv(EnvAllowProd) != "1" {
		return nil, fmt.Errorf("obsdktest: %s=production needs %s=1: production runs use real accounts", EnvEnv, EnvAllowProd)
	}
	l.Config = obsdk.Config{
		Env: env,
		Credentials: obsdk.Credentials{
			ClientID: need(EnvClientID), ClientSecret: obsdk.Secret(os.Getenv(EnvSecret)), RedirectURL: need(EnvRedirect),
		},
		Extra: map[string]string{},
	}
	for _, kv := range strings.Split(os.Getenv(EnvExtra), ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("obsdktest: %s: %q is not key=value", EnvExtra, kv)
		}
		l.Config.Extra[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	l.SessionFile = repoPath(os.Getenv(EnvSessionFile))
	l.PSU = obsdk.PSUContext{IP: os.Getenv(EnvPSUIP), UserAgent: os.Getenv(EnvPSUAgent)}
	if len(missing) > 0 {
		return nil, fmt.Errorf("obsdktest: set %s", strings.Join(missing, ", "))
	}
	if err := l.loadTLS(); err != nil {
		return nil, err
	}
	if err := l.loadSeal(); err != nil {
		return nil, err
	}
	return l, nil
}

// loadTLS builds an mTLS HTTP client from OBSDK_TLS_* when they are set.
func (l *Live) loadTLS() error {
	certPath, keyPath, caPath := repoPath(os.Getenv(EnvTLSCert)), repoPath(os.Getenv(EnvTLSKey)), repoPath(os.Getenv(EnvTLSCA))
	if certPath == "" && keyPath == "" && caPath == "" {
		return nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPath != "" || keyPath != "" {
		cert, err := readCert(certPath)
		if err != nil {
			return fmt.Errorf("obsdktest: %s: %w", EnvTLSCert, err)
		}
		key, err := readKey(keyPath)
		if err != nil {
			return fmt.Errorf("obsdktest: %s: %w", EnvTLSKey, err)
		}
		tc.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}}
	}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("obsdktest: %s: %w", EnvTLSCA, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("obsdktest: %s: no PEM certificates in %s", EnvTLSCA, caPath)
		}
		tc.RootCAs = pool
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tc
	l.Config.HTTPClient = &http.Client{Timeout: 60 * time.Second, Transport: t}
	return nil
}

// loadSeal reads the request-signing key from OBSDK_SEAL_* when set.
func (l *Live) loadSeal() error {
	keyPath := repoPath(os.Getenv(EnvSealKey))
	if keyPath == "" {
		return nil
	}
	key, err := readKey(keyPath)
	if err != nil {
		return fmt.Errorf("obsdktest: %s: %w", EnvSealKey, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("obsdktest: %s: key cannot sign", EnvSealKey)
	}
	seal := &obsdk.Seal{Key: signer, KeyID: os.Getenv(EnvSealKID)}
	if p := repoPath(os.Getenv(EnvSealCert)); p != "" {
		if seal.Certificate, err = readCert(p); err != nil {
			return fmt.Errorf("obsdktest: %s: %w", EnvSealCert, err)
		}
	}
	l.Config.Seal = seal
	return nil
}

// repoPath resolves a relative path that does not exist from the working
// directory against the module root, so the paths in banks/<bank>/sandbox.env
// work both for obdev (run from the root) and for go test (run in a package).
func repoPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	dir, err := os.Getwd()
	if err != nil {
		return p
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, p)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		dir = parent
	}
}

// readCert reads one certificate, PEM or DER.
func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	return x509.ParseCertificate(b)
}

// readKey reads a private key, PEM or DER, in PKCS#8, PKCS#1 or SEC 1 form.
func readKey(path string) (crypto.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	if k, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(b); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

// LoadSession reads SessionFile, returning nil when there is none yet.
func (l *Live) LoadSession() (*obsdk.Session, error) {
	if l.SessionFile == "" {
		return nil, nil
	}
	b, err := os.ReadFile(l.SessionFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return obsdk.ParseSession(b)
}

// SaveSession writes the session to SessionFile (mode 0600: it holds tokens).
func (l *Live) SaveSession(s *obsdk.Session) error {
	if l.SessionFile == "" || s == nil {
		return nil
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(l.SessionFile, b, 0o600)
}

// Client builds the client: restored from the saved session when there is one,
// otherwise created from the target.
func (l *Live) Client() (obsdk.Client, *obsdk.Session, error) {
	s, err := l.LoadSession()
	if err != nil {
		return nil, nil, err
	}
	if s != nil {
		c, err := obsdk.Restore(s, l.Config)
		return c, s, err
	}
	c, err := obsdk.New(l.Target, l.Config)
	return c, nil, err
}

// RunLive is a generic smoke test for any integration, driven by the
// environment. It needs a session saved by `obdev connect` (or an earlier run),
// because logging in takes a person. It lists accounts, reads balances and a
// month of transactions for the first account, then refreshes the token.
// Nothing is asserted about bank data beyond "the SDK didn't fail".
//
// Put it behind a build tag so normal `go test` never reaches the network:
//
//	//go:build live
//	func TestLive(t *testing.T) { obsdktest.RunLive(t) }
func RunLive(t *testing.T) {
	t.Helper()
	l, err := LiveFromEnv()
	if err != nil {
		t.Skip(err)
	}
	c, s, err := l.Client()
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Skipf("no session: run `go run ./cmd/obdev connect` with %s set", EnvSessionFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	opts := obsdk.CallOptions{}
	if l.PSU.IP != "" || l.PSU.UserAgent != "" {
		opts.PSU = &l.PSU
	}
	keep := func(ns *obsdk.Session) {
		if ns != nil {
			s = ns
			if err := l.SaveSession(s); err != nil {
				t.Errorf("save session: %v", err)
			}
		}
	}

	accts, err := c.Accounts(ctx, s, opts)
	if err != nil {
		t.Fatalf("accounts: %v", err)
	}
	keep(accts.Session)
	t.Logf("accounts: %d", len(accts.Data))
	if len(accts.Data) > 0 {
		id := accts.Data[0].ID
		bal, err := c.Balances(ctx, s, id, opts)
		if err != nil {
			t.Errorf("balances: %v", err)
		} else {
			keep(bal.Session)
			t.Logf("balances: %d", len(bal.Data))
		}
		now := time.Now()
		tx, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: id, From: now.AddDate(0, 0, -30), To: now, Options: opts})
		if err != nil {
			t.Errorf("transactions: %v", err)
		} else {
			keep(tx.Session)
			t.Logf("transactions: %d (more pages: %t, step: %t)", len(tx.Transactions), tx.NextCursor != "", tx.Step != nil)
		}
	}
	ns, err := c.Refresh(ctx, s)
	if err != nil {
		t.Errorf("refresh: %v", err)
	} else {
		keep(ns)
	}
}
