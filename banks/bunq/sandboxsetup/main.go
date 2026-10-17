// Command sandboxsetup prepares bunq's sandbox for obdev: it creates a
// sandbox user that owns an OAuth client (with the redirect URLs given), and
// a test user to connect with, funded with sandbox money. It prints the
// values for banks/bunq/sandbox.env.
//
//	go run ./banks/bunq/sandboxsetup [-redirect http://localhost/cb] [-business] [-fund=false]
//
// bunq lets a sandbox user log in to the sandbox app only if that user made
// no API call before. To give OAuth consent in the app, create the test user
// with -fund=false (funding needs API calls as that user).
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const api = "https://public-api.sandbox.bunq.com/v1"

func main() {
	redirect := flag.String("redirect", "http://localhost/cb", "comma-separated callback URLs for the OAuth client")
	business := flag.Bool("business", false, "make the test user a company (sandbox-user-company)")
	fund := flag.Bool("fund", true, "ask Sugar Daddy for €500 for the test user (makes API calls as that user)")
	flag.Parse()
	if err := run(strings.Split(*redirect, ","), *business, *fund); err != nil {
		fmt.Fprintln(os.Stderr, "sandboxsetup:", err)
		os.Exit(1)
	}
}

type ctx struct {
	key   *rsa.PrivateKey
	token string // session token
	user  string

	lastUser json.RawMessage // the user object from session-server
}

func run(redirects []string, business, fund bool) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	ownerKey, err := sandboxUser("person")
	if err != nil {
		return fmt.Errorf("owner user: %w", err)
	}
	owner, err := login(key, ownerKey)
	if err != nil {
		return fmt.Errorf("owner login: %w", err)
	}
	res, err := owner.call("POST", "/user/"+owner.user+"/oauth-client", map[string]string{"status": "ACTIVE"})
	if err != nil {
		return fmt.Errorf("oauth client: %w", err)
	}
	clientID := res.id()
	for _, u := range redirects {
		if _, err := owner.call("POST", "/user/"+owner.user+"/oauth-client/"+clientID+"/callback-url", map[string]string{"url": strings.TrimSpace(u)}); err != nil {
			return fmt.Errorf("callback url %s: %w", u, err)
		}
	}
	res, err = owner.call("GET", "/user/"+owner.user+"/oauth-client/"+clientID, nil)
	if err != nil {
		return err
	}
	var oc struct {
		ClientID string `json:"client_id"`
		Secret   string `json:"secret"`
	}
	if err := json.Unmarshal(res.object("OauthClient"), &oc); err != nil || oc.ClientID == "" {
		return fmt.Errorf("unreadable oauth client")
	}

	kind := "person"
	if business {
		kind = "company"
	}
	userKey, err := sandboxUser(kind)
	if err != nil {
		return fmt.Errorf("test user: %w", err)
	}
	var phone, email string
	if fund {
		u, err := login(key, userKey)
		if err != nil {
			return fmt.Errorf("test user login: %w", err)
		}
		phone, email = u.aliases()
		res, err := u.call("GET", "/user/"+u.user+"/monetary-account", nil)
		if err != nil {
			return err
		}
		var acc struct {
			ID json.Number `json:"id"`
		}
		for _, m := range res.Response {
			for k, v := range m {
				if strings.HasPrefix(k, "MonetaryAccount") && acc.ID == "" {
					_ = json.Unmarshal(v, &acc)
				}
			}
		}
		if acc.ID == "" {
			return fmt.Errorf("test user has no account")
		}
		_, err = u.call("POST", "/user/"+u.user+"/monetary-account/"+acc.ID.String()+"/request-inquiry", map[string]any{
			"amount_inquired":    map[string]string{"value": "500.00", "currency": "EUR"},
			"counterparty_alias": map[string]string{"type": "EMAIL", "value": "sugardaddy@bunq.com", "name": "Sugar Daddy"},
			"description":        "sandbox money", "allow_bunqme": false,
		})
		if err != nil {
			return fmt.Errorf("sandbox money: %w", err)
		}
	}

	fmt.Printf("OBSDK_CLIENT_ID=%s\nOBSDK_CLIENT_SECRET=%s\nOBSDK_REDIRECT_URL=%s\n", oc.ClientID, oc.Secret, strings.TrimSpace(redirects[0]))
	if business {
		fmt.Println("OBSDK_SEGMENT=business")
	}
	fmt.Printf("SANDBOX_USER_API_KEY=%s\nSANDBOX_USER_PHONE=%s\nSANDBOX_USER_EMAIL=%s\nSANDBOX_OAUTH_OWNER_API_KEY=%s\n", userKey, phone, email, ownerKey)
	if !fund {
		fmt.Fprintln(os.Stderr, "The test user made no API call: look up its phone number or e-mail with a GET /user after logging in to the sandbox app, or create one with -fund to use method api_key.")
	}
	return nil
}

// ---- bunq calls ----

type envelope struct {
	Response []map[string]json.RawMessage `json:"Response"`
	Error    []struct {
		Desc string `json:"error_description"`
	} `json:"Error"`
}

func (e *envelope) object(t string) json.RawMessage {
	for _, m := range e.Response {
		if v, ok := m[t]; ok {
			return v
		}
	}
	return nil
}

func (e *envelope) id() string {
	var id struct {
		ID json.Number `json:"id"`
	}
	_ = json.Unmarshal(e.object("Id"), &id)
	return id.ID.String()
}

var hc = &http.Client{Timeout: 30 * time.Second}

func do(key *rsa.PrivateKey, method, path, auth string, body any) (*envelope, error) {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, api+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	for k, v := range map[string]string{"Content-Type": "application/json", "Cache-Control": "no-cache", "User-Agent": "obsdk-sandboxsetup",
		"X-Bunq-Language": "en_US", "X-Bunq-Region": "nl_NL", "X-Bunq-Geolocation": "0 0 0 0 000"} {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Bunq-Client-Request-Id", fmt.Sprintf("setup-%d", time.Now().UnixNano()))
	if auth != "" {
		req.Header.Set("X-Bunq-Client-Authentication", auth)
	}
	if len(b) > 0 && key != nil {
		sum := sha256.Sum256(b)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Bunq-Client-Signature", base64.StdEncoding.EncodeToString(sig))
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var e envelope
	_ = json.Unmarshal(rb, &e)
	if res.StatusCode != http.StatusOK {
		if len(e.Error) > 0 {
			return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, res.StatusCode, e.Error[0].Desc)
		}
		return nil, fmt.Errorf("%s %s: HTTP %d", method, path, res.StatusCode)
	}
	return &e, nil
}

func sandboxUser(kind string) (string, error) {
	e, err := do(nil, "POST", "/sandbox-user-"+kind, "", nil)
	if err != nil {
		return "", err
	}
	var k struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(e.object("ApiKey"), &k); err != nil || k.APIKey == "" {
		return "", fmt.Errorf("no api key in the response")
	}
	return k.APIKey, nil
}

// login makes an installation, a device and a session for an API key.
func login(key *rsa.PrivateKey, apiKey string) (*ctx, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	e, err := do(key, "POST", "/installation", "", map[string]string{"client_public_key": pub})
	if err != nil {
		return nil, err
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(e.object("Token"), &tok)
	if _, err := do(key, "POST", "/device-server", tok.Token, map[string]any{"description": "obsdk sandboxsetup", "secret": apiKey, "permitted_ips": []string{"*"}}); err != nil {
		return nil, err
	}
	s, err := do(key, "POST", "/session-server", tok.Token, map[string]string{"secret": apiKey})
	if err != nil {
		return nil, err
	}
	var st struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(s.object("Token"), &st)
	c := &ctx{key: key, token: st.Token}
	for _, t := range []string{"UserPerson", "UserCompany"} {
		if raw := s.object(t); raw != nil {
			var u struct {
				ID json.Number `json:"id"`
			}
			_ = json.Unmarshal(raw, &u)
			c.user = u.ID.String()
			c.lastUser = raw
		}
	}
	if c.user == "" {
		return nil, fmt.Errorf("session has no user")
	}
	return c, nil
}

func (c *ctx) call(method, path string, body any) (*envelope, error) {
	return do(c.key, method, path, c.token, body)
}

// aliases returns the user's phone number and e-mail, for the sandbox app.
func (c *ctx) aliases() (phone, email string) {
	var u struct {
		Alias []struct{ Type, Value string } `json:"alias"`
	}
	_ = json.Unmarshal(c.lastUser, &u)
	for _, a := range u.Alias {
		switch a.Type {
		case "PHONE_NUMBER":
			phone = a.Value
		case "EMAIL":
			email = a.Value
		}
	}
	return phone, email
}
