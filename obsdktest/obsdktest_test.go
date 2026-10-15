package obsdktest

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func get(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func ex(method, path string, query map[string][]string, status int, body string) Exchange {
	e := Exchange{Request: Request{Method: method, Path: path, Query: query}, Response: Response{Status: status}}
	if strings.HasPrefix(body, "{") {
		e.Response.Body = []byte(body)
	} else {
		e.Response.BodyText = body
	}
	return e
}

func TestReplayConsumesInOrderAndMatchesQuery(t *testing.T) {
	rp := NewReplayerFrom([]Exchange{
		ex("GET", "/poll", nil, 200, `{"n":1}`),
		ex("GET", "/poll", nil, 200, `{"n":2}`),
		ex("GET", "/q", map[string][]string{"a": {"1"}}, 200, "one"),
	})
	c := rp.Client()
	if _, b := get(t, c, "http://x/poll"); !strings.Contains(b, `1`) {
		t.Errorf("first poll: %s", b)
	}
	if _, b := get(t, c, "http://other-host/poll"); !strings.Contains(b, `2`) {
		t.Errorf("second poll (host is ignored): %s", b)
	}
	if _, err := c.Get("http://x/poll"); err == nil || !strings.Contains(err.Error(), "no unused recorded exchange") {
		t.Errorf("third poll should fail: %v", err)
	}
	if _, err := c.Get("http://x/q?a=2"); err == nil || !strings.Contains(err.Error(), "same method and path") {
		t.Errorf("wrong query should list candidates: %v", err)
	}
	if _, b := get(t, c, "http://x/q?a=1"); b != "one" {
		t.Errorf("query match: %q", b)
	}
	if len(rp.Unused()) != 0 || len(rp.Requests()) != 5 {
		t.Errorf("unused=%v seen=%d", rp.Unused(), len(rp.Requests()))
	}
}

func TestReplayOptions(t *testing.T) {
	rp := NewReplayerFrom([]Exchange{ex("GET", "/p", map[string][]string{"t": {"1"}}, 200, "ok")}, IgnoreQuery("t"), RepeatLast())
	c := rp.Client()
	for i := 0; i < 3; i++ {
		if _, b := get(t, c, "http://x/p?t=999"); b != "ok" {
			t.Fatalf("call %d: %q", i, b)
		}
	}
}

func TestReplayMatchesRedactedSecrets(t *testing.T) {
	// The fixture holds placeholders; the SDK sends real values.
	rp := NewReplayerFrom([]Exchange{ex("POST", "/token", map[string][]string{"client_secret": {"REDACTED:client_secret"}, "code": {"REDACTED:code:abc123"}}, 200, "{}")})
	req, _ := http.NewRequest("POST", "http://x/token?client_secret=hunter2&code=REDACTED:access_code:abc123", nil)
	res, err := rp.Client().Do(req)
	if err != nil {
		t.Fatal(err) // a secret under another label with the same digest still matches
	}
	res.Body.Close()
}

func TestReplayerDoesNotFollowRedirects(t *testing.T) {
	e := ex("GET", "/auth", nil, 302, "")
	e.Response.Headers = map[string]string{"Location": "https://bank/login"}
	res, _ := get(t, NewReplayerFrom([]Exchange{e}).Client(), "http://x/auth")
	if res.StatusCode != 302 || res.Header.Get("Location") != "https://bank/login" {
		t.Errorf("%d %v", res.StatusCode, res.Header)
	}
}

func TestLoadExchangesValidates(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "001.json"), []byte(`{"request":{"method":"GET"},"response":{"status":200}}`), 0o644)
	if _, err := LoadExchanges(dir); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("missing path: %v", err)
	}
}

func TestRedactor(t *testing.T) {
	r := DefaultRedactor(map[string]string{"cid-123": "client_id", "s3cret": "client_secret"})
	if got := r.QueryValue("client_id", "cid-123"); got != "REDACTED:client_id" {
		t.Errorf("literal: %s", got)
	}
	a, b := r.QueryValue("code", "AAA"), r.QueryValue("code", "BBB")
	if a == b || a != r.QueryValue("code", "AAA") || !strings.HasPrefix(a, "REDACTED:code:") {
		t.Errorf("digests: %s %s", a, b)
	}
	if r.QueryValue("code", a) != a {
		t.Error("masking must be idempotent")
	}
	if got := r.QueryValue("bic", "SANDSESS"); got != "SANDSESS" {
		t.Errorf("ordinary values survive: %s", got)
	}
	out := string(r.JSON([]byte(`{"access_token":"T","code":"MISSING_BANK_ID","iban":"SE4550000000058398257466","ownerName":"Ann Lee","amount":"12.00","n":{"refresh_token":"R","note":"has s3cret inside"}}`)))
	for _, leak := range []string{`"T"`, "SE4550000000058398257466", "Ann Lee", `"R"`, "s3cret"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %s in %s", leak, out)
		}
	}
	for _, keep := range []string{"MISSING_BANK_ID", "12.00", "SE00PSEUDO"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %s in %s", keep, out)
		}
	}
	if u := r.URL("https://app/cb?state=S1&access_code=XYZ&other=1"); !strings.Contains(u, "state=S1") || strings.Contains(u, "XYZ") || strings.Contains(u, "other=1") {
		t.Errorf("url: %s", u)
	}
	if u := r.URL("access_code=XYZ&state=S1"); strings.Contains(u, "XYZ") || strings.HasPrefix(u, "?") {
		t.Errorf("bare query: %s", u)
	}
	if r.Header("Authorization", "Bearer abc") == "Bearer abc" {
		t.Error("authorization leaked")
	}
}

func TestRedactZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("a.json")
	io.WriteString(w, `{"creditorName":"Ann Lee","amount":"1"}`)
	zw.Close()
	out, err := DefaultRedactor(nil).Zip(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil || len(zr.File) != 1 {
		t.Fatal(err)
	}
	f, _ := zr.File[0].Open()
	b, _ := io.ReadAll(f)
	if strings.Contains(string(b), "Ann Lee") || !strings.Contains(string(b), `"amount": "1"`) {
		t.Errorf("zip content: %s", b)
	}
}

// Recording a conversation and replaying it must give the same answers, with
// no secrets on disk.
func TestRecordThenReplay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"SUPERSECRET","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer SUPERSECRET" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"accounts":[{"iban":"SE4550000000058398257466"}]}`)
	}))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "exchanges")
	rec, err := NewRecorder(dir, nil, DefaultRedactor(map[string]string{"my-client-secret": "client_secret"}))
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: rec}
	res, err := c.Post(srv.URL+"/token?client_secret=my-client-secret", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	b, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(b), "SUPERSECRET") {
		t.Fatalf("the caller must still see the real response: %s", b)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/accounts", nil)
	req.Header.Set("Authorization", "Bearer SUPERSECRET")
	if res, err = c.Do(req); err != nil || res.StatusCode != 200 {
		t.Fatalf("%v %v", err, res)
	}
	_ = tok

	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 2 || !strings.HasPrefix(filepath.Base(files[0]), "001-post-") {
		t.Fatalf("files = %v", files)
	}
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, leak := range []string{"SUPERSECRET", "my-client-secret", "SE4550000000058398257466"} {
			if strings.Contains(string(data), leak) {
				t.Errorf("%s leaks %s:\n%s", f, leak, data)
			}
		}
	}

	// A second recorder in the same directory continues the numbering.
	rec2, _ := NewRecorder(dir, nil, nil)
	if rec2.n != 2 {
		t.Errorf("numbering restarts at %d", rec2.n)
	}

	// Replay with different credentials than were used while recording.
	rp, err := NewReplayer(dir)
	if err != nil {
		t.Fatal(err)
	}
	pc := rp.Client()
	res, err = pc.Post("http://anything/token?client_secret=another-secret", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	if !strings.Contains(string(b), "REDACTED:access_token:") {
		t.Errorf("replayed token: %s", b)
	}
	if _, body := get(t, pc, "http://anything/accounts"); !strings.Contains(body, "SE00PSEUDO") {
		t.Errorf("replayed accounts: %s", body)
	}
	rp.AssertAllUsed(t)
}

func TestScenarioLoadRequiresFrozenClock(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "scenario.json"), []byte(`{"config":{"bank":"x","country":"SE","env":"sandbox"},"calls":[]}`), 0o644)
	if _, err := LoadScenario(dir); err == nil || !strings.Contains(err.Error(), "now") {
		t.Errorf("err = %v", err)
	}
}

func TestIDSourceFollowsScenarioThenCounts(t *testing.T) {
	s := &Scenario{Config: ScenarioConfig{IDs: map[string][]string{"state": {"s-a"}}}}
	next := s.idSource()
	if next("state") != "s-a" || next("state") != "state-2" || next("request") != "request-1" {
		t.Error("id sequence")
	}
}

func TestRedactorScrubsEchoedAccountNumbers(t *testing.T) {
	r := DefaultRedactor(nil)
	body := string(r.JSON([]byte(`{"creditorAccount":{"iban":"SE4880000123451234567890"}}`)))
	msg := string(r.JSON([]byte(`{"psuMessage":"Approve payment of 1.00 SEK to SE4880000123451234567890"}`)))
	if strings.Contains(body+msg, "SE4880000123451234567890") {
		t.Fatalf("IBAN leaked:\n%s\n%s", body, msg)
	}
	if want := pseudonym("iban", "SE4880000123451234567890"); !strings.Contains(msg, want) {
		t.Errorf("message should carry the same pseudonym %s: %s", want, msg)
	}
}
