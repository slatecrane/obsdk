package obsdktest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Seen is a request the replayer received, for assertions in tests.
type Seen struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

// Replayer is an http.RoundTripper that answers from recorded exchanges.
// Matching is by method, path and query; each exchange answers one request, in
// file order, so repeated polls can be given different answers. A request with
// no unused matching exchange is an error that lists the nearest candidates.
type Replayer struct {
	mu          sync.Mutex
	slots       []*slot
	seen        []Seen
	ignoreQuery map[string]bool
	matchBody   bool
	repeatLast  bool
	red         *Redactor
}

type slot struct {
	ex   Exchange
	used bool
}

// ReplayOption tunes matching.
type ReplayOption func(*Replayer)

// IgnoreQuery excludes query parameters from matching (for example volatile ones).
func IgnoreQuery(keys ...string) ReplayOption {
	return func(r *Replayer) {
		for _, k := range keys {
			r.ignoreQuery[k] = true
		}
	}
}

// WithRedactor sets the redactor applied to outgoing requests before matching
// (secret query values and JSON fields become the same placeholders the
// recorder wrote). The default redactor is used otherwise.
func WithRedactor(red *Redactor) ReplayOption { return func(r *Replayer) { r.red = red } }

// MatchBody also requires JSON request bodies to match the fixture.
func MatchBody() ReplayOption { return func(r *Replayer) { r.matchBody = true } }

// RepeatLast answers a request whose exchanges are all used with the last
// matching one instead of failing. Useful for hand-written fixtures that poll.
func RepeatLast() ReplayOption { return func(r *Replayer) { r.repeatLast = true } }

// NewReplayer loads exchanges from dir.
func NewReplayer(dir string, opts ...ReplayOption) (*Replayer, error) {
	ex, err := LoadExchanges(dir)
	if err != nil {
		return nil, err
	}
	return NewReplayerFrom(ex, opts...), nil
}

// NewReplayerFrom builds a replayer from in-memory exchanges.
func NewReplayerFrom(ex []Exchange, opts ...ReplayOption) *Replayer {
	r := &Replayer{ignoreQuery: map[string]bool{}, red: DefaultRedactor(nil)}
	for _, o := range opts {
		o(r)
	}
	for _, e := range ex {
		r.slots = append(r.slots, &slot{ex: e})
	}
	return r
}

// Client returns an http.Client that never follows redirects and uses the replayer.
func (r *Replayer) Client() *http.Client {
	return &http.Client{Transport: r, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Requests returns every request received so far.
func (r *Replayer) Requests() []Seen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Seen(nil), r.seen...)
}

// Unused lists exchanges that were never requested.
func (r *Replayer) Unused() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, s := range r.slots {
		if !s.used {
			out = append(out, describe(s.ex))
		}
	}
	return out
}

// AssertAllUsed fails the test if some recorded exchange was never requested,
// which usually means the SDK stopped making a call it used to make.
func (r *Replayer) AssertAllUsed(t testing.TB) {
	t.Helper()
	if u := r.Unused(); len(u) > 0 {
		t.Errorf("recorded exchanges never requested:\n  %s", strings.Join(u, "\n  "))
	}
}

func describe(e Exchange) string {
	name := e.file
	if name == "" {
		name = "(inline)"
	}
	return fmt.Sprintf("%s %s %s", e.Request.Method, e.Request.Path, name)
}

func (r *Replayer) queryMatches(want map[string][]string, got url.Values) bool {
	norm := func(m map[string][]string) map[string]string {
		out := map[string]string{}
		for k, v := range m {
			if r.ignoreQuery[k] {
				continue
			}
			c := make([]string, len(v))
			for i, x := range v {
				// The SDK may carry a secret under another name than the one it
				// is sent under (callback "access_code" becomes token "code"):
				// compare placeholders by digest, not by label.
				c[i] = labelRe.ReplaceAllString(x, "REDACTED:*:")
			}
			sort.Strings(c)
			out[k] = strings.Join(c, "\x00")
		}
		return out
	}
	w, g := norm(want), norm(got)
	if len(w) != len(g) {
		return false
	}
	for k, v := range w {
		gv, ok := g[k]
		if !ok {
			return false
		}
		// A recorded literal credential ("REDACTED:client_secret", no digest)
		// stands for whatever credential the caller configured.
		if literalRe.MatchString(v) {
			continue
		}
		if gv != v {
			return false
		}
	}
	return true
}

var literalRe = regexp.MustCompile(`^REDACTED:[A-Za-z0-9_-]+$`)

var labelRe = regexp.MustCompile(`REDACTED:[A-Za-z0-9_-]+:`)

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

// RoundTrip implements http.RoundTripper.
func (r *Replayer) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	path := strings.TrimRight(req.URL.Path, "/")
	q := req.URL.Query()
	// Match on the redacted form of the request: the fixture holds placeholders,
	// the SDK sends whatever credentials the test configured.
	rq := url.Values{}
	for k, vs := range q {
		for _, v := range vs {
			rq.Add(k, r.red.QueryValue(k, v))
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, Seen{Method: req.Method, Path: path, Query: q, Header: req.Header.Clone(), Body: body})

	var candidates []string
	var last *slot
	for _, s := range r.slots {
		e := s.ex
		if !strings.EqualFold(e.Request.Method, req.Method) || strings.TrimRight(e.Request.Path, "/") != path {
			continue
		}
		candidates = append(candidates, fmt.Sprintf("%s query=%v used=%t", e.file, e.Request.Query, s.used))
		if !r.queryMatches(e.Request.Query, rq) {
			continue
		}
		if r.matchBody && len(e.Request.Body) > 0 && !jsonEqual(e.Request.Body, r.red.JSON(body)) {
			continue
		}
		last = s
		if s.used {
			continue
		}
		s.used = true
		return build(req, e.Response)
	}
	if last != nil && r.repeatLast {
		return build(req, last.ex.Response)
	}
	msg := fmt.Sprintf("obsdktest: no unused recorded exchange for %s %s?%s", req.Method, path, q.Encode())
	if len(candidates) > 0 {
		msg += "\n  same method and path:\n    " + strings.Join(candidates, "\n    ")
	}
	return nil, fmt.Errorf("%s", msg)
}

func build(req *http.Request, rs Response) (*http.Response, error) {
	var body []byte
	switch {
	case rs.BodyBase64 != "":
		b, err := base64.StdEncoding.DecodeString(rs.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("obsdktest: bad body_base64: %w", err)
		}
		body = b
	case len(rs.Body) > 0:
		body = rs.Body
	default:
		body = []byte(rs.BodyText)
	}
	h := http.Header{}
	for k, v := range rs.Headers {
		h.Set(k, v)
	}
	if len(rs.Body) > 0 && h.Get("Content-Type") == "" {
		h.Set("Content-Type", "application/json")
	}
	return &http.Response{
		Status: fmt.Sprintf("%d %s", rs.Status, http.StatusText(rs.Status)), StatusCode: rs.Status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: h,
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req,
	}, nil
}
