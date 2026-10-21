package obsdktest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// Recorder is an http.RoundTripper that forwards to a real transport and writes
// every exchange, redacted, to dir as numbered JSON files.
type Recorder struct {
	dir  string
	next http.RoundTripper
	red  *Redactor

	mu sync.Mutex
	n  int
}

// NewRecorder records into dir (created if needed). next defaults to http.DefaultTransport.
func NewRecorder(dir string, next http.RoundTripper, red *Redactor) (*Recorder, error) {
	if next == nil {
		next = http.DefaultTransport
	}
	if red == nil {
		red = DefaultRedactor(nil)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	r := &Recorder{dir: dir, next: next, red: red}
	// Continue numbering after files from earlier runs so scenarios can be
	// recorded over several invocations without overwriting.
	if files, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(files) > 0 {
		for _, f := range files {
			var n int
			if _, err := fmt.Sscanf(filepath.Base(f), "%d-", &n); err == nil && n > r.n {
				r.n = n
			}
		}
	}
	return r, nil
}

// requestHeaders recorded for information; volatile or useless ones are skipped.
var skipRequestHeaders = map[string]bool{"date": true, "x-request-id": true, "user-agent": true, "accept-encoding": true, "content-length": true}

// responseHeaders recorded; everything else (Date, cookies, server details) is dropped.
var keepResponseHeaders = map[string]bool{
	"content-type": true, "location": true, "retry-after": true, "x-request-id": true, "aspsp-sca-approach": true,
	"login-method": true, "login-method-extended": true, "content-disposition": true,
	"x-rate-limit-limit": true, "x-rate-limit-remaining": true, "x-rate-limit-reset": true,
}

// RoundTrip implements http.RoundTripper.
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
		if len(reqBody) == 0 {
			// Keep an empty body empty: any other reader makes the transport
			// treat its length as unknown and stream it, and ABN AMRO's edge
			// then waits for a DELETE body that never comes.
			req.Body = http.NoBody
		}
	}
	res, err := r.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resBody, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	res.Body = io.NopCloser(bytes.NewReader(resBody))

	ex := Exchange{
		Request: Request{
			Method: req.Method, Path: r.red.Text(req.URL.Path), Headers: map[string]string{},
		},
		Response: Response{Status: res.StatusCode, Headers: map[string]string{}},
	}
	if q := req.URL.Query(); len(q) > 0 {
		ex.Request.Query = map[string][]string{}
		for k, vs := range q {
			for _, v := range vs {
				ex.Request.Query[k] = append(ex.Request.Query[k], r.red.QueryValue(k, v))
			}
		}
	}
	for k, vs := range req.Header {
		if skipRequestHeaders[strings.ToLower(k)] || len(vs) == 0 {
			continue
		}
		ex.Request.Headers[k] = r.red.Header(k, vs[0])
	}
	for k, vs := range res.Header {
		if keepResponseHeaders[strings.ToLower(k)] && len(vs) > 0 {
			ex.Response.Headers[k] = r.red.Header(k, vs[0])
		}
	}
	if len(ex.Request.Headers) == 0 {
		ex.Request.Headers = nil
	}
	ex.Request.Body, ex.Request.BodyText, _ = r.encodeBody(reqBody, req.Header.Get("Content-Type"))
	var bin string
	ex.Response.Body, ex.Response.BodyText, bin = r.encodeBody(resBody, res.Header.Get("Content-Type"))
	ex.Response.BodyBase64 = bin

	if werr := r.write(ex); werr != nil {
		return nil, werr
	}
	return res, nil
}

// encodeBody redacts a body and picks the most readable representation.
func (r *Recorder) encodeBody(b []byte, contentType string) (js json.RawMessage, text, b64 string) {
	if len(b) == 0 {
		return nil, "", ""
	}
	if bytes.HasPrefix(b, []byte("PK\x03\x04")) {
		if z, err := r.red.Zip(b); err == nil {
			return nil, "", base64.StdEncoding.EncodeToString(z)
		}
		return nil, "[unreadable archive omitted]", ""
	}
	if json.Valid(b) {
		return json.RawMessage(r.red.JSON(b)), "", ""
	}
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") && utf8.Valid(b) {
		return nil, r.red.Form(string(b)), ""
	}
	if utf8.Valid(b) {
		return nil, r.red.Text(string(b)), ""
	}
	return nil, "[binary body omitted]", ""
}

var slugRe = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func (r *Recorder) write(ex Exchange) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	parts := strings.Split(strings.Trim(ex.Request.Path, "/"), "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	slug := strings.Trim(slugRe.ReplaceAllString(strings.Join(parts, "-"), "-"), "-")
	name := fmt.Sprintf("%03d-%s-%s.json", r.n, strings.ToLower(ex.Request.Method), slug)
	b, err := json.MarshalIndent(ex, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.dir, name), append(b, '\n'), 0o644)
}
