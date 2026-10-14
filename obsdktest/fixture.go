package obsdktest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Request is the recorded (redacted) request half of an exchange. Matching
// uses Method, Path and Query; Headers and Body are kept for people reading
// the fixture and for tests that assert on what the SDK sent.
type Request struct {
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	Query    map[string][]string `json:"query,omitempty"`
	Headers  map[string]string   `json:"headers,omitempty"`
	Body     json.RawMessage     `json:"body,omitempty"`      // JSON bodies, inline for readability
	BodyText string              `json:"body_text,omitempty"` // non-JSON text bodies
}

// Response is the recorded (redacted) response.
type Response struct {
	Status     int               `json:"status"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       json.RawMessage   `json:"body,omitempty"`
	BodyText   string            `json:"body_text,omitempty"`
	BodyBase64 string            `json:"body_base64,omitempty"` // binary, e.g. a statement ZIP
}

// Exchange is one request and its response. Fixtures are plain JSON files so
// they can be written or edited by hand, which is how you cover cases the
// sandbox can't produce (error codes, expired tokens, odd payloads).
type Exchange struct {
	Note     string   `json:"note,omitempty"`
	Request  Request  `json:"request"`
	Response Response `json:"response"`

	file string // set when loaded from disk
}

// File is the file the exchange was loaded from, for error messages.
func (e Exchange) File() string { return e.file }

// LoadExchanges reads every *.json file in dir in name order.
func LoadExchanges(dir string) ([]Exchange, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := make([]Exchange, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e Exchange
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("obsdktest: %s: %w", f, err)
		}
		if e.Request.Method == "" || e.Request.Path == "" || e.Response.Status == 0 {
			return nil, fmt.Errorf("obsdktest: %s: request.method, request.path and response.status are required", f)
		}
		e.file = f
		out = append(out, e)
	}
	return out, nil
}
