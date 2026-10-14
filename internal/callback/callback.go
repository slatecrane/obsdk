// Package callback parses redirect callbacks. Banks return parameters in the
// query, in the fragment, as a form body, as JSON, or as urlencoded JSON.
package callback

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoParams means the callback carried no parameters at all. Some banks
// return the user like that after an approval; the callback is then only a
// signal to check status.
var ErrNoParams = errors.New("callback: no parameters found")

// Params is a flat view of a callback.
type Params map[string]string

// Get returns the first non-empty value among keys.
func (p Params) Get(keys ...string) string {
	for _, k := range keys {
		if v := p[k]; v != "" {
			return v
		}
	}
	return ""
}

// Error returns a description when the callback reports a failure.
func (p Params) Error() (code, description string, failed bool) {
	code = p.Get("error")
	if code == "" {
		return "", "", false
	}
	return code, p.Get("error_description", "error_message"), true
}

// Parse accepts a full URL, a path with query, a bare query string, a
// fragment ("#a=b"), a JSON object, or a urlencoded JSON object. Query and
// fragment values are merged; the query wins on conflict.
func Parse(raw string) (Params, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("callback: empty")
	}
	if p, ok := fromJSON(raw); ok {
		return p, nil
	}
	if strings.HasPrefix(raw, "%7B") || strings.HasPrefix(raw, "%7b") {
		if dec, err := url.QueryUnescape(raw); err == nil {
			if p, ok := fromJSON(dec); ok {
				return p, nil
			}
		}
	}

	var query, fragment string
	switch {
	case strings.Contains(raw, "://") || strings.HasPrefix(raw, "/"):
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("callback: %w", err)
		}
		query, fragment = u.RawQuery, u.Fragment
	case strings.HasPrefix(raw, "#"):
		fragment = raw[1:]
	default:
		raw = strings.TrimPrefix(raw, "?")
		if i := strings.Index(raw, "#"); i >= 0 {
			query, fragment = raw[:i], raw[i+1:]
		} else {
			query = raw
		}
	}

	out := Params{}
	// A urlencoded JSON object can sit in the fragment or query as the whole value.
	for _, part := range []string{fragment, query} { // query last so it wins
		if part == "" {
			continue
		}
		if dec, err := url.QueryUnescape(part); err == nil {
			if p, ok := fromJSON(dec); ok {
				for k, v := range p {
					out[k] = v
				}
				continue
			}
		}
		vals, err := url.ParseQuery(part)
		if err != nil {
			return nil, fmt.Errorf("callback: %w", err)
		}
		for k := range vals {
			out[k] = vals.Get(k)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoParams
	}
	return out, nil
}

func fromJSON(s string) (Params, bool) {
	if !strings.HasPrefix(s, "{") {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil, false
	}
	p := Params{}
	for k, v := range m {
		switch t := v.(type) {
		case string:
			p[k] = t
		case nil:
		default:
			b, _ := json.Marshal(t)
			p[k] = string(b)
		}
	}
	return p, true
}
