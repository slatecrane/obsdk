// Package flowstate encodes resumable-operation state as an opaque, versioned string.
//
// The encoding is not encrypted: state can contain tokens, so callers must
// treat it like a Session.
package flowstate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const prefix = "obs1."

// Encode serializes v.
func Encode(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Decode restores v from Encode output.
func Decode(s string, v any) error {
	if !strings.HasPrefix(s, prefix) {
		return fmt.Errorf("flowstate: unrecognized state")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return fmt.Errorf("flowstate: %w", err)
	}
	return json.Unmarshal(b, v)
}
