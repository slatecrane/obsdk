package obsdk

import (
	"encoding/json"
	"fmt"
	"time"
)

const sessionVersion = 1

// Session is everything the SDK needs to act for a user after authorization.
// Persist it (encrypted at rest: it contains tokens) and hand it back on the
// next call. Updated sessions are returned in result envelopes, on steps and
// in FlowError; save them whenever Result.Session, Step.Session or
// FlowError.Session is non-nil.
type Session struct {
	Version     int     `json:"v"`
	Bank        string  `json:"bank"`
	Country     Country `json:"country"`
	Segment     Segment `json:"segment,omitempty"`
	Env         Env     `json:"env"`
	Integration string  `json:"integration"` // opaque; selects the implementation on restore

	// Generation increases on every change. Use it for compare-and-swap when
	// several instances may refresh the same session.
	Generation int       `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`

	AccessToken      string     `json:"access_token,omitempty"`
	RefreshToken     string     `json:"refresh_token,omitempty"`
	TokenType        string     `json:"token_type,omitempty"`
	Scope            string     `json:"scope,omitempty"`
	AccessExpiresAt  *time.Time `json:"access_expires_at,omitempty"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at,omitempty"`

	// Consents are keyed by bank-defined kind (e.g. "detailed").
	Consents map[string]Consent `json:"consents,omitempty"`

	// Meta is for integration-private data (e.g. the auth method used).
	Meta map[string]string `json:"meta,omitempty"`
}

// Consent records a bank-side consent.
type Consent struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status,omitempty"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	Accounts   []string   `json:"accounts,omitempty"` // IBAN or BBAN of covered accounts
}

// Clone returns a deep copy.
func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	c := *s
	if s.AccessExpiresAt != nil {
		t := *s.AccessExpiresAt
		c.AccessExpiresAt = &t
	}
	if s.RefreshExpiresAt != nil {
		t := *s.RefreshExpiresAt
		c.RefreshExpiresAt = &t
	}
	if s.Consents != nil {
		c.Consents = make(map[string]Consent, len(s.Consents))
		for k, v := range s.Consents {
			if len(v.Accounts) > 0 {
				v.Accounts = append([]string(nil), v.Accounts...)
			}
			c.Consents[k] = v
		}
	}
	if s.Meta != nil {
		c.Meta = make(map[string]string, len(s.Meta))
		for k, v := range s.Meta {
			c.Meta[k] = v
		}
	}
	return &c
}

// Touch bumps Generation and UpdatedAt. Integrations call it on every change.
func (s *Session) Touch(now time.Time) {
	s.Version = sessionVersion
	s.Generation++
	s.UpdatedAt = now.UTC()
}

// AccessExpired reports whether the access token is known to be expired.
func (s *Session) AccessExpired(now time.Time) bool {
	return s.AccessExpiresAt != nil && !now.Before(*s.AccessExpiresAt)
}

// Marshal serializes the session as JSON.
func (s *Session) Marshal() ([]byte, error) { return json.Marshal(s) }

// ParseSession restores a session saved with Marshal.
func ParseSession(data []byte) (*Session, error) {
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("obsdk: parse session: %w", err)
	}
	if s.Version == 0 || s.Version > sessionVersion {
		return nil, fmt.Errorf("obsdk: unsupported session version %d", s.Version)
	}
	return &s, nil
}
