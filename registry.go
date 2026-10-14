package obsdk

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Maturity is an honest statement of how well a variant has been verified,
// from least to most.
type Maturity string

const (
	MaturityUnverified      Maturity = "unverified"       // written from documentation only
	MaturityExperimental    Maturity = "experimental"     // runs against a fake server or recorded spec examples
	MaturitySandboxVerified Maturity = "sandbox_verified" // sandbox variant exercised end to end against the bank's real sandbox
	MaturityVerified        Maturity = "verified"         // production variant exercised against the bank's real production API
)

// Variant is one (country, segment, environment) an integration serves.
type Variant struct {
	Country    Country  `json:"country"`
	Segment    Segment  `json:"segment"`
	Env        Env      `json:"env"`
	Maturity   Maturity `json:"maturity"`
	VerifiedOn string   `json:"verified_on,omitempty"` // YYYY-MM-DD of the last real-API check; required for sandbox_verified and verified
}

// Requirement describes a Config input an integration needs.
type Requirement struct {
	Name     string `json:"name"` // "client_id", "client_secret", "redirect_url", "seal", "tls_client_cert" or an Extra key
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
	Envs     []Env  `json:"envs,omitempty"` // empty means all environments
	Note     string `json:"note,omitempty"`
}

// AuthInfo describes how users authenticate.
type AuthInfo struct {
	Approaches []string `json:"approaches"`        // "redirect", "decoupled", ...
	Methods    []string `json:"methods,omitempty"` // statically known method ids
	Dynamic    bool     `json:"dynamic"`           // the bank also reports methods at runtime (see AuthMethodLister)
}

// Limits holds numbers callers plan around.
type Limits struct {
	MaxConsentDays           int `json:"max_consent_days,omitempty"`
	MaxRequestsPerDay        int `json:"max_requests_per_day,omitempty"` // per account and resource, under a recurring consent
	MaxParallel              int `json:"max_parallel,omitempty"`
	HistoryWithoutStepUpDays int `json:"history_without_step_up_days,omitempty"`
	// RequiresPSUHeaders lists PSUContext fields the bank insists on for user-initiated calls.
	RequiresPSUHeaders []string `json:"requires_psu_headers,omitempty"`
}

// Info is the discovery record for a bank.
type Info struct {
	Bank         string        `json:"bank"` // stable key
	Name         string        `json:"name"`
	Group        string        `json:"group,omitempty"`
	Spec         string        `json:"spec"` // "berlin-group", "stet", "uk", "polish-api", "custom"
	Variants     []Variant     `json:"variants"`
	Capabilities []Capability  `json:"capabilities"`
	Auth         AuthInfo      `json:"auth"`
	Requirements []Requirement `json:"requirements"`
	Limits       Limits        `json:"limits"`
	Docs         []string      `json:"docs,omitempty"`
	Notes        []string      `json:"notes,omitempty"` // quirks worth knowing
}

// Has reports whether the integration offers a capability.
func (i Info) Has(c Capability) bool {
	for _, x := range i.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// Factory builds a client for one resolved variant.
type Factory func(cfg Config, t Target) (Client, error)

// Integration is what a bank package registers.
type Integration struct {
	ID      string // internal; stored (opaque) in sessions so restores resolve to the same code
	Info    Info
	Factory Factory
}

// Registry maps targets to integrations. Registration is strict: two
// integrations may not serve the same (bank, country, segment, env).
type Registry struct {
	mu   sync.RWMutex
	byID map[string]*Integration
}

// NewRegistry returns an empty registry (useful in tests and custom setups).
func NewRegistry() *Registry { return &Registry{byID: map[string]*Integration{}} }

// Register adds an integration or explains why it cannot.
func (r *Registry) Register(i Integration) error {
	if i.ID == "" || i.Factory == nil {
		return fmt.Errorf("obsdk: integration needs an ID and a Factory")
	}
	if i.Info.Bank == "" || i.Info.Bank != strings.ToLower(i.Info.Bank) {
		return fmt.Errorf("obsdk: integration %q needs a lowercase Info.Bank", i.ID)
	}
	if len(i.Info.Variants) == 0 {
		return fmt.Errorf("obsdk: integration %q has no variants", i.ID)
	}
	for _, v := range i.Info.Variants {
		if err := v.checkMaturity(); err != nil {
			return fmt.Errorf("obsdk: integration %q, variant %s/%s/%s: %w", i.ID, v.Country, v.Segment, v.Env, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byID[i.ID]; dup {
		return fmt.Errorf("obsdk: integration %q already registered", i.ID)
	}
	for _, other := range r.byID {
		if other.Info.Bank != i.Info.Bank {
			continue
		}
		for _, a := range i.Info.Variants {
			for _, b := range other.Info.Variants {
				if a.Country == b.Country && a.Segment == b.Segment && a.Env == b.Env {
					return fmt.Errorf("obsdk: integration %q conflicts with %q on %s/%s/%s/%s",
						i.ID, other.ID, i.Info.Bank, a.Country, a.Segment, a.Env)
				}
			}
		}
	}
	cp := i
	r.byID[i.ID] = &cp
	return nil
}

// checkMaturity keeps the verified levels tied to the environment they were
// checked in, with a date.
func (v Variant) checkMaturity() error {
	switch v.Maturity {
	case MaturityUnverified, MaturityExperimental:
		return nil
	case MaturitySandboxVerified:
		if v.Env != Sandbox {
			return fmt.Errorf("maturity %q is only for sandbox variants", v.Maturity)
		}
	case MaturityVerified:
		if v.Env != Production {
			return fmt.Errorf("maturity %q is only for production variants; use %q", v.Maturity, MaturitySandboxVerified)
		}
	default:
		return fmt.Errorf("unknown maturity %q", v.Maturity)
	}
	if v.VerifiedOn == "" {
		return fmt.Errorf("maturity %q needs VerifiedOn", v.Maturity)
	}
	return nil
}

// Filter narrows List. Zero fields match everything.
type Filter struct {
	Bank       string
	Country    Country
	Segment    Segment
	Env        Env
	Capability Capability
}

// List returns discovery records matching the filter, sorted by bank.
func (r *Registry) List(f Filter) []Info {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Info
	for _, i := range r.byID {
		if f.Bank != "" && i.Info.Bank != strings.ToLower(f.Bank) {
			continue
		}
		if f.Capability != "" && !i.Info.Has(f.Capability) {
			continue
		}
		if f.Country != "" || f.Segment != "" || f.Env != "" {
			ok := false
			for _, v := range i.Info.Variants {
				if (f.Country == "" || v.Country == f.Country) &&
					(f.Segment == "" || v.Segment == f.Segment) &&
					(f.Env == "" || v.Env == f.Env) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, i.Info)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Bank < out[b].Bank })
	return mergeByBank(out)
}

// mergeByBank folds several integrations of one bank into one record so
// callers see banks, not implementations.
func mergeByBank(in []Info) []Info {
	var out []Info
	for _, i := range in {
		if n := len(out); n > 0 && out[n-1].Bank == i.Bank {
			m := &out[n-1]
			m.Variants = append(m.Variants, i.Variants...)
			for _, c := range i.Capabilities {
				if !m.Has(c) {
					m.Capabilities = append(m.Capabilities, c)
				}
			}
			continue
		}
		out = append(out, i)
	}
	return out
}

// Lookup returns the discovery record of a bank.
func (r *Registry) Lookup(bank string) (Info, bool) {
	l := r.List(Filter{Bank: bank})
	if len(l) == 0 {
		return Info{}, false
	}
	return l[0], true
}

func (r *Registry) resolve(t Target, env Env) (*Integration, Target, error) {
	t.Bank = strings.ToLower(t.Bank)
	t.Country = Country(strings.ToUpper(string(t.Country)))
	r.mu.RLock()
	defer r.mu.RUnlock()
	known := false
	type hit struct {
		i   *Integration
		seg Segment
	}
	var hits []hit
	for _, i := range r.byID {
		if i.Info.Bank != t.Bank {
			continue
		}
		known = true
		for _, v := range i.Info.Variants {
			if v.Country == t.Country && v.Env == env && (t.Segment == "" || v.Segment == t.Segment) {
				hits = append(hits, hit{i, v.Segment})
			}
		}
	}
	if !known {
		return nil, t, fmt.Errorf("%w: %q", ErrUnknownBank, t.Bank)
	}
	if len(hits) == 0 {
		return nil, t, fmt.Errorf("%w: %s in %s (%s, segment %q)", ErrUnsupportedTarget, t.Bank, t.Country, env, t.Segment)
	}
	if len(hits) > 1 {
		// Registration is strict, so each hit is a different segment. With no
		// segment requested, personal wins when present; otherwise ask.
		var segs []Segment
		for _, h := range hits {
			if h.seg == Personal && t.Segment == "" {
				t.Segment = Personal
				return h.i, t, nil
			}
			segs = append(segs, h.seg)
		}
		sort.Slice(segs, func(a, b int) bool { return segs[a] < segs[b] })
		return nil, t, &AmbiguousTargetError{Target: t, Segments: segs}
	}
	if t.Segment == "" {
		t.Segment = hits[0].seg
	}
	return hits[0].i, t, nil
}

// New resolves the target and builds a client. cfg.Env must be set.
func (r *Registry) New(t Target, cfg Config) (Client, error) {
	if cfg.Env != Sandbox && cfg.Env != Production {
		return nil, &ConfigError{Bank: t.Bank, Env: cfg.Env, Invalid: []string{"Env must be set explicitly to sandbox or production"}}
	}
	i, rt, err := r.resolve(t, cfg.Env)
	if err != nil {
		return nil, err
	}
	if err := validateConfig(i.Info, cfg); err != nil {
		return nil, err
	}
	return i.Factory(cfg, rt)
}

// Restore rebuilds the client that produced a session.
func (r *Registry) Restore(s *Session, cfg Config) (Client, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil session", ErrInvalidRequest)
	}
	if cfg.Env == "" {
		cfg.Env = s.Env
	}
	if cfg.Env != s.Env {
		return nil, &ConfigError{Bank: s.Bank, Env: cfg.Env, Invalid: []string{fmt.Sprintf("session belongs to %s", s.Env)}}
	}
	r.mu.RLock()
	i := r.byID[s.Integration]
	r.mu.RUnlock()
	if i == nil {
		return nil, fmt.Errorf("%w: session was created by an integration that is not registered (import the bank package)", ErrUnknownBank)
	}
	if err := validateConfig(i.Info, cfg); err != nil {
		return nil, err
	}
	return i.Factory(cfg, Target{Bank: s.Bank, Country: s.Country, Segment: s.Segment})
}

func validateConfig(info Info, cfg Config) error {
	var missing []string
	for _, rq := range info.Requirements {
		if !rq.Required || !appliesTo(rq, cfg.Env) {
			continue
		}
		ok := false
		switch rq.Name {
		case "client_id":
			ok = cfg.Credentials.ClientID != ""
		case "client_secret":
			ok = cfg.Credentials.ClientSecret != ""
		case "redirect_url":
			ok = cfg.Credentials.RedirectURL != ""
		case "seal":
			ok = cfg.Seal != nil
		case "tls_client_cert":
			ok = cfg.HTTPClient != nil
		default:
			ok = cfg.Extra[rq.Name] != ""
		}
		if !ok {
			missing = append(missing, rq.Name)
		}
	}
	if len(missing) > 0 {
		return &ConfigError{Bank: info.Bank, Env: cfg.Env, Missing: missing}
	}
	return nil
}

func appliesTo(rq Requirement, env Env) bool {
	if len(rq.Envs) == 0 {
		return true
	}
	for _, e := range rq.Envs {
		if e == env {
			return true
		}
	}
	return false
}

// Default is the process-wide registry that bank packages register into.
var Default = NewRegistry()

// Register adds an integration to the default registry. Bank packages call it
// from init and panic on conflicts, which are programming errors.
func Register(i Integration) {
	if err := Default.Register(i); err != nil {
		panic(err)
	}
}

// List queries the default registry.
func List(f Filter) []Info { return Default.List(f) }

// Lookup queries the default registry.
func Lookup(bank string) (Info, bool) { return Default.Lookup(bank) }

// New builds a client from the default registry.
func New(t Target, cfg Config) (Client, error) { return Default.New(t, cfg) }

// Restore rebuilds a client from a session using the default registry.
func Restore(s *Session, cfg Config) (Client, error) { return Default.Restore(s, cfg) }
