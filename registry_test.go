package obsdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type stubClient struct{ Client }

func stub(bank string, vs ...Variant) Integration {
	return Integration{
		ID: bank + "-" + string(vs[0].Country) + "-" + string(vs[0].Segment),
		Info: Info{Bank: bank, Name: bank, Spec: "custom", Variants: vs, Capabilities: AISP,
			Requirements: []Requirement{{Name: "client_id", Required: true}, {Name: "client_secret", Required: true, Secret: true, Envs: []Env{Production}}, {Name: "region", Required: true, Envs: []Env{Sandbox}}}},
		Factory: func(Config, Target) (Client, error) { return stubClient{}, nil },
	}
}

func v(c Country, s Segment, e Env) Variant {
	return Variant{Country: c, Segment: s, Env: e, Maturity: MaturityExperimental}
}

func TestRegistrationIsStrict(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stub("acme", v("DE", Personal, Sandbox))); err != nil {
		t.Fatal(err)
	}
	second := stub("acme", v("DE", Personal, Sandbox))
	second.ID = "acme-v2"
	if err := r.Register(second); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Errorf("same variant twice: %v", err)
	}
	same := stub("acme", v("DE", Personal, Sandbox))
	if err := r.Register(same); err == nil {
		t.Error("duplicate id accepted")
	}
	// Different segment or environment is fine.
	other := stub("acme", v("DE", Business, Sandbox))
	if err := r.Register(other); err != nil {
		t.Errorf("different segment: %v", err)
	}
	bad := Integration{ID: "x", Info: Info{Bank: "Upper", Variants: []Variant{v("DE", Personal, Sandbox)}}, Factory: other.Factory}
	if err := r.Register(bad); err == nil {
		t.Error("uppercase bank key accepted")
	}
}

func TestMaturityMatchesEnvironment(t *testing.T) {
	cases := []struct {
		v  Variant
		ok bool
	}{
		{Variant{Country: "DE", Env: Sandbox, Maturity: MaturitySandboxVerified, VerifiedOn: "2026-10-13"}, true},
		{Variant{Country: "DE", Env: Production, Maturity: MaturityVerified, VerifiedOn: "2026-10-13"}, true},
		{Variant{Country: "DE", Env: Production, Maturity: MaturityUnverified}, true},
		{Variant{Country: "DE", Env: Sandbox, Maturity: MaturityVerified, VerifiedOn: "2026-10-13"}, false},
		{Variant{Country: "DE", Env: Production, Maturity: MaturitySandboxVerified, VerifiedOn: "2026-10-13"}, false},
		{Variant{Country: "DE", Env: Sandbox, Maturity: MaturitySandboxVerified}, false}, // no date
		{Variant{Country: "DE", Env: Sandbox, Maturity: "stable"}, false},
	}
	for _, c := range cases {
		err := NewRegistry().Register(stub("acme", c.v))
		if (err == nil) != c.ok {
			t.Errorf("%s/%s: err = %v, want ok=%t", c.v.Env, c.v.Maturity, err, c.ok)
		}
	}
}

func TestResolveAndValidate(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stub("acme", v("DE", Personal, Sandbox), v("DE", Personal, Production)))
	biz := stub("acme", v("DE", Business, Sandbox))
	_ = r.Register(biz)
	_ = r.Register(stub("solo", v("PL", Business, Sandbox)))

	good := Config{Env: Sandbox, Credentials: Credentials{ClientID: "id"}, Extra: map[string]string{"region": "eu"}}

	if _, err := r.New(Target{Bank: "acme", Country: "DE"}, Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("env must be explicit: %v", err)
	}
	if _, err := r.New(Target{Bank: "nope", Country: "DE"}, good); !errors.Is(err, ErrUnknownBank) {
		t.Errorf("unknown bank: %v", err)
	}
	if _, err := r.New(Target{Bank: "acme", Country: "FR"}, good); !errors.Is(err, ErrUnsupportedTarget) {
		t.Errorf("unsupported country: %v", err)
	}
	// Personal wins when no segment is given and both exist.
	if _, err := r.New(Target{Bank: "ACME", Country: "de"}, good); err != nil {
		t.Errorf("case-insensitive target / personal default: %v", err)
	}
	// A bank that only has a business variant resolves without a segment.
	if _, err := r.New(Target{Bank: "solo", Country: "PL"}, good); err != nil {
		t.Errorf("single business variant: %v", err)
	}
	// Requirements are checked per environment and reported together.
	_, err := r.New(Target{Bank: "acme", Country: "DE"}, Config{Env: Sandbox, Credentials: Credentials{}})
	var ce *ConfigError
	if !errors.As(err, &ce) || strings.Join(ce.Missing, ",") != "client_id,region" {
		t.Errorf("missing sandbox config: %v", err)
	}
	_, err = r.New(Target{Bank: "acme", Country: "DE"}, Config{Env: Production, Credentials: Credentials{ClientID: "id"}})
	if !errors.As(err, &ce) || strings.Join(ce.Missing, ",") != "client_secret" {
		t.Errorf("missing production config: %v", err)
	}
}

func TestAmbiguousTarget(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stub("acme", v("DE", Business, Sandbox)))
	two := stub("acme", v("DE", Segment("corporate"), Sandbox))
	_ = r.Register(two)
	_, err := r.New(Target{Bank: "acme", Country: "DE"}, Config{Env: Sandbox, Credentials: Credentials{ClientID: "id"}, Extra: map[string]string{"region": "x"}})
	var ae *AmbiguousTargetError
	if !errors.Is(err, ErrAmbiguousTarget) || !errors.As(err, &ae) || len(ae.Segments) != 2 {
		t.Errorf("ambiguous: %v", err)
	}
}

func TestDiscovery(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stub("acme", v("DE", Personal, Sandbox)))
	_ = r.Register(stub("acme", v("FR", Personal, Production)))
	_ = r.Register(stub("zeta", v("DE", Personal, Production)))

	all := r.List(Filter{})
	if len(all) != 2 || all[0].Bank != "acme" || len(all[0].Variants) != 2 {
		t.Fatalf("banks are merged and sorted: %+v", all)
	}
	if got := r.List(Filter{Country: "DE", Env: Production}); len(got) != 1 || got[0].Bank != "zeta" {
		t.Errorf("filter: %+v", got)
	}
	if got := r.List(Filter{Capability: CapPayments}); len(got) != 0 {
		t.Errorf("capability filter: %+v", got)
	}
	if i, ok := r.Lookup("ACME"); !ok || i.Bank != "acme" {
		t.Error("lookup")
	}
	if _, ok := r.Lookup("missing"); ok {
		t.Error("lookup of unknown bank")
	}
}

func TestRestore(t *testing.T) {
	r := NewRegistry()
	in := stub("acme", v("DE", Personal, Sandbox))
	_ = r.Register(in)
	s := &Session{Version: 1, Bank: "acme", Country: "DE", Env: Sandbox, Integration: in.ID}
	cfg := Config{Credentials: Credentials{ClientID: "id"}, Extra: map[string]string{"region": "x"}}
	if _, err := r.Restore(s, cfg); err != nil {
		t.Errorf("restore: %v", err)
	}
	cfg.Env = Production
	if _, err := r.Restore(s, cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("env mismatch: %v", err)
	}
	s.Integration = "gone"
	cfg.Env = Sandbox
	if _, err := r.Restore(s, cfg); !errors.Is(err, ErrUnknownBank) {
		t.Errorf("unknown integration: %v", err)
	}
	if _, err := r.Restore(nil, cfg); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("nil session: %v", err)
	}
}

func TestSecretIsRedacted(t *testing.T) {
	c := Credentials{ClientID: "id", ClientSecret: "super-secret"}
	b, _ := json.Marshal(c)
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "secret", c.ClientSecret)
	out := fmt.Sprintf("%v %+v %s %s", c, c, b, buf.String())
	if strings.Contains(out, "super-secret") {
		t.Errorf("secret leaked: %s", out)
	}
	if c.ClientSecret.Reveal() != "super-secret" {
		t.Error("Reveal broken")
	}
}

func TestSessionRoundTripAndClone(t *testing.T) {
	exp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := &Session{Bank: "b", Env: Sandbox, AccessToken: "t", AccessExpiresAt: &exp,
		Consents: map[string]Consent{"k": {ID: "c", Accounts: []string{"a"}}}, Meta: map[string]string{"m": "1"}}
	s.Touch(exp)
	b, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSession(b)
	if err != nil || got.AccessToken != "t" || got.Generation != 1 || !got.AccessExpiresAt.Equal(exp) {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	cl := s.Clone()
	cl.Consents["k"].Accounts[0] = "changed"
	cl.Meta["m"] = "2"
	*cl.AccessExpiresAt = exp.Add(time.Hour)
	if s.Consents["k"].Accounts[0] != "a" || s.Meta["m"] != "1" || !s.AccessExpiresAt.Equal(exp) {
		t.Error("Clone shares memory with the original")
	}
	if !s.AccessExpired(exp) || s.AccessExpired(exp.Add(-time.Second)) {
		t.Error("AccessExpired")
	}
	if _, err := ParseSession([]byte(`{"v":99}`)); err == nil {
		t.Error("future session version accepted")
	}
	if _, err := ParseSession([]byte(`{}`)); err == nil {
		t.Error("versionless session accepted")
	}
}

func TestStableAccountID(t *testing.T) {
	a := StableAccountID([]Identifier{{"BBAN", "123"}, {"IBAN", "SE00 1234"}}, "SEK")
	b := StableAccountID([]Identifier{{"IBAN", "se001234"}}, "sek")
	if a == "" || a != b {
		t.Errorf("IBAN-based id should ignore other identifiers, spacing and case: %q %q", a, b)
	}
	if StableAccountID([]Identifier{{"IBAN", "SE001234"}}, "SEK") == StableAccountID([]Identifier{{"IBAN", "SE001234"}}, "EUR") {
		t.Error("currencies sharing an IBAN need distinct ids")
	}
	if StableAccountID([]Identifier{{"BBAN", "123"}}, "SEK") == StableAccountID([]Identifier{{"BBAN", "123"}}, "EUR") {
		t.Error("BBAN-based id must include currency")
	}
	if StableAccountID(nil, "SEK") != "" {
		t.Error("no identifiers should give an empty id")
	}
}

func TestDecimal(t *testing.T) {
	r, ok := Decimal("-425.65").Rat()
	if !ok || r.FloatString(2) != "-425.65" {
		t.Errorf("rat: %v", r)
	}
	if _, ok := Decimal("abc").Rat(); ok {
		t.Error("garbage parsed")
	}
}
