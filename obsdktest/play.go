package obsdktest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

var update = flag.Bool("obsdktest.update", false, "rewrite golden.json files with the current outcomes")

// ClientConfig builds the obsdk.Config for the scenario: a frozen clock,
// replayed identifiers and placeholder credentials. doer carries the HTTP.
func (s *Scenario) ClientConfig(doer obsdk.HTTPDoer) obsdk.Config {
	redirect := s.Config.RedirectURL
	if redirect == "" {
		redirect = "https://app.example/callback"
	}
	now := s.Config.Now
	return obsdk.Config{
		Env: obsdk.Env(s.Config.Env),
		Credentials: obsdk.Credentials{
			ClientID:     placeholder("client_id"),
			ClientSecret: obsdk.Secret(placeholder("client_secret")),
			RedirectURL:  redirect,
		},
		Extra:      s.Config.Extra,
		HTTPClient: doer,
		Seal:       &obsdk.Seal{Key: testSigner{}, KeyID: "test-kid"},
		Now:        func() time.Time { return now },
		NewID:      s.idSource(),
	}
}

// testSigner stands in for a signing key in replays. Its signatures are fixed
// bytes, so anything signed (request objects in redirect URLs) is reproducible
// and can be compared with golden files. Banks never see them during replay.
type testSigner struct{}

var testSignerKey = &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}

func (testSigner) Public() crypto.PublicKey { return testSignerKey }
func (testSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return append([]byte("test-signature:"), digest[:8]...), nil
}

func (s *Scenario) idSource() func(string) string {
	var mu sync.Mutex
	used := map[string]int{}
	return func(purpose string) string {
		mu.Lock()
		defer mu.Unlock()
		n := used[purpose]
		used[purpose]++
		if ids := s.Config.IDs[purpose]; n < len(ids) {
			return ids[n]
		}
		return fmt.Sprintf("%s-%d", purpose, n+1)
	}
}

// NewClient builds the client under test. With a session.json next to the
// scenario the client is restored from it, otherwise created from the target.
func (s *Scenario) NewClient(doer obsdk.HTTPDoer) (*Runner, error) {
	cfg := s.ClientConfig(doer)
	r := &Runner{}
	var err error
	if b, rerr := os.ReadFile(filepath.Join(s.Dir, "session.json")); rerr == nil {
		if r.Session, err = obsdk.ParseSession(b); err != nil {
			return nil, err
		}
		r.Client, err = obsdk.Restore(r.Session, cfg)
	} else if os.IsNotExist(rerr) {
		r.Client, err = obsdk.New(obsdk.Target{Bank: s.Config.Bank, Country: obsdk.Country(s.Config.Country), Segment: obsdk.Segment(s.Config.Segment)}, cfg)
	} else {
		return nil, rerr
	}
	return r, err
}

// Replay runs the scenario against its recorded exchanges and returns the
// outcomes, plus the names of recorded exchanges that were never requested.
func Replay(ctx context.Context, s *Scenario) (outcomes []Outcome, unused []string, err error) {
	var opts []ReplayOption
	if len(s.Config.IgnoreQuery) > 0 {
		opts = append(opts, IgnoreQuery(s.Config.IgnoreQuery...))
	}
	if s.Config.MatchBody {
		opts = append(opts, MatchBody())
	}
	if s.Config.RepeatLast {
		opts = append(opts, RepeatLast())
	}
	rp, err := NewReplayer(s.ExchangesDir(), opts...)
	if err != nil {
		return nil, nil, err
	}
	run, err := s.NewClient(rp.Client())
	if err != nil {
		return nil, nil, err
	}
	for _, c := range s.Calls {
		outcomes = append(outcomes, run.Do(ctx, c))
	}
	return outcomes, rp.Unused(), nil
}

// MarshalOutcomes renders outcomes the way golden.json stores them.
func MarshalOutcomes(o []Outcome) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(o); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Play replays the scenario in dir and compares the outcomes with golden.json.
// Run `go test -obsdktest.update` to (re)write golden files, then review the
// diff in version control: the golden file is the contract.
//
// Every recorded exchange must be used; leftovers usually mean the SDK stopped
// making a call the bank was once asked for.
func Play(t *testing.T, dir string) {
	t.Helper()
	s, err := LoadScenario(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, unused, err := Replay(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MarshalOutcomes(got)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join(dir, "golden.json")
	if *update {
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v\nrun with -obsdktest.update to create it", err)
		}
		if !bytes.Equal(want, b) {
			t.Errorf("outcomes differ from %s (run with -obsdktest.update to accept)\n%s", golden, firstDiff(string(want), string(b)))
		}
	}
	if len(unused) > 0 {
		t.Errorf("recorded exchanges never requested:\n  %s", strings.Join(unused, "\n  "))
	}
}

// PlayAll runs Play as a subtest for every scenario found under root.
func PlayAll(t *testing.T, root string) {
	t.Helper()
	dirs, err := FindScenarios(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Skipf("no scenarios under %s", root)
	}
	for _, d := range dirs {
		rel, _ := filepath.Rel(root, d)
		t.Run(filepath.ToSlash(rel), func(t *testing.T) { Play(t, d) })
	}
}

// firstDiff shows the first differing line with a little context.
func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			lo := i - 3
			if lo < 0 {
				lo = 0
			}
			ctx := strings.Join(g[lo:i], "\n")
			return fmt.Sprintf("first difference at line %d:\n  want: %s\n  got:  %s\n  context:\n%s", i+1, a, b, ctx)
		}
	}
	return "(no textual difference)"
}
