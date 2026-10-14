package obsdktest

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// ScenarioRecorder captures a live session as a replayable scenario: the HTTP
// exchanges (through a Recorder), the calls made on the client, and the
// identifiers the client generated. Everything is redacted on the way in.
//
//	rec, _ := obsdktest.NewScenarioRecorder(dir, cfg, nil)
//	cfg.HTTPClient = &http.Client{Transport: rec.Transport(nil)}
//	cfg.NewID = rec.NewID(cfg.NewID)
//	client = rec.Wrap(client)
//	... drive the client ...
//	rec.Save()
//
// Then run the scenario once with -obsdktest.update to create golden.json and
// read both the exchanges and the golden file before committing them.
type ScenarioRecorder struct {
	Scenario *Scenario
	Red      *Redactor

	mu      sync.Mutex
	rec     *Recorder
	started bool
}

// NewScenarioRecorder starts or continues the scenario in dir. cfg supplies
// bank, country, segment and env for a new scenario; for an existing one only
// the calls and exchanges are appended. red may be nil.
func NewScenarioRecorder(dir string, cfg ScenarioConfig, red *Redactor) (*ScenarioRecorder, error) {
	if red == nil {
		red = DefaultRedactor(nil)
	}
	r := &ScenarioRecorder{Red: red}
	if s, err := LoadScenario(dir); err == nil {
		r.Scenario = s
	} else if os.IsNotExist(err) {
		if cfg.Now.IsZero() {
			cfg.Now = time.Now().UTC().Truncate(time.Second)
		}
		cfg.IDs = map[string][]string{}
		extra := map[string]string{}
		for k, v := range cfg.Extra {
			if k == "base_url" {
				continue // points at the live host; replay doesn't use hosts
			}
			extra[k] = red.QueryValue(k, v)
		}
		if len(extra) == 0 {
			extra = nil
		}
		cfg.Extra = extra
		r.Scenario = &Scenario{Dir: dir, Config: cfg}
	} else {
		return nil, err
	}
	return r, nil
}

// Transport returns the recording transport; next defaults to http.DefaultTransport.
func (r *ScenarioRecorder) Transport(next http.RoundTripper) http.RoundTripper {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rec == nil {
		rec, err := NewRecorder(r.Scenario.ExchangesDir(), next, r.Red)
		if err != nil {
			return errTransport{err}
		}
		r.rec = rec
	}
	return r.rec
}

type errTransport struct{ err error }

func (e errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// NewID wraps an identifier source (nil for the SDK default) and remembers what it produced.
func (r *ScenarioRecorder) NewID(next func(string) string) func(string) string {
	return func(purpose string) string {
		var id string
		if next != nil {
			id = next(purpose)
		} else {
			id = obsdk.NewUUID()
		}
		r.mu.Lock()
		if r.Scenario.Config.IDs == nil {
			r.Scenario.Config.IDs = map[string][]string{}
		}
		r.Scenario.Config.IDs[purpose] = append(r.Scenario.Config.IDs[purpose], id)
		r.mu.Unlock()
		return id
	}
}

// SetStartSession stores a redacted copy of the session the recording starts
// from (when the first call isn't a connect). Tokens never reach the fixture.
// It does nothing if the scenario already has calls.
func (r *ScenarioRecorder) SetStartSession(s *obsdk.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == nil || len(r.Scenario.Calls) > 0 {
		return nil
	}
	c := s.Clone()
	if c.AccessToken != "" {
		c.AccessToken = placeholder("access_token")
	}
	if c.RefreshToken != "" {
		c.RefreshToken = placeholder("refresh_token")
	}
	for k, con := range c.Consents {
		for i, a := range con.Accounts {
			con.Accounts[i] = pseudonym("iban", a)
		}
		c.Consents[k] = con
	}
	b, err := c.Marshal()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.Scenario.Dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.Scenario.Dir, "session.json"), b, 0o644)
}

// Save writes scenario.json.
func (r *ScenarioRecorder) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Scenario.Save()
}

func (r *ScenarioRecorder) add(c Call) {
	r.mu.Lock()
	r.Scenario.Calls = append(r.Scenario.Calls, c)
	r.mu.Unlock()
}

func (r *ScenarioRecorder) values(v map[string]string) map[string]string {
	if len(v) == 0 {
		return nil
	}
	out := make(map[string]string, len(v))
	for k, x := range v {
		out[k] = r.Red.QueryValue(k, x)
	}
	return out
}

func (r *ScenarioRecorder) psu(c *Call, p obsdk.PSUContext) {
	if p.IP != "" {
		c.PSUIP = "203.0.113.7" // documentation address
	}
	c.PSUUserAgent = p.UserAgent
	if p.ID != "" {
		c.PSUID = placeholder("psu_id")
	}
}

// Wrap returns a client that logs every call into the scenario.
func (r *ScenarioRecorder) Wrap(c obsdk.Client) obsdk.Client {
	return &recordingClient{Client: c, r: r}
}

type recordingClient struct {
	obsdk.Client
	r *ScenarioRecorder
}

func (c *recordingClient) Connect(ctx context.Context, req obsdk.ConnectRequest) (*obsdk.Step, error) {
	call := Call{Op: "connect", Method: req.Method, Language: req.Language, RedirectURL: req.RedirectURL,
		ValidityDays: req.ConsentValidityDays, Values: c.r.values(req.Values)}
	for _, cp := range req.Capabilities {
		call.Capabilities = append(call.Capabilities, string(cp))
	}
	c.r.psu(&call, req.PSU)
	c.r.add(call)
	return c.Client.Connect(ctx, req)
}

func (c *recordingClient) Resume(ctx context.Context, state string, in obsdk.StepInput) (*obsdk.Step, error) {
	call := Call{Op: "resume", Values: c.r.values(in.Values)}
	if in.Callback != "" {
		call.Callback = c.r.Red.URL(in.Callback)
	}
	c.r.add(call)
	return c.Client.Resume(ctx, state, in)
}

func (c *recordingClient) Accounts(ctx context.Context, s *obsdk.Session, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	call := Call{Op: "accounts"}
	if o.PSU != nil {
		c.r.psu(&call, *o.PSU)
	}
	c.r.add(call)
	return c.Client.Accounts(ctx, s, o)
}

func (c *recordingClient) Balances(ctx context.Context, s *obsdk.Session, id string, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	call := Call{Op: "balances", Account: id}
	if o.PSU != nil {
		c.r.psu(&call, *o.PSU)
	}
	c.r.add(call)
	return c.Client.Balances(ctx, s, id, o)
}

func (c *recordingClient) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	call := Call{Op: "transactions", Account: q.AccountID, PageSize: q.PageSize, Cursor: q.Cursor}
	if !q.From.IsZero() {
		call.From = q.From.UTC().Format(time.RFC3339)
	}
	if !q.To.IsZero() {
		call.To = q.To.UTC().Format(time.RFC3339)
	}
	for _, st := range q.Status {
		call.Status = append(call.Status, string(st))
	}
	if q.Options.PSU != nil {
		c.r.psu(&call, *q.Options.PSU)
	}
	c.r.add(call)
	return c.Client.Transactions(ctx, s, q)
}

func (c *recordingClient) Refresh(ctx context.Context, s *obsdk.Session) (*obsdk.Session, error) {
	c.r.add(Call{Op: "refresh"})
	return c.Client.Refresh(ctx, s)
}

func (c *recordingClient) Disconnect(ctx context.Context, s *obsdk.Session) (*obsdk.DisconnectResult, error) {
	c.r.add(Call{Op: "disconnect"})
	return c.Client.Disconnect(ctx, s)
}

// AuthMethods keeps the optional AuthMethodLister capability visible through the wrapper.
func (c *recordingClient) AuthMethods(ctx context.Context) ([]obsdk.AuthMethod, error) {
	l, ok := c.Client.(obsdk.AuthMethodLister)
	if !ok {
		return nil, obsdk.ErrUnsupported
	}
	c.r.add(Call{Op: "auth_methods"})
	return l.AuthMethods(ctx)
}
