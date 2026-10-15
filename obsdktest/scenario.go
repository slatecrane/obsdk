package obsdktest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// Scenario is a scripted conversation with one integration: which bank, which
// calls to make, and (next to it on disk) the bank's recorded responses and the
// outcomes the SDK is expected to produce.
//
//	<dir>/scenario.json      this struct
//	<dir>/exchanges/*.json   recorded HTTP exchanges, consumed in file order
//	<dir>/session.json       optional starting session (for refresh/data scenarios)
//	<dir>/golden.json        expected outcomes, written with -obsdktest.update
//
// Scenarios are plain JSON so you can write or edit them by hand, for example
// to cover an error the sandbox can't produce.
type Scenario struct {
	Dir         string         `json:"-"`
	Description string         `json:"description,omitempty"`
	Config      ScenarioConfig `json:"config"`
	Calls       []Call         `json:"calls"`
}

// ScenarioConfig holds everything needed to build the client under test.
type ScenarioConfig struct {
	Bank    string `json:"bank"`
	Country string `json:"country"`
	Segment string `json:"segment,omitempty"`
	Env     string `json:"env"`

	// Now freezes the clock. Required: expiry maths must be reproducible.
	Now time.Time `json:"now"`

	RedirectURL string            `json:"redirect_url,omitempty"` // default https://app.example/callback
	Extra       map[string]string `json:"extra,omitempty"`

	// IDs lists, per purpose ("state", "request"), the identifiers the client
	// generated while recording. Replay hands them out in order, so OAuth state
	// values match the recorded callbacks. Past the end, "<purpose>-<n>" is used.
	IDs map[string][]string `json:"ids,omitempty"`

	// Matching tunes the replayer.
	IgnoreQuery []string `json:"ignore_query,omitempty"`
	MatchBody   bool     `json:"match_body,omitempty"`
	RepeatLast  bool     `json:"repeat_last,omitempty"`
}

// Call is one step of a scenario. Op is one of: connect, resume, accounts,
// balances, transactions, refresh, disconnect, auth_methods.
//
// resume uses the state of the previous step automatically.
type Call struct {
	Op   string `json:"op"`
	Note string `json:"note,omitempty"`

	// connect
	Method       string   `json:"method,omitempty"`
	Language     string   `json:"language,omitempty"`
	RedirectURL  string   `json:"redirect_url,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	ValidityDays int      `json:"validity_days,omitempty"`

	// connect, resume
	Callback string            `json:"callback,omitempty"`
	Values   map[string]string `json:"values,omitempty"`

	// balances, transactions
	Account  string   `json:"account,omitempty"`
	From     string   `json:"from,omitempty"` // RFC 3339 or 2006-01-02
	To       string   `json:"to,omitempty"`
	Status   []string `json:"status,omitempty"`
	PageSize int      `json:"page_size,omitempty"`
	Cursor   string   `json:"cursor,omitempty"`

	// initiate_payment
	Payment *PaymentCall `json:"payment,omitempty"`

	// payment_status, cancel_payment: Payment.Ref; empty means the last
	// payment the run saw.
	Ref string `json:"ref,omitempty"`

	// PSU context, for any call that takes one.
	PSUIP        string `json:"psu_ip,omitempty"`
	PSUUserAgent string `json:"psu_user_agent,omitempty"`
	PSUID        string `json:"psu_id,omitempty"`
}

// PaymentCall is the bank-facing part of an obsdk.PaymentRequest (method,
// language, redirect URL, values and PSU come from the Call).
type PaymentCall struct {
	Type           obsdk.PaymentType    `json:"type"`
	Debtor         *obsdk.PaymentDebtor `json:"debtor,omitempty"`
	Transfers      []obsdk.Transfer     `json:"transfers"`
	ExecutionDate  string               `json:"execution_date,omitempty"`
	ChargeBearer   string               `json:"charge_bearer,omitempty"`
	Context        string               `json:"context,omitempty"`
	IdempotencyKey string               `json:"idempotency_key,omitempty"`
	WithSession    bool                 `json:"with_session,omitempty"` // pass the run's session as PaymentRequest.Session
}

// LoadScenario reads <dir>/scenario.json.
func LoadScenario(dir string) (*Scenario, error) {
	b, err := os.ReadFile(filepath.Join(dir, "scenario.json"))
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("obsdktest: %s: %w", filepath.Join(dir, "scenario.json"), err)
	}
	s.Dir = dir
	if s.Config.Bank == "" || s.Config.Country == "" || s.Config.Env == "" {
		return nil, fmt.Errorf("obsdktest: %s: config.bank, config.country and config.env are required", dir)
	}
	if s.Config.Now.IsZero() {
		return nil, fmt.Errorf("obsdktest: %s: config.now is required (replays need a frozen clock)", dir)
	}
	return &s, nil
}

// Save writes scenario.json into s.Dir.
func (s *Scenario) Save() error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, "scenario.json"), append(b, '\n'), 0o644)
}

// ExchangesDir is where the scenario's recorded exchanges live.
func (s *Scenario) ExchangesDir() string { return filepath.Join(s.Dir, "exchanges") }

// FindScenarios returns every directory under root that holds a scenario.json,
// so a bank package can run all of its fixtures with one loop.
func FindScenarios(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == root {
				return filepath.SkipAll
			}
			return err
		}
		if !d.IsDir() && d.Name() == "scenario.json" {
			out = append(out, filepath.Dir(p))
		}
		return nil
	})
	return out, err
}
