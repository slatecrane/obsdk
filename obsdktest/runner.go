package obsdktest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// Outcome is what one Call produced, reduced to stable, comparable data.
// Opaque Step.State values are masked; raw bodies are left out of page-level
// fields (transactions keep their own Raw so normalisation stays visible).
type Outcome struct {
	Op    string        `json:"op"`
	Note  string        `json:"note,omitempty"`
	Error *ErrorOutcome `json:"error,omitempty"`

	Step         *obsdk.Step        `json:"step,omitempty"`
	Accounts     []obsdk.Account    `json:"accounts,omitempty"`
	Balances     []obsdk.Balance    `json:"balances,omitempty"`
	Transactions *obsdk.TxPage      `json:"transactions,omitempty"`
	Session      *obsdk.Session     `json:"session,omitempty"`
	Disconnect   *DisconnectOutcome `json:"disconnect,omitempty"`
	AuthMethods  []obsdk.AuthMethod `json:"auth_methods,omitempty"`
}

// DisconnectOutcome mirrors obsdk.DisconnectResult.
type DisconnectOutcome struct {
	Closed []string          `json:"closed,omitempty"`
	Failed map[string]string `json:"failed,omitempty"`
}

// ErrorOutcome names the sentinel errors an error matches (errors.Is) and its message.
type ErrorOutcome struct {
	Is      []string `json:"is,omitempty"`
	Message string   `json:"message"`
}

var sentinels = []struct {
	name string
	err  error
}{
	{"access_expired", obsdk.ErrAccessExpired},
	{"reauth_required", obsdk.ErrReauthRequired},
	{"auth_failed", obsdk.ErrAuthFailed},
	{"rate_limited", obsdk.ErrRateLimited},
	{"refresh_failed", obsdk.ErrRefreshFailed},
	{"unsupported", obsdk.ErrUnsupported},
	{"invalid_config", obsdk.ErrInvalidConfig},
	{"invalid_request", obsdk.ErrInvalidRequest},
	{"unknown_bank", obsdk.ErrUnknownBank},
	{"unsupported_target", obsdk.ErrUnsupportedTarget},
	{"ambiguous_target", obsdk.ErrAmbiguousTarget},
}

func errorOutcome(err error) *ErrorOutcome {
	e := &ErrorOutcome{Message: err.Error()}
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			e.Is = append(e.Is, s.name)
		}
	}
	return e
}

// Runner executes Calls against a client, carrying the session and the
// resumable state from one call to the next, like an application would.
type Runner struct {
	Client  obsdk.Client
	Session *obsdk.Session
	state   string
}

// Do runs one call. It never returns an error: failures are part of the Outcome.
func (r *Runner) Do(ctx context.Context, c Call) Outcome {
	out := Outcome{Op: c.Op, Note: c.Note}
	fail := func(err error) Outcome { out.Error = errorOutcome(err); return out }

	psu := obsdk.PSUContext{IP: c.PSUIP, UserAgent: c.PSUUserAgent, ID: c.PSUID}
	opts := obsdk.CallOptions{}
	if psu != (obsdk.PSUContext{}) {
		opts.PSU = &psu
	}

	switch c.Op {
	case "connect":
		req := obsdk.ConnectRequest{Method: c.Method, Language: c.Language, RedirectURL: c.RedirectURL,
			Values: c.Values, ConsentValidityDays: c.ValidityDays}
		if opts.PSU != nil {
			req.PSU = psu
		}
		for _, cp := range c.Capabilities {
			req.Capabilities = append(req.Capabilities, obsdk.Capability(cp))
		}
		step, err := r.Client.Connect(ctx, req)
		if err != nil {
			return fail(err)
		}
		r.takeStep(step)
		out.Step = maskStep(step)
	case "resume":
		if r.state == "" {
			return fail(fmt.Errorf("obsdktest: resume without a pending step"))
		}
		step, err := r.Client.Resume(ctx, r.state, obsdk.StepInput{Callback: c.Callback, Values: c.Values})
		if err != nil {
			return fail(err)
		}
		r.takeStep(step)
		out.Step = maskStep(step)
	case "accounts":
		res, err := r.Client.Accounts(ctx, r.Session, opts)
		if err != nil {
			return fail(err)
		}
		r.adopt(res.Session)
		out.Accounts, out.Session = res.Data, res.Session
	case "balances":
		res, err := r.Client.Balances(ctx, r.Session, c.Account, opts)
		if err != nil {
			return fail(err)
		}
		r.adopt(res.Session)
		out.Balances, out.Session = res.Data, res.Session
	case "transactions":
		q := obsdk.TxQuery{AccountID: c.Account, PageSize: c.PageSize, Cursor: c.Cursor, Options: opts}
		var err error
		if q.From, err = parseTime(c.From); err != nil {
			return fail(err)
		}
		if q.To, err = parseTime(c.To); err != nil {
			return fail(err)
		}
		for _, s := range c.Status {
			q.Status = append(q.Status, obsdk.TxStatus(s))
		}
		res, err := r.Client.Transactions(ctx, r.Session, q)
		if err != nil {
			return fail(err)
		}
		r.adopt(res.Session)
		out.Session = res.Session
		if res.Step != nil {
			r.state = res.Step.State
			out.Step = maskStep(res.Step)
		} else {
			page := res.TxPage
			page.Raw = nil
			out.Transactions = &page
		}
	case "refresh":
		s, err := r.Client.Refresh(ctx, r.Session)
		if err != nil {
			return fail(err)
		}
		r.adopt(s)
		out.Session = s
	case "disconnect":
		res, err := r.Client.Disconnect(ctx, r.Session)
		if err != nil {
			return fail(err)
		}
		if res.Session != nil {
			r.adopt(res.Session)
		}
		out.Disconnect = &DisconnectOutcome{Closed: res.Closed, Failed: res.Failed}
		out.Session = res.Session
	case "auth_methods":
		l, ok := r.Client.(obsdk.AuthMethodLister)
		if !ok {
			return fail(fmt.Errorf("%w: client does not list auth methods", obsdk.ErrUnsupported))
		}
		ms, err := l.AuthMethods(ctx)
		if err != nil {
			return fail(err)
		}
		out.AuthMethods = ms
	default:
		return fail(fmt.Errorf("obsdktest: unknown op %q", c.Op))
	}
	return out
}

func (r *Runner) adopt(s *obsdk.Session) {
	if s != nil {
		r.Session = s
	}
}

func (r *Runner) takeStep(st *obsdk.Step) {
	r.state = st.State
	if st.Kind == obsdk.StepDone && st.Session != nil {
		r.Session = st.Session
	}
}

func maskStep(st *obsdk.Step) *obsdk.Step {
	c := *st
	if c.State != "" {
		c.State = "<state>"
	}
	c.Raw = nil
	return &c
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: bad time %q", obsdk.ErrInvalidRequest, strings.TrimSpace(s))
	}
	return t, nil
}
