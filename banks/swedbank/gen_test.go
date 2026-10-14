//go:build gen

package swedbank_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/obsdktest"
)

// TestGenerate rebuilds the synthetic scenarios under testdata by driving the
// client against the in-repo fake and recording the traffic with obsdktest.
//
//	go test -tags gen -run TestGenerate ./banks/swedbank
//	go test ./banks/swedbank -obsdktest.update     # then review the diff
//
// These fixtures are NOT real Swedbank traffic: they exercise the SDK's
// handling of the documented behaviour. Replace them with recordings made by
// `obdev -record` as soon as you have sandbox access, and keep the synthetic
// ones for cases the sandbox can't produce.
func TestGenerate(t *testing.T) {
	loginCallback := func(f *fake) func(*obsdk.Step) obsdk.StepInput {
		return func(s *obsdk.Step) obsdk.StepInput {
			if s.Redirect != nil && s.Redirect.URL == "https://bank.example/login?session=1" {
				return obsdk.StepInput{Callback: "https://app.example/cb?access_code=CODE1&state=" + f.lastState}
			}
			return obsdk.StepInput{Callback: "https://app.example/cb?done=1"} // back from consent approval
		}
	}
	noInput := func(*obsdk.Step) obsdk.StepInput { return obsdk.StepInput{} }
	login := func(t *testing.T, c obsdk.Client, f *fake) *obsdk.Session {
		step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu})
		if err != nil {
			t.Fatal(err)
		}
		return drive(t, c, step, loginCallback(f)).Session
	}

	gen(t, "se-connect-redirect", &fake{}, "Redirect login, then redirect approval of the detailed consent.",
		func(t *testing.T, c obsdk.Client, f *fake) { login(t, c, f) })

	gen(t, "se-connect-redirect-consents-valid", &fake{consentsValid: true}, "Redirect login; the bank grants both consents without extra approval.",
		func(t *testing.T, c obsdk.Client, f *fake) { login(t, c, f) })

	gen(t, "se-connect-decoupled-multibank", &fake{multiBank: true, consentsValid: true}, "Decoupled login where the user belongs to several banks and must pick one.",
		func(t *testing.T, c obsdk.Client, f *fake) {
			step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu, Method: "decoupled"})
			if err != nil {
				t.Fatal(err)
			}
			drive(t, c, step, func(s *obsdk.Step) obsdk.StepInput {
				if s.Kind == obsdk.StepInputRequired {
					return obsdk.StepInput{Values: map[string]string{"bank_id": "08999"}}
				}
				return obsdk.StepInput{}
			})
		})

	gen(t, "se-connect-decoupled-consent-approval", &fake{}, "Decoupled login; the detailed consent needs a second app approval.",
		func(t *testing.T, c obsdk.Client, f *fake) {
			step, err := c.Connect(context.Background(), obsdk.ConnectRequest{PSU: psu, Method: "decoupled"})
			if err != nil {
				t.Fatal(err)
			}
			drive(t, c, step, noInput)
		})

	gen(t, "se-data", &fake{consentsValid: true}, "Accounts, balances and two pages of transactions after login.",
		func(t *testing.T, c obsdk.Client, f *fake) {
			ctx := context.Background()
			s := login(t, c, f)
			accs, err := c.Accounts(ctx, s, obsdk.CallOptions{})
			if err != nil {
				t.Fatal(err)
			}
			id := accs.Data[0].ID
			if _, err := c.Balances(ctx, s, id, obsdk.CallOptions{}); err != nil {
				t.Fatal(err)
			}
			from := fixedNow.AddDate(0, 0, -30)
			p1, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: id, From: from, Status: []obsdk.TxStatus{obsdk.TxBooked, obsdk.TxPending}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: id, From: from, Cursor: p1.NextCursor}); err != nil {
				t.Fatal(err)
			}
		})

	gen(t, "se-extended-history", &fake{consentsValid: true}, "Transactions older than 90 days: statement export, a 428 wait, ZIP download.",
		func(t *testing.T, c obsdk.Client, f *fake) {
			ctx := context.Background()
			s := login(t, c, f)
			res, err := c.Transactions(ctx, s, obsdk.TxQuery{AccountID: "acc1", From: fixedNow.AddDate(0, 0, -200), Options: obsdk.CallOptions{PSU: &psu}})
			if err != nil {
				t.Fatal(err)
			}
			drive(t, c, res.Step, noInput)
		})

	refresh := func(setup func(f *fake)) func(*testing.T, obsdk.Client, *fake) {
		return func(t *testing.T, c obsdk.Client, f *fake) {
			s := login(t, c, f)
			setup(f)
			_, _ = c.Refresh(context.Background(), s) // failures are the point of some scenarios
		}
	}
	gen(t, "se-refresh-keeps-refresh-token", &fake{consentsValid: true}, "Refresh response carries no refresh token: the old one stays.",
		refresh(func(f *fake) {}))
	gen(t, "se-refresh-rotates-refresh-token", &fake{consentsValid: true}, "Refresh response carries a new refresh token: it replaces the old one.",
		refresh(func(f *fake) { f.rotateRefresh = true }))
	gen(t, "se-refresh-rejected", &fake{consentsValid: true}, "Bank answers 400: the user must log in again (ErrReauthRequired).",
		refresh(func(f *fake) { f.tokenStatus = 400 }))
	gen(t, "se-refresh-unavailable", &fake{consentsValid: true}, "Bank answers 503: temporary failure, not a reason to log in again.",
		refresh(func(f *fake) { f.tokenStatus = 503 }))
}

// gen records one scenario into testdata/<name>.
func gen(t *testing.T, name string, f *fake, desc string, fn func(*testing.T, obsdk.Client, *fake)) {
	t.Run(name, func(t *testing.T) {
		dir := filepath.Join("testdata", name)
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		f.t = t
		srv := httptest.NewServer(f)
		defer srv.Close()

		red := obsdktest.DefaultRedactor(map[string]string{"cid": "client_id", "shh": "client_secret"})
		rec, err := obsdktest.NewScenarioRecorder(dir, obsdktest.ScenarioConfig{
			Bank: "swedbank", Country: "SE", Env: "sandbox", Now: fixedNow,
			RedirectURL: "https://app.example/cb", Extra: map[string]string{"base_url": srv.URL},
		}, red)
		if err != nil {
			t.Fatal(err)
		}
		rec.Scenario.Description = desc

		var mu sync.Mutex
		n := map[string]int{}
		seq := func(purpose string) string {
			mu.Lock()
			defer mu.Unlock()
			n[purpose]++
			return fmt.Sprintf("%s-%d", purpose, n[purpose])
		}
		c, err := obsdk.New(obsdk.Target{Bank: "swedbank", Country: "SE"}, obsdk.Config{
			Env:         obsdk.Sandbox,
			Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "shh", RedirectURL: "https://app.example/cb"},
			Extra:       map[string]string{"base_url": srv.URL},
			HTTPClient:  &http.Client{Transport: rec.Transport(nil)},
			Now:         func() time.Time { return fixedNow },
			NewID:       rec.NewID(seq),
		})
		if err != nil {
			t.Fatal(err)
		}
		fn(t, rec.Wrap(c), f)
		if err := rec.Save(); err != nil {
			t.Fatal(err)
		}
	})
}
