# ob-sdk

A stateless Go client library for European open banking APIs (AISP first, PISP later).
One small interface over Berlin Group, STET, UK, Polish API and bank-specific variants,
so applications don't write per-bank code.

> **Status: early.** The core and a Swedbank integration exist. Swedbank was written from its
> published specs; its Swedish sandbox flow (decoupled login, consents, accounts, balances,
> transactions) has been run against the real sandbox. Redirect login, the Baltics, extended history
> and production are still unverified. See [docs/swedbank.md](docs/swedbank.md).

## Usage

```go
import (
    obsdk "github.com/ob-sdk/ob-sdk"
    _ "github.com/ob-sdk/ob-sdk/banks/all" // or import only the banks you need
)

c, err := obsdk.New(obsdk.Target{Bank: "swedbank", Country: "SE"}, obsdk.Config{
    Env: obsdk.Sandbox, // always explicit
    Credentials: obsdk.Credentials{ClientID: id, ClientSecret: secret, RedirectURL: cb},
})

// Authorization is a resumable sequence of steps the caller acts on.
step, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: obsdk.PSUContext{IP: ip, UserAgent: ua}})
for step.Kind != obsdk.StepDone {
    switch step.Kind {
    case obsdk.StepRedirect:      // send the user to step.Redirect.URL; pass the callback back
    case obsdk.StepInputRequired: // ask for step.Fields
    case obsdk.StepWait:          // show step.Challenge, wait step.WaitFor
    }
    step, err = c.Resume(ctx, step.State, input)
}
session := step.Session // persist this (encrypted); it is all the SDK needs later

accounts, err := c.Accounts(ctx, session, obsdk.CallOptions{})
txs, err := c.Transactions(ctx, session, obsdk.TxQuery{AccountID: accounts.Data[0].ID, From: from})
```

A runnable version is in [examples/swedbank](examples/swedbank/main.go).

## Principles

- **Stateless.** A client holds configuration only. Sessions and step states are plain, versioned,
  serializable values that you store; any instance can continue them.
- **Thin.** No servers, schedulers, storage or retry policy. You decide how to wait, poll and persist.
- **Config is not state.** Credentials, certificates (QWAC for mTLS via your `http.Client`, QSealC via
  `crypto.Signer`, so keys may live in an HSM/KMS) never enter a session.
- **Normalized, with the raw response.** Amounts are exact decimals with consistent sign and direction;
  every object keeps `Raw` for debugging.
- **Honest errors.** `errors.Is` against `ErrAccessExpired` (refresh), `ErrReauthRequired` (user must
  log in again), `ErrRateLimited`, `ErrAuthFailed`. Classification uses both bank codes and the
  operation that was running.
- **Discoverable.** `obsdk.List` / `obsdk.Lookup` describe banks, countries, segments, environments,
  capabilities, required configuration and how well each variant has been verified.

## Layout

| Path | Purpose |
|---|---|
| `*.go` | public API: types, sessions, steps, errors, registry |
| `banks/<bank>` | one package per bank; registers itself in `init` |
| `banks/all` | imports every bank |
| `internal/callback` | parses redirect callbacks (query, fragment, JSON, urlencoded JSON) |
| `internal/flowstate` | versioned opaque encoding of resumable state |
| `obsdktest` | test kit: record/replay of bank traffic, scenarios, redaction, live helpers |
| `cmd/obdev` | development tool: talk to a real sandbox, record scenarios, replay them |
| `live/` | tests against real banks (`-tags live`, development only) |
| `examples/` | runnable references |
| `docs/` | bank notes and design decisions |

## Adding a bank

1. Create `banks/<bank>` and register an `obsdk.Integration` in `init` with an honest `Info`
   (variants with maturity, capabilities, requirements, limits, quirk notes).
2. Implement `obsdk.Client`. Prefer small per-bank code on top of shared helpers over copying another bank.
3. Add unit tests for pure functions and recorded scenarios for every flow (see [docs/testing.md](docs/testing.md)).
4. Write a `docs/<bank>.md` listing what you verified and what you assumed.

Registration is strict: two integrations may not serve the same bank, country, segment and environment.

The full walkthrough (portal setup, the `obdev` loop against a sandbox, recording, common sandbox
errors) is in [docs/new-integration.md](docs/new-integration.md).

## Testing

`go test ./...` never touches the network or needs credentials. Tests come in three layers:

- **Unit tests** for pure functions, and for methods through a stub `obsdk.HTTPDoer`
  (`Config.HTTPClient`, `Config.Now` and `Config.NewID` are injectable).
- **Scenario replays**: each bank has `testdata/<scenario>/` with a script of calls, the bank's recorded
  responses and the expected outcomes. `obsdktest.PlayAll(t, "testdata")` runs them all.
- **Live runs** against a real sandbox, for development only: `obdev` and `go test -tags live ./live`.

Record a scenario from a real sandbox with `obdev -record <dir> ...`; secrets and personal data are
redacted on the way to disk. Details in [docs/testing.md](docs/testing.md).

## Not yet

PISP (payments), more banks, request signing helpers (the `Seal` config exists; Swedbank's sandbox
doesn't need it), optional automatic refresh, dynamic client registration.
