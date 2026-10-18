# CLAUDE.md

Stateless Go client library (`github.com/slatecrane/obsdk`) for European open banking: account
information (AIS) and payments (PIS) behind one interface, over Berlin Group, UK OBIE and bank-specific
APIs. Go 1.22, standard library only (no dependencies; keep it that way).

Scope: EU/EEA first, UK only where it comes cheaply, nothing else.

## Commands

```sh
gofmt -l .                  # CI fails on any output
go vet ./...
go test -race ./...         # offline: unit tests + recorded scenario replays, no credentials
go test ./banks/<bank> -obsdktest.update   # regenerate golden.json after an intended change; review the diff
go test ./banks/<bank> -run TestScenarios/<scenario>

# against a real sandbox (development only, needs banks/<bank>/sandbox.env)
set -a; . banks/<bank>/sandbox.env; set +a
go run ./cmd/obdev list | connect | accounts | balances ID | transactions ID -from 2026-09-01 \
                   | refresh | disconnect | payment-spec | pay | payment-status | cancel-payment | auth-methods | jwks
go run ./cmd/obdev -record banks/<bank>/testdata/live-<country>-<name> <command>   # record a scenario
go run ./cmd/obdev replay banks/<bank>/testdata/<scenario>
go test -tags live ./live -v          # smoke test using the session saved by obdev connect
go test -tags gen ./banks/swedbank    # regenerates Swedbank's synthetic scenarios from its fake server
```

Production runs need `OBSDK_ENV=production` and `OBSDK_ALLOW_PRODUCTION=1`. All `OBSDK_*` variables are
defined in [obsdktest/live.go](obsdktest/live.go).

## Architecture

- **Root package (`obsdk`)** is the public API: `Client` interface ([client.go](client.go)), `Step`/`StepInput`
  ([step.go](step.go)), `Session` ([session.go](session.go)), normalized model ([model.go](model.go),
  [types.go](types.go)), payments and `PaymentSpec` ([payment.go](payment.go), [schemes.go](schemes.go)),
  typed errors ([errors.go](errors.go)), registry and discovery ([registry.go](registry.go)).
- **Registry, like `database/sql` drivers.** Each `banks/<bank>` package calls `obsdk.Register` in `init`
  with an `Integration{ID, Info, Factory}`. `banks/all` imports every bank. `New(Target, Config)` resolves
  (bank, country, segment, env) to exactly one integration; registration panics on overlaps.
  `Restore(session, cfg)` rebuilds the client from `Session.Integration`.
- **Stateless clients.** A client holds config only. All mutable state is in serializable values the caller
  stores: `Session` (tokens, consents, `Meta`) and `Step.State` (opaque, built with
  [internal/flowstate](internal/flowstate/flowstate.go); not encrypted, contains secrets).
  Credentials, certificates and keys (QWAC via `Config.HTTPClient`, QSealC via `Config.Seal` /
  `crypto.Signer`) must never end up in a session or state.
- **Auth and payment approval are step state machines.** `Connect` / `InitiatePayment` / `CancelPayment`
  return a `Step` (redirect, input, display, wait, done); `Resume(state, input)` continues it. Each bank's
  `flow.go` holds a serializable flow struct.
- **Shared internals:** [internal/callback](internal/callback/callback.go) parses redirect callbacks (query,
  fragment, JSON, ...); [internal/bgstatus](internal/bgstatus/bgstatus.go) maps Berlin Group payment status
  codes. Request signing is still per bank (`jwt.go` in revolut/hsbc; `http.go` in ing, rabobank,
  nordea, bunq).
- **Bank package layout:** `<bank>.go` (registration, `Info`, client construction), `flow.go`, `ais.go`,
  `payment.go`, `http.go` (request helper + error mapping), tests, `testdata/` scenarios,
  `sandbox.env.example`. Swedbank also splits out `consent.go`, `sca.go`, `token.go`, `statement.go`.
  bunq has `sandboxsetup/` to create sandbox users via its API.
- **[obsdktest](obsdktest/)** is the test kit: scenario recorder (with redaction), replayer, golden-file
  runner (`obsdktest.PlayAll(t, "testdata")`), live-env helpers. [cmd/obdev](cmd/obdev/main.go) is the
  CLI that drives a real sandbox with the same client and records scenarios.

## Rules when writing integration code

- **Honest `Info`.** One `Variant` per country/segment/env with a `Maturity`. Sandbox starts
  `experimental`, becomes `sandbox_verified` (with `VerifiedOn` date) only after the obdev loop passed
  against the real sandbox. Production stays `unverified` — we can't test it (no QWAC/QSealC), but still
  implement it from the bank's docs.
- **Hand out the session as soon as it exists:** set `Step.Session` on every step after login; on failure
  after that, return `*obsdk.FlowError{Session, Err}`. Call `Session.Touch(now)` on every change.
- **Data:** populate every normalized field the bank sends, leave the rest empty (empty fields per bank are
  expected), keep the original in `Raw`. Amounts are exact decimal strings, signed, `Direction` always set.
- **Pagination is pass-through:** return the bank's continuation as an opaque `TxPage.NextCursor`, accept
  it as `TxQuery.Cursor`; never infer the last page from item counts.
- **Errors:** map to the typed errors in `errors.go` using HTTP status, the bank's code *and* the running
  operation (`ErrAccessExpired`, `ErrReauthRequired`, `ErrRateLimited`, `ErrAuthFailed`, ...).
- **Flow structs round-trip through JSON:** empty maps come back `nil`, so initialize before writing.
- **Injectables only:** use `Config.HTTPClient`, `Config.Now`, `Config.NewID` — never `http.DefaultClient`,
  `time.Now` or random ids directly, or replays break.
- When a bank's own links/behaviour are wrong, work around it in one place with a comment, and record it
  in `docs/<bank>.md`.

## Testing

Three layers ([docs/testing.md](docs/testing.md)): unit tests (pure helpers, stub `HTTPDoer`, fake servers),
scenario replays (`testdata/<scenario>/{scenario.json, exchanges/, session.json?, golden.json}`; matching is
on method + path + query, every exchange must be consumed), and live runs (never in CI).

Recording pitfalls: don't pipe obdev into `head` (scenario.json never gets saved); delete partial scenarios
from failed runs; remove duplicated exchanges caused by per-process caches (e.g. ING's app token); review
every file in `exchanges/` for personal data before committing — redaction is not complete.

## Docs to keep in sync

- [docs/banks.md](docs/banks.md) — one row per registered bank; `banks/all` has a test that fails if a bank is
  missing. Don't list banks in the README.
- `docs/<bank>.md` — flows, quirks, what was verified against the sandbox (dated) and what is assumed.
- [docs/new-integration.md](docs/new-integration.md) — full walkthrough for adding a bank, including a table
  of common sandbox errors; extend it when you hit a new one.
- [docs/payments.md](docs/payments.md) — payment model and per-bank payment coverage.

## Secrets and git hygiene

- Sandbox credentials live in `banks/<bank>/sandbox.env` (gitignored); commit only `sandbox.env.example`
  with every variable empty and a note on where it comes from. Keys/certs (`*.pem`, `*.key`, `*.p12`,
  `*.der`, `*.csr`, `banks/*/cert/`) and session files (`*.session.json`) are ignored — check before every
  push that nothing like that is staged. Public roots embedded in code use `.crt`.
- `main` is protected: work on a branch, one bank integration per branch/PR, with its docs updated.
