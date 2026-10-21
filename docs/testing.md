# Testing

Three layers, from cheapest to most real. Only the first two run in CI; the third exists to make
development against real banks pleasant.

| Layer | Runs with | Needs |
|---|---|---|
| Unit tests | `go test ./...` | nothing |
| Scenario replays | `go test ./...` | nothing (recorded bank responses) |
| Live runs | `obdev`, `go test -tags live ./live` | sandbox credentials, a person to log in |

## Why this works: what is injectable

The client never reaches for the outside world on its own.

| Seam | Field | Default | Tests use |
|---|---|---|---|
| HTTP | `Config.HTTPClient` (`obsdk.HTTPDoer`, one `Do` method) | `*http.Client`, 30s | a stub, or a client whose transport replays fixtures |
| Clock | `Config.Now` | `time.Now` | a frozen time |
| Identifiers | `Config.NewID(purpose)` | random UUIDs | a fixed sequence, so OAuth `state` matches recorded callbacks |

`Config` is never serialized, so injecting these changes nothing about sessions or resumable state.

## Layer 1: unit tests

Pure helpers (`expiry`, `parseTPP`, `apiErr`, `toTransaction`, `parseStatementArchive`, ...) are tested directly
in the bank package (`banks/swedbank/unit_test.go`). For a method that makes one call, a hand-written doer is
enough:

```go
type doerFunc func(*http.Request) (*http.Response, error)
func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

c, _ := obsdk.New(target, obsdk.Config{HTTPClient: doerFunc(func(r *http.Request) (*http.Response, error) {
    // assert on r, return a canned response or an error
}), Now: func() time.Time { return frozen }, ...})
```

## Layer 2: scenarios (recorded request/response examples)

A scenario is a directory:

```
banks/swedbank/testdata/se-data/
  scenario.json     which bank/country/env, frozen time, recorded ids, and the list of calls
  exchanges/        one JSON file per HTTP exchange, consumed in file order
  session.json      optional: start from a stored session instead of logging in
  golden.json       what the SDK is expected to return for each call
```

`scenario.json` (abridged):

```json
{ "config": { "bank": "swedbank", "country": "SE", "env": "sandbox", "now": "2026-10-11T12:00:00Z",
              "ids": { "state": ["state-1"] } },
  "calls": [ {"op": "connect", "psu_ip": "203.0.113.7"},
             {"op": "resume", "callback": "https://app.example/cb?access_code=...&state=state-1"},
             {"op": "accounts"} ] }
```

Ops: `connect`, `resume` (uses the previous step's state), `accounts`, `balances`, `transactions`,
`refresh`, `disconnect`, `auth_methods`, `initiate_payment` (request under `payment`;
`"with_session": true` passes the run's session), `payment_status` and `cancel_payment` (these act on
the last payment the run saw, unless `ref` is set; the recorder stores the `ref` it was given, since refs
hold no tokens). Secrets that travel under two names (Nordea's `?auth_code=` comes back as the form field
`code=`) get the same placeholder label, so a replayed request matches what was recorded. The recorder pseudonymizes payment account numbers (UK sort code and account numbers stay 14 digits, so they still validate), and
replaces an account number it has already pseudonymized wherever it shows up again in free text (Swedbank
echoes the payee's IBAN in `psuMessage`). Numbers it never saw under an account key are not caught, so
still skim exchanges before committing.

An exchange file:

```json
{ "note": "optional comment",
  "request":  { "method": "GET", "path": "/sandbox/v5/accounts", "query": {"bic": ["SANDSESS"]} },
  "response": { "status": 200, "headers": {"Content-Type": "application/json"}, "body": { ... } } }
```

Matching uses method, path and query (not host, not headers). The same request repeated (polling) is answered
by the next file in order. Bodies may be `body` (JSON), `body_text` or `body_base64` (ZIP statements).
Every exchange must be used, otherwise the test fails: a leftover means the SDK stopped making a call.

Run them in a bank package:

```go
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }
```

The outcomes are compared with `golden.json`. After an intended change, regenerate and **review the diff**:

```
go test ./banks/swedbank -obsdktest.update
```

Opaque `Step.State` is masked as `<state>`; everything else (normalised model, `Raw`, sessions, error kinds) is
compared, so the golden files double as a readable contract of what the SDK returns for each bank.

### Writing a scenario by hand

Copy a directory, edit the exchanges, run with `-obsdktest.update`. This is the way to cover what a sandbox
can't produce: expired tokens, 429s, odd payloads, a consent that expired.

### Recording a scenario from a real sandbox

```
export OBSDK_BANK=swedbank OBSDK_COUNTRY=SE OBSDK_ENV=sandbox
export OBSDK_CLIENT_ID=... OBSDK_CLIENT_SECRET=... OBSDK_REDIRECT_URL=https://localhost/cb
export OBSDK_SESSION_FILE=$HOME/.obsdk/swedbank-se.json

go run ./cmd/obdev -record banks/swedbank/testdata/se-redirect connect
go run ./cmd/obdev -record banks/swedbank/testdata/se-redirect accounts
go run ./cmd/obdev -record banks/swedbank/testdata/se-redirect transactions ACCOUNT_ID -from 2026-01-01
go test ./banks/swedbank -obsdktest.update
```

Several invocations append to the same scenario. Redaction:

- your client id and secret become `REDACTED:client_id` / `REDACTED:client_secret`;
- tokens, codes and similar become `REDACTED:<key>:<digest>`, in headers, queries, JSON and
  form-encoded bodies; the digest keeps different values distinguishable
  (so a rotated refresh token doesn't look like the old one);
- names, IBANs and payment references become stable pseudonyms (IBANs keep their country code), and so
  do e-mail addresses and phone numbers in alias objects such as bunq's `{"type": "EMAIL", "value": …}`;
- account numbers used as ids (ABN AMRO puts the IBAN in every path and passes it as the account id) get the same
  pseudonym in paths, recorded call arguments and the start session, also across separate obdev invocations;
- the PSU IP becomes `203.0.113.7`; `base_url` is dropped; the session file is never copied. A start
  session (`session.json`) keeps its shape, but its tokens and any `Meta` value whose key names a token
  or secret are masked.

**No automatic redaction is complete.** Read `exchanges/` before committing: look for account numbers in free text,
merchant names you consider private, and bank-specific secret fields. Add them with a custom `Redactor`
(`obsdktest.NewScenarioRecorder(dir, cfg, red)`).

### Synthetic scenarios

`banks/swedbank/testdata` currently holds scenarios generated by `go test -tags gen ./banks/swedbank`, which
drives the client against the in-repo fake server and records it. They are **not real Swedbank traffic**: they
pin down what the SDK does with the behaviour described in the docs. Replace them with real recordings as soon as
you can, and keep synthetic ones for failure cases.

## Layer 3: live runs (development only)

Nothing in `go test ./...` depends on these.

- `obdev` (see `cmd/obdev`) logs in interactively, calls the API and prints results. `obdev replay <dir>` runs a
  recorded scenario offline.
- `go test -tags live ./live -v` is a smoke test (accounts, balances, a month of transactions, refresh) that reuses
  the session saved by `obdev connect`.
- Production requires `OBSDK_ENV=production` **and** `OBSDK_ALLOW_PRODUCTION=1`.

Environment variables: `OBSDK_BANK`, `OBSDK_COUNTRY`, `OBSDK_SEGMENT`, `OBSDK_ENV`, `OBSDK_ALLOW_PRODUCTION`,
`OBSDK_CLIENT_ID`, `OBSDK_CLIENT_SECRET`, `OBSDK_REDIRECT_URL`, `OBSDK_EXTRA` (`k=v,k=v`), `OBSDK_SESSION_FILE`,
`OBSDK_PSU_IP`, `OBSDK_PSU_USER_AGENT`, for mTLS `OBSDK_TLS_CERT` / `OBSDK_TLS_KEY` (PEM or DER) and
`OBSDK_TLS_CA` (extra server roots), and for request signing `OBSDK_SEAL_KEY` / `OBSDK_SEAL_KID` /
`OBSDK_SEAL_CERT`. Each bank's `banks/<bank>/sandbox.env.example` lists the ones it needs; copy it to
`sandbox.env` (gitignored) and load it with `set -a; . banks/<bank>/sandbox.env; set +a`.

The session file holds tokens (written with mode 0600). Keep it out of the repository.
