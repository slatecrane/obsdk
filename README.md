# ob-sdk

A stateless Go client library for European open banking APIs (account information and payments).
One small interface over Berlin Group, STET, UK, Polish API and bank-specific variants,
so applications don't write per-bank code.

> **Status: early.** Integrations are written from the banks' published specs and checked against
> their sandboxes; production is unverified everywhere. See [docs/banks.md](docs/banks.md) for the
> banks covered and how far each is verified.

## Usage

```go
import (
    obsdk "github.com/slatecrane/obsdk"
    _ "github.com/slatecrane/obsdk/banks/all" // or import only the banks you need
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

Payments use the same steps. Each bank describes the fields it needs per payment type, so forms can
be built from data:

```go
spec, _ := c.Info().PaymentSpec("SE", obsdk.Personal, obsdk.PaymentDomestic) // fields, limits, schemes
step, err = c.InitiatePayment(ctx, obsdk.PaymentRequest{Type: obsdk.PaymentDomestic, PSU: psu, Transfers: transfers})
// ... drive steps as above; step.Payment.Ref reads the status later
```

See [docs/payments.md](docs/payments.md).

A runnable version is in [examples/swedbank](examples/swedbank/main.go).

### Example: reading accounts end to end

Connecting a user's account in production, from client setup to transactions. Values such as
`clientID`, the user's IP or the callback URL are placeholders; error handling is left out.

```go
import (
    "context"
    "crypto"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "net/http"
    "time"

    obsdk "github.com/slatecrane/obsdk"
    _ "github.com/slatecrane/obsdk/banks/all"
)

// 1. Initialize. The QWAC goes into the HTTP client (mTLS), the QSealC into Config.Seal.
//    Neither ever ends up in a session. The key only has to be a crypto.Signer, so an
//    HSM/KMS-backed key works too.
qwac, err := tls.LoadX509KeyPair("qwac.crt", "qwac.key")
httpClient := &http.Client{
    Timeout:   30 * time.Second,
    Transport: &http.Transport{TLSClientConfig: &tls.Config{
        Certificates: []tls.Certificate{qwac},
        MinVersion:   tls.VersionTLS12,
    }},
}
var sealCert *x509.Certificate // parsed QSealC certificate
var sealKey crypto.Signer      // its private key: *rsa.PrivateKey, *ecdsa.PrivateKey or a KMS signer

cfg := obsdk.Config{
    Env: obsdk.Production,
    Credentials: obsdk.Credentials{
        ClientID:     clientID,
        ClientSecret: obsdk.Secret(clientSecret),
        RedirectURL:  "https://app.example.com/bank/callback",
    },
    HTTPClient: httpClient,
    Seal:       &obsdk.Seal{Key: sealKey, Certificate: sealCert, KeyID: kid},
}
// New checks the config against the bank's requirements (obsdk.Lookup lists them)
// and returns an *obsdk.ConfigError naming anything missing.
c, err := obsdk.New(obsdk.Target{Bank: "revolut", Country: "GB"}, cfg)

// 2. Authorize. Connect creates the consent and returns the first step.
ctx := context.Background()
psu := obsdk.PSUContext{IP: "10.10.10.10", UserAgent: "User-Agent"} // the end user's device
step, err := c.Connect(ctx, obsdk.ConnectRequest{PSU: psu})

// 3. Redirect. Send the user to the bank to log in and approve the consent.
//    step.State is opaque and contains secrets: keep it server-side until the callback.
//    (Some banks start with StepInputRequired or StepWait instead; see Usage above.)
redirectURL := step.Redirect.URL // e.g. respond with 302 Location: redirectURL

// 4. Get the token. The bank sends the user back to RedirectURL; Resume with that
//    callback exchanges the code for tokens and returns the session.
callback := "https://app.example.com/bank/callback?code=abc123&state=xyz"
step, err = c.Resume(ctx, step.State, obsdk.StepInput{Callback: callback})
// Some banks need more steps after the callback (a second consent, app approval):
// keep calling Resume until step.Kind == obsdk.StepDone.
sess := step.Session // store it encrypted: it holds the tokens and consents

// 5. Fetch accounts. Later, possibly in another process, rebuild the client with
//    obsdk.Restore(sess, cfg).
opts := obsdk.CallOptions{PSU: &psu} // omit PSU for unattended background syncs
accounts, err := c.Accounts(ctx, sess, opts)
if errors.Is(err, obsdk.ErrAccessExpired) {
    sess, err = c.Refresh(ctx, sess) // ErrReauthRequired here means: run Connect again
    accounts, err = c.Accounts(ctx, sess, opts)
}

// 6. Balances and transactions per account. Account.ID is valid only inside this
//    session; use Account.StableID to match accounts across reconnects.
for _, a := range accounts.Data {
    balances, err := c.Balances(ctx, sess, a.ID, opts)
    for _, b := range balances.Data {
        fmt.Println(a.Name, b.Kind, b.Amount.Amount, b.Amount.Currency)
    }

    q := obsdk.TxQuery{AccountID: a.ID, From: time.Now().AddDate(0, 0, -90), Options: opts}
    for {
        res, err := c.Transactions(ctx, sess, q)
        if err != nil { break }
        if res.Step != nil { break } // the bank wants the user to approve older history: drive it like Connect
        for _, t := range res.Transactions {
            fmt.Println(t.BookingDate, t.Direction, t.Amount.Amount, t.Counterparty.Name)
        }
        if res.NextCursor == "" { break }
        q.Cursor = res.NextCursor // opaque; page sizes differ per bank
    }
}
```

Persist every non-nil `Session` the SDK hands back (`Step.Session`, `Result.Session`,
`TxResult.Session`, `FlowError.Session`): banks rotate tokens and consent state along the way.

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

## New integrations

Missing a bank? There are two ways to get it added.

### Build it yourself (preferred)

Pull requests with new integrations are the fastest route and very welcome.

1. Create `banks/<bank>` and register an `obsdk.Integration` in `init` with an honest `Info`
   (variants with maturity, capabilities, requirements, limits, quirk notes).
2. Implement `obsdk.Client`. Prefer small per-bank code on top of shared helpers over copying another bank.
3. Add unit tests for pure functions and recorded scenarios for every flow (see [docs/testing.md](docs/testing.md)).
4. Write a `docs/<bank>.md` listing what you verified and what you assumed.
5. Open a pull request.

Registration is strict: two integrations may not serve the same bank, country, segment and environment.

The full walkthrough (portal setup, the `obdev` loop against a sandbox, recording, common sandbox
errors) is in [docs/new-integration.md](docs/new-integration.md). If you get stuck, open a draft PR or
an issue and ask.

### Request one

[Open an issue](https://github.com/slatecrane/obsdk/issues/new) with:

- the bank name and the countries you need;
- a link to the bank's open banking developer portal or API documentation;
- anything else that helps: the standard it follows (Berlin Group, STET, UK, Polish API, …), whether
  it has a public sandbox, the services you need (accounts, balances, transactions, payments), and
  any quirks you already know about.

### Help us test in production

Integrations are developed against sandboxes, so production behavior is often unverified (each
bank's `docs/<bank>.md` says what has been checked). If you have production access to a bank we
support (a QWAC/QSealC and a registration with the bank), we'd love your help confirming it works,
and we're happy to support you in setting things up: open an issue and we'll work through it together.

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

Bulk payments and standing orders (the payment model has room for both), more banks, request signing helpers (the `Seal` config exists; Swedbank's sandbox
doesn't need it), optional automatic refresh, dynamic client registration.
