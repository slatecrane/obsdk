# Adding a bank integration

A practical walkthrough: from an empty developer-portal account to a bank package with recorded
scenarios. It follows the loop used to bring Swedbank up against its real sandbox.

We develop and verify against **sandboxes only**: production can't be tested without valid QWAC and
QSealC certificates. Production variants are still implemented from the bank's docs plus what the
sandbox showed, and registered as `MaturityUnverified`.

Related docs: [testing.md](testing.md) (how scenarios and replays work),
[gotchas.md](gotchas.md) (behaviors to check for), [design-notes.md](design-notes.md) (why things are shaped
the way they are), [swedbank.md](swedbank.md) and [revolut.md](revolut.md) (finished examples of a
bank's notes).

## 1. Before writing code

**Read and check off.** Get the bank's API specs and developer docs. Walk through [gotchas.md](gotchas.md) as a
checklist and note which behaviors the bank has: auth approaches, extra approvals, PSU headers, odd
callbacks, archives, error codes.

**Set up the developer portal.** Most sandbox failures on day one are portal configuration, not code:

- Create an app and note its API key / client id and secret. They go in `banks/<bank>/sandbox.env`,
  which is never committed (see [Sandbox credentials](#sandbox-credentials)).
- Register redirect URIs. Use `http://localhost/cb`; some banks also check it in decoupled flows.
- Enable the sandbox OAuth scope(s) on the app.
- Subscribe the app to **every** API product the flow touches: login, token, consents, accounts, ...
  At Swedbank each of these is a separate product.
- Certificates: many sandboxes accept any certificate or none. Upload one only when a call asks for it.
  Some (Revolut) issue sandbox certificates from your CSR; keep the key, CSR and certificates next to
  `sandbox.env` (`*.key`, `*.csr`, `*.der`, `*.pem` are ignored by git).
- Signed requests: if the bank verifies signatures against a JWKS URL registered in the portal,
  `go run ./cmd/obdev jwks` prints one for the configured key (public data only).

### Sandbox credentials

Each sandbox comes with its own set of credentials: app id and secret, certificates, a test user to log
in with. Every bank package keeps a committed template and a local copy:

| File | Committed | Holds |
|---|---|---|
| `banks/<bank>/sandbox.env.example` | yes | every variable obdev needs, empty, with a note on where in the portal each comes from |
| `banks/<bank>/sandbox.env` | no (gitignored) | your values, including the sandbox test user's login |

```sh
cp banks/<bank>/sandbox.env.example banks/<bank>/sandbox.env   # fill it in
set -a; . banks/<bank>/sandbox.env; set +a
go run ./cmd/obdev connect
```

Relative paths in the file are resolved from the repository root, so the same file works for obdev and
for `go test -tags live ./live`. Values the code never reads, such as the test user's phone number and
password, still belong in the file (as `SANDBOX_USER_*`), so whoever runs the bank next has them.

When adding a bank, write its `sandbox.env.example` first: it is the checklist of what someone needs
from the bank to test the integration. To have an integration tested by someone else, they fill in
their own copy; the files never need to leave their machine.

Portal changes can take a few minutes to reach the bank's API gateway. Retry before debugging.

## 2. Create the package

```
banks/<bank>/
  <bank>.go        registration (init) and client construction
  flow.go          Connect/Resume state machine
  ais.go           accounts, balances, transactions
  http.go          request helper and error mapping
  *_test.go        unit tests, fake-server tests, TestScenarios
  testdata/        recorded scenarios
```

Add the import to `banks/all`. Register an `obsdk.Integration` in `init` with an honest `Info`:

- `Variants`: one per country, segment and environment, each with a maturity:

  | Maturity | Meaning | Allowed on |
  |---|---|---|
  | `unverified` | written from documentation only | any |
  | `experimental` | runs against a fake server or recorded spec examples | any |
  | `sandbox_verified` | exercised end to end against the bank's real sandbox | sandbox variants, with `VerifiedOn` |
  | `verified` | exercised against the bank's real production API | production variants, with `VerifiedOn` |

  Sandbox starts as `experimental` and goes to `sandbox_verified` once the obdev loop below passes.
  Production stays `unverified` until someone runs it with real certificates. `Register` rejects a
  verified level on the wrong environment or without a date.
- `Requirements`, `Limits`, `Capabilities`, and `Notes` for quirks a consumer must know.

## 3. Implement the client: rules that matter

**Auth is a state machine.** `Connect` returns a `Step`; `Resume` takes `Step.State` back. Keep all flow
data in a serializable struct (see `flow` in `banks/swedbank/flow.go`). Remember it goes through JSON:
empty maps come back as `nil` (`omitempty`), so initialize maps before writing to them.

**Hand the session out as soon as it exists.** Once login produced tokens, put the session on every
returned `Step` (`Step.Session`). If the flow fails after that, return the error wrapped in
`*obsdk.FlowError{Session, Err}`. Some banks allow one token per user, so a new login has already
invalidated the caller's previous session.

**Follow the bank's links, but don't trust them blindly.** Steering links (`_links`) are usually right, but
Swedbank's sandbox returns a decoupled poll link that 404s. When a link is wrong, rewrite it in one place
and say why in a comment and in `docs/<bank>.md`.

**Return what the bank sent, in one shape.**
- Populate every normalized field the bank provides; leave the rest empty. Some fields are always
  empty at some banks, and that's expected. Keep the original object in `Raw`.
- Amounts are exact decimals, signed, with `Direction` always set.
- Look for data in non-standard places too (Swedbank's sandbox puts the counterparty in
  `additionalTransactionData`).

**Pagination is pass-through.** Page sizes differ per bank and may ignore what you ask for. Return the
bank's continuation (next link, page id, continuation key) as `TxPage.NextCursor`, accept it back as
`TxQuery.Cursor`, and leave it empty when there are no more pages. Never decide "last page" from the
number of items.

**Errors.** Map bank errors to the typed errors in `errors.go`, using the status, the bank's code *and*
the operation that was running: some codes only mean something for one call.

## 4. Test without a bank first

Write unit tests for pure helpers, and a small fake server for the flows (see
`banks/swedbank/swedbank_test.go`). Then add `TestScenarios` (`obsdktest.PlayAll(t, "testdata")`).
Hand-written scenarios from the spec examples are fine to start with; real recordings replace them later.

## 5. Run against the sandbox with obdev

`cmd/obdev` drives your client exactly as an application would, and can record the conversation.

```sh
set -a; . banks/<bank>/sandbox.env; set +a   # see "Sandbox credentials" above
```

The variables (all listed in `obsdktest/live.go`):

```sh
OBSDK_BANK=<bank> OBSDK_COUNTRY=SE OBSDK_ENV=sandbox
OBSDK_CLIENT_ID=... OBSDK_CLIENT_SECRET=...
OBSDK_REDIRECT_URL=http://localhost/cb          # must be registered in the portal
OBSDK_PSU_IP=127.0.0.1 OBSDK_PSU_USER_AGENT=obdev/0.1
OBSDK_SESSION_FILE=banks/<bank>/sandbox.session.json   # holds tokens; mode 0600, gitignored
OBSDK_TLS_CERT=... OBSDK_TLS_KEY=... OBSDK_TLS_CA=...   # mTLS, when the bank wants it (PEM or DER)
OBSDK_SEAL_KEY=... OBSDK_SEAL_KID=...                   # request signing, when the bank wants it
```

The loop:

1. **Smallest call first.** `go run ./cmd/obdev auth-methods` (or anything that needs no user login)
   proves the host, credentials and default query parameters.
2. **Connect.** `go run ./cmd/obdev connect -method decoupled` (or `redirect`: open the printed URL and
   paste the callback back). The session is saved after every step, so a failure late in the flow still
   leaves you logged in.
3. **Read the failure, fix the code, run again.** Errors carry the bank's status, code and text.
4. **Data calls** use the saved session: `accounts`, `balances ID`, `transactions ID -from 2026-09-01`.
   Page through transactions with the returned cursor: `transactions ID -size 1`, then
   `-cursor <next_cursor>`.
5. **Record** once a flow works: put `-record banks/<bank>/testdata/live-<country>-<name>` before the
   command. Record connect and data calls into separate scenarios. Running several commands with the
   same directory appends calls.
6. **Review** every file in `exchanges/`. Redaction covers credentials, tokens, codes and PSU data, but
   check for anything personal. Then create the golden files and run everything:

   ```sh
   go test ./banks/<bank>/ -obsdktest.update
   go test ./...
   ```

Recording pitfalls:

- Redirect flows read the callback from stdin. When the consent page runs in a browser you can't
  read from (or the callback lands on a page like `https://example.com`), paste the full URL from the
  address bar. Codes are short-lived (Revolut: two minutes, HSBC: one), so pass the callback on at once.
- Don't pipe obdev into `head` or anything that exits early. That kills obdev before `scenario.json` is
  saved, and the replay then fails with "recorded exchanges never requested". Redirect to a file instead.
- A run that failed halfway leaves a partial scenario that breaks `go test`. Delete it and record again.
- A failed call recorded on purpose is fine (it becomes an error outcome in `golden.json`). To drop one,
  delete its file in `exchanges/` and its entry in `scenario.json`'s `calls`, plus the `ids` it used.
- Each obdev command is a new process with a new client. Anything a client caches (ING's application
  token) is fetched again by the next command, but a replay runs every call on one client and never
  asks twice. Delete the repeated exchange, or replay fails with "recorded exchanges never requested".
- Replays match requests on method, path and query. Values that change on every run (timestamps down
  to the millisecond) must come from the scenario, or be rounded to what the scenario stores (seconds).

## 6. Common sandbox errors

From Swedbank, ING, Nordea, HSBC, Rabobank, bunq, Handelsbanken and OP. Other banks word them differently, but the causes repeat.

| Error | Cause | Fix |
|---|---|---|
| `Mismatch redirect URI ...` | redirect URI not registered (also checked in decoupled flows) | register it in the portal, or change `OBSDK_REDIRECT_URL` |
| `SCOPE_INVALID: Not allowed scope` | OAuth scope not enabled on the app | enable it in the portal's OAuth settings |
| `bic ... does not support scope` | scope doesn't belong to the environment | use the sandbox scope with sandbox BICs |
| `SERVICE_BLOCKED: Endpoint not allowed` | app not subscribed to that API product, or the change hasn't propagated | subscribe, wait a few minutes |
| `No MTLS session established` | sandbox app identifier missing (Swedbank: `app-id`), or a certificate is really needed | send the identifier; upload a certificate only if that doesn't help |
| `Service not found` (404) | wrong base path or version | compare with the paths in the bank's own links |
| ING consent page: "The value of 'redirect_uri' is not in the allowed redirect URIs list" | the sandbox app allows one fixed URL | use `https://www.example.com/` |
| ING: `400 SignatureError "Missing required 'x-jws-signature' header"` although it is sent | the payment gateway matches header names case-sensitively | send the name in lower case (Go canonicalizes it; set `req.Header["x-jws-signature"]` directly) |
| ING: `404` with an empty body | a stub sandbox with no scenario for this exact request | compare with the bank's test-scenario document, field by field |
| Nordea: `401 error.digest.invalid` on `/authorize/token` | the digest of a form body is expected over the sorted, *unencoded* `name=value` pairs | hash what the bank's own Postman script hashes, not the bytes sent |
| HSBC: `400 UK.OBIE.Signature.InvalidClaim` on a payment consent | the `http://openbanking.org.uk/iss` claim must be the signing certificate's subject DN exactly as `openssl -nameopt RFC2253` prints it; Go's `pkix.Name` reorders attributes | format the DN from the certificate's raw subject |
| Rabobank: `401 Application is not registered with mutual tls` | no client certificate linked to the app, although the sandbox accepts any certificate | link one under the app's Configuration → Add certificate (whole PEM chain) |
| Rabobank: `401 CERTIFICATE_MISSING "The certificate header is empty."` | mTLS passed, but the request lacks `TPP-Signature-Certificate` / `Signature` | sign every API call, including payment status |
| Rabobank: `400 FORMAT_ERROR "Currently only bookingStatus booked is allowed"` | `bookingStatus` `pending` or `both`, though the spec lists them | ask for `booked` only |
| bunq: `400 "A device already exists for the current installation."` | a second device-server on one installation | make a new installation for every API key or access token |
| bunq: `400 {"error":"invalid_request","error_description":"Missing required GET parameter \"grant_type\"."}` on the token endpoint | OAuth parameters sent as a form body | put them in the query string of the POST |
| bunq: `403 "Insufficient authentication."` on a data call | the session token expired or was deleted | start a new session (session-server), i.e. `Refresh` |
| Handelsbanken: `401 "Invalid client id or secret."` on a consent, although the token call worked | the token endpoint issues tokens for any client id; the API gateway checks it | use the app's client id (32 hex digits in the sandbox) |
| Handelsbanken: `500 "Unexpected error"` on a business consent | the sandbox doesn't know the company id | send the sandbox user's name (`SANDBOX-CORPORATE-SE-1`) as `PSU-Corporate-ID` |
| Handelsbanken NL: `400 "Invalid date format (dateFrom)"` | the NL sandbox rejects the date filter in every format | leave the dates out and filter yourself |
| Handelsbanken SE: `400 "Field chargeBearer allows [SHAR]"` on a business SEPA payment | the Swedish corporate API wants `SHAR` where NL/LU want `SLEV` | send `SHAR` |
| OP: `400 VALIDATION "Bad request"` on `POST .../{paymentId}/submit` | the submit call has no body; the spec defines an (empty) JSON request body | send `{}` with `Content-Type: application/json` |
| OP: `404 "Authorization ... not found"` on `DELETE .../authorizations/{id}`, while `GET` shows it `Authorized` | the sandbox can't revoke an approved authorization | don't count a 404 as revoked; read the authorization to check |
| A login call returns `302` and the next call fails | the HTTP client followed the bank's redirect to its login page (or to your redirect URI) | don't follow redirects on that call; hand `Location` to the user (Nordea's `/authorize`) |

## 7. Finish

- Add a row to [banks.md](banks.md) (a test fails until you do). Don't list banks in the README.
- Write `docs/<bank>.md`: the flows, behaviors worth knowing, **what was verified against the sandbox
  (with a date)** and what is still assumed.
- Add the bank to `gotchas.md`: new behaviors as entries, plus a line in the bank index.
- Set the sandbox variants you ran to `sandbox_verified` with `VerifiedOn`, and name the scenarios that
  prove it in a comment.
