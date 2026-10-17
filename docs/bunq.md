# bunq integration notes

bunq (licensed in the Netherlands, serving the EEA) has one public API for every country and both
segments. It is not a Berlin Group or STET API: its own REST API with OAuth 2.0 on top. The
integration registers the 30 EEA countries, personal and business. The API makes no difference
between countries; the segment only labels the session. bunq does not filter its accounts by it either.

| | Sandbox | Production |
|---|---|---|
| API | `https://public-api.sandbox.bunq.com/v1` | `https://api.bunq.com/v1` |
| OAuth authorization page | `https://oauth.sandbox.bunq.com/auth` | `https://oauth.bunq.com/auth` |
| OAuth token | `https://api-oauth.sandbox.bunq.com/v1/token` | `https://api.oauth.bunq.com/v1/token` |
| Certificates | none | none for bunq users' own OAuth clients; QSealC for PSD2 TPPs (see below) |
| OAuth client | made through the API by a sandbox user | in the bunq app, or through the API |

Built from doc.bunq.com (Authentication, OAuth, API context, Signing, Pagination, Draft Payment,
Errors, Rate Limits) and bunq's OpenAPI file (`github.com/bunq/doc`, branch `develop`), checked against
the sandbox on 2026-10-17.

## What the integration needs

`Info.Requirements` lists these; `banks/bunq/sandbox.env.example` shows where each comes from.

- `seal`: any RSA key of 2048 bits or more (`Config.Seal.Key`; no certificate). It registers
  installations and signs request bodies. It is not a QSealC.
- `client_id`, `client_secret` and `redirect_url` of an OAuth client, for the redirect method. A bunq
  user creates one in the app, or with `POST /user/{id}/oauth-client` plus
  `POST /user/{id}/oauth-client/{id}/callback-url`. Each user can have one OAuth client.
- `permitted_ips` (Extra, optional): IPs, or `*`, the user's token may be used from. Empty binds it to
  the IP that connects; servers behind several IPs need to list them.
- `device_name` (Extra, optional): the device name the user sees in the app (default `obsdk`).

**Sandbox setup**: `go run ./banks/bunq/sandboxsetup` creates a sandbox user that owns an OAuth client
with `http://localhost/cb`, and a test user funded with €500 from "Sugar Daddy". It prints the values
for `sandbox.env`. No portal and no sign-up are involved.

**PSD2 TPPs** register with their QSealC (`POST /payment-service-provider-credential`) instead of
being bunq users, and then create their OAuth client the same way. That registration is a one-time
setup outside the SDK and is not implemented. bunq's docs say OAuth is mandatory for public apps and
that accessing other users' data may require a PSD2 licence.

## Flows

**Common headers** on every call: `Cache-Control: no-cache`, `User-Agent`, `X-Bunq-Language`,
`X-Bunq-Region`, `X-Bunq-Geolocation: 0 0 0 0 000`, and a unique `X-Bunq-Client-Request-Id`. bunq
refuses a request id used twice on the same device. Every request with a body is signed:
`X-Bunq-Client-Signature` = base64 RSA PKCS#1 v1.5 over SHA-256 of the exact body (headers and URL
are not signed). bunq demands it for payments and session-server (`466` otherwise); the sandbox
checks almost nothing. The response signature (`X-Bunq-Server-Signature`) is not verified.

**Connect, method `redirect`** (default, OAuth):

1. Redirect to `{auth}?response_type=code&client_id=…&redirect_uri=…&state=…`. bunq has no scopes.
   The page shows a QR code that the user scans with the bunq app, where they pick the accounts to
   share. In the sandbox that is the Android sandbox app.
2. Callback `?code=…&state=…` → `POST {token}?grant_type=authorization_code&code=…&redirect_uri=…&client_id=…&client_secret=…`.
   The parameters must be in the **query string**: a form body gets
   `400 {"error":"invalid_request","error_description":"Missing required GET parameter \"grant_type\"."}`.
   The answer is `{"access_token", "token_type": "bearer", "state"}`: no expiry and no refresh token.
3. Activation, the "API context" (below), with the access token as the secret.

**Connect, method `api_key`**: the user's own API key (bunq app: Settings → Developers → API keys),
entered at an input step (`api_key`, a secret field) or pre-filled in `ConnectRequest.Values`. Then
the same activation. bunq allows API keys for applications only their owner uses.

**Activation**, the same for both methods:

1. `POST /installation {"client_public_key": "<PEM>"}` → installation `Token`.
2. `POST /device-server {"description", "secret", "permitted_ips"?}` authenticated with the
   installation token. One device per installation: a second one is refused with "A device already
   exists for the current installation.", so every user gets their own installation.
3. `POST /session-server {"secret"}` with the installation token → session `Token`, its `Id` and
   the user. The user is `UserPerson`/`UserCompany` for an API key. For OAuth it is a `UserApiKey`,
   whose `id` replaces the user id in every path and which names the app (`requested_by_user`) and
   the user (`granted_by_user`).
4. `GET /user/{id}/monetary-account` lists the shared accounts.

The session keeps the long-lived secret (OAuth access token or API key) in `RefreshToken`, the bunq
session token in `AccessToken`, and the installation token, user id, user type and session id in
`Meta`. The session lasts the user's auto-logout time (`session_timeout`, a week by default; for
OAuth the shorter of the app's and the user's). bunq extends it while it is used; the SDK takes the
conservative value.

**Refresh** calls session-server again with the stored secret and installation token. When the
installation token is refused, it makes a new installation and device and tries once more. A key
change in `Config.Seal` ends up the same way. A refused secret (`400 "User credentials are incorrect.
Incorrect API key or IP address."`) → `ErrReauthRequired`.

**Disconnect** deletes the bunq session (`DELETE /session/{id}` → `200 {"Response":[]}`; the token is
dead afterwards) and clears the session's tokens. bunq has no API to revoke an OAuth grant or an API
key: `DisconnectResult.Failed` says so, and the user revokes it in the app.

## Behaviors worth knowing

- **Response shape**: `{"Response": [ {"<Type>": {...}}, ... ], "Pagination": {...}}`. Every object
  is wrapped in its type name: `Id`, `Token`, `MonetaryAccountBank`, `Payment`, `DraftPayment`, …
  Errors: `{"Error": [{"error_description", "error_description_translated"}]}`, with no codes. The
  SDK classifies by status and text.
- **Expired or dead session token**: `403 "Insufficient authentication."` (not 401) →
  `ErrAccessExpired`; Refresh starts a new session.
- **Rate limits** are per endpoint and IP, e.g. `429 "Too many requests. You can do a maximum of 2
  calls per 3 second to this endpoint."` (PUT draft-payment). `RateLimitedError.RetryAfter` takes the
  seconds from that text. Installation is the scarcest: bunq documents "as low as 10 per day".
- **Accounts**: every type comes from `/monetary-account` (`MonetaryAccountBank`, `Savings`,
  `Joint`, `External`, …). `Product` is the type without the prefix; `Type` is `CACC` or `SVGS`;
  `Name` is the user's description; `OwnerName` is `display_name`; `BIC` is `BUNQNL2A`, except for
  external accounts; `CreditLimit` is the overdraft limit when it isn't zero. `Usage` comes from the
  user type (`UserPerson` → `PRIV`, `UserCompany` → `ORGA`). Listings are paged like transactions;
  the SDK asks for 200 and follows `older_url`.
- **Balances**: one per account, the available balance (`balance`) → `interim_available`, dated by
  the account's `updated` in Europe/Amsterdam. It also comes inline with every account.
- **Transactions** are bunq `Payment` objects: incoming and outgoing, card payments and requests.
  All are booked, so a query for pending alone → `ErrUnsupported`.
  - bunq cannot filter by date. Listings run newest first; `count` is at most 200 (default 10).
    `Pagination.older_url` leads to older items and is `null` on the last page.
  - The SDK returns one bank page per call and drops payments newer than `To`. It stops (empty
    `NextCursor`) at the first payment older than `From`.
  - The cursor wraps `older_url` together with the window, so the caller need not repeat From/To.
  - A page can come back empty while the SDK walks past payments newer than `To`.
  - Cursors must point at the same account's payment listing; anything else is refused.
- **Transaction fields**:
  - `ID` is the payment id; `BookingDate` and `TransactionDate` are `created` (UTC) as a date in
    Europe/Amsterdam.
  - Counterparty: `display_name` and `iban`. Remittance: `description`. `ReferenceNumber`:
    `merchant_reference`. `MerchantCategory`: the counterparty's `merchant_category_code`.
  - `BalanceAfter`: `balance_after_mutation`. `BankCode` and `BankCodeText`: `type` (`BUNQ`,
    `EBA_SCT`, `MASTERCARD`, …) and `sub_type` (`PAYMENT`, `REQUEST`, `SCT`, …).
  - Amounts are signed relative to the account.

## Payments

Draft payments: a payment on one of the user's accounts that the user accepts in the bunq app. bunq
documents draft payments as the way for PSD2 providers (PSD2 forbids them from executing
`/payment` directly). An OAuth app could also pay straight between the user's own accounts; that isn't
offered.

| SDK type | bunq | Notes |
|---|---|---|
| `sepa` | `draft-payment` with one entry, counterparty `{type: IBAN, value, name}` | EUR. bunq sends it as a SEPA credit transfer (`EBA_SCT`), or as a bunq payment when the payee banks with bunq. |

Flow:

1. `PaymentRequest.Session` (from Connect) is required, and so is the debtor IBAN, which must be one
   of the session's accounts. The SDK lists the accounts to find its monetary account id.
2. `POST /user/{id}/monetary-account/{account}/draft-payment
   {"status":"PENDING","entries":[{"amount","counterparty_alias","description"}],"number_of_required_accepts":1}`
   → `{"Id"}`. Without a payee name bunq answers `400 "Pointer has no name set."`.
3. A wait step (`NeedsUser`, `WaitFor` 5 s): the user accepts in the bunq app. Resume reads
   `GET …/draft-payment/{id}`.
   - `PENDING`: wait again.
   - `ACCEPTED` with `object.Payment`: `completed`, final. bunq books it at once.
   - `REJECTED` / `EXPIRED`: a `FlowError` with `ErrAuthFailed` and the payment (`rejected`).
4. `PaymentStatus` and `CancelPayment` read the draft with the user's session
   (`PaymentCallOptions.Session`; `StatusNeedsSession`). `Payment.Ref` names user, account and draft.
5. Cancel: draft statuses are `PENDING`, `ACCEPTED`, `REJECTED`, `EXPIRED` (and
   `DEPRECATED_ACCEPTED_PENDING_PAYMENT`); `CANCELLED` is refused. A pending draft is withdrawn with
   `PUT … {"status":"REJECTED","previous_updated_timestamp": <its updated>}`. `CancelPayment` reports
   `cancelled`; later status reads show `rejected`. A draft that isn't pending → `400 "To update the
   status of a draft payment to "REJECTED", it must have status "PENDING"."`, which the SDK refuses
   before calling.

Not implemented: several entries in one draft (bunq takes up to 350 and turns them into a
`PaymentBatch`), scheduled drafts (`schedule`), payments to e-mail or phone aliases (bunq-to-bunq),
and the PISP-only `payment-service-provider-issuer-transaction`.

## Verified against the real sandbox (NL, 2026-10-17)

NL personal and business sandbox variants are registered as `sandbox_verified`. The other countries
stay `experimental` (same API and host); production stays `unverified`.

Scenarios (`banks/bunq/testdata/`), all with method `api_key`:

- `live-nl-connect`: input step, then installation, device-server (no `permitted_ips`, so bound to
  the caller's IP), session-server (`UserPerson`, `session_timeout` 604800) and accounts.
- `live-nl-data`: accounts, balances, three transaction pages of two (`count=2`, then `older_url`
  twice; the last has `older_url: null`), and a pending-only query (`ErrUnsupported`).
- `live-nl-refresh`: session-server with the stored installation token. The sandbox returned the same
  session token as before.
- `live-nl-pay-sepa`: draft created, one poll while `PENDING`, accepted, then `ACCEPTED` with a
  `Payment` (`EBA_SCT`) → `completed`.
- `live-nl-pay-cancel`: draft created, withdrawn (`REJECTED`), status read (`rejected`), second
  cancel refused.
- `live-nl-business-connect`, `live-nl-business-disconnect`: a sandbox company user (`UserCompany`
  → `ORGA`), then `DELETE /session/{id}`.

Approving a draft in the sandbox doesn't need the app: the account owner can `PUT` the draft to
`ACCEPTED` with their own API key, which is how the recordings did it.

Observed:

- Sandbox users come from `POST /sandbox-user-person` / `sandbox-user-company` (no authentication).
  The response carries the API key and, for persons, the user with phone and e-mail aliases. Money
  comes from a request-inquiry to `sugardaddy@bunq.com` (up to €500), which lands a few seconds later.
- A sandbox user can log in to the sandbox app only if it never made an API call before (bunq's docs).
- The consent page is a JavaScript app. It polls a public
  `GET https://api.oauth.triage.bunq.com/v1/oauth-request/{uuid}` (status `PENDING`, the callback URL,
  the state) and deep-links the app with `token-qr-oauth-request`. There is no public route for
  accepting it outside the app.
- The token endpoint answers a bad code with `400 {"Error":[{"error_description":"Invalid hash \"…\"."}]}`.
- After `DELETE /session/{id}` the old token gets `403 "Insufficient authentication."`.

## Still assumed

- **OAuth consent end to end**: needs the Android sandbox app (an emulator or a device) to scan the
  QR code. The authorization URL, the token exchange (query parameters, error shapes) and an OAuth
  session (`UserApiKey`, user id in paths, timeouts) are covered by unit tests built from the docs'
  examples; the live run hasn't been done.
- Which accounts `/monetary-account` returns under OAuth (bunq says the ones the user picked), and
  whether a PSD2 AISP sees the same objects.
- Production: request and response signing (the sandbox checks almost nothing), IP binding without
  `permitted_ips`, the installation rate limit, and whether an OAuth app may withdraw a draft
  payment (the recordings did it as the account owner).
- Card authorisations that are not yet settled: bunq models them as `MastercardAction`, which the SDK
  does not read; only settled `Payment`s appear.
