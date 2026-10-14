# Swedbank integration notes

Covers SE, EE, LV and LT (selected by BIC). Sandbox and production differ in scope
(`PSD2sandbox` / `PSD2`), BIC (`SAND*` / real) and the AIS base path.

Built from these specs: authorize (redirect), authorize-decoupled, token, consents, accounts.
The developer documentation PDF has **not** been read; anything it would settle is listed below.

## Flows

**Connect** = login, then consents, then account discovery, as one resumable sequence:

1. Login, either
   - `redirect`: `GET /psd2/authorize` (302, `Location` is the bank login page) → user returns with
     `access_code` and `state` → `POST /psd2/token`; or
   - `decoupled`: methods from `GET /psd2/v5/available-authentication-methods` → inputs the method
     needs (Baltics: `psu_id` plus `personal_id` or `phone_number`) → `POST /psd2/v5/authorize-decoupled`
     → poll; Swedish users with several banks get a `bank_id` choice (`MISSING_BANK_ID`) → `PUT` → code → token.
2. `allAccounts` consent (one-off) → list accounts.
3. `detailed` consent for those accounts (recurring, 4 requests/day, default 90 days, max 180),
   approved by redirect or app depending on the login method. Skipped approvals happen when the login
   scopes already cover it (`scope_extra`).
4. Done: session, plus the accounts the bank exposed.

**Transactions** within 90 days page through `GET .../transactions` (always paginated). Older ranges
(or `RESOURCE_NOT_POSTED`, or an HTTP 210 answer) start the export: `transactionsOver90Days` consent →
`POST .../transactions` → optional approval → poll status → download ZIP → merged into one page. The
caller sees ordinary steps; the final `StepDone` carries `Transactions`.

## Behaviors worth knowing

- One access token per user, bank and app: a new login invalidates the previous token. Refresh keeps
  the old refresh token when the bank sends no new one.
- `expires_in` is read as seconds (values above 1e9 are treated as absolute Unix time).
- Pagination cursors are short-lived and single-use in Sweden.
- Secrets travel in query strings (`client_secret`, `refresh_token`, `apiKey`); SDK logs redact them.
- "Other login session is ongoing" (SE decoupled) is retried once automatically, as the spec says.
- Statement 428 means "still generating": the SDK returns a wait step of 60s.
- `Date` and `X-Request-ID` are sent on every call.

## Verified against the real sandbox (SE, 2026-10-13)

The SE sandbox variant is registered as `sandbox_verified`. EE/LV/LT sandbox stay `experimental`; all
production variants stay `unverified`.

- No QWAC/QSealC needed in the sandbox as long as `app-id` is sent; without it, AIS calls answer
  `No MTLS session established`.
- `redirect_uri` / `redirectUri` must match a URI registered on the app, **also for decoupled login**
  (the field is required there too).
- The app needs the `PSD2sandbox` scope enabled in the portal's OAuth settings (`SCOPE_INVALID` otherwise).
  `PSD2` and extra scopes such as `PSD2account_list` are rejected for `SANDSESS`.
- Sandbox Mobile BankID decoupled login is approved immediately: the first poll returns
  `finalised` with an `authorizationCode`.
- The sandbox's `scaStatus` link is `/sandbox/v5/authorize-decoupled/authorize/{id}`, which answers
  404. The working path is `/psd2/v5/...`; the SDK rewrites it.
- The token response has `expires_in: 3600` (seconds) and `Login-Method` / `Login-Method-Extended` headers.
- AIS base path `/sandbox/v5` is correct (`/accounts` reaches consent validation).
- `available-authentication-methods` with `apiKey` returns only `MOBILE_ID`; with `app-id` it also
  returns `PIN_CALCULATOR`, `BANKID_CARD` and `PIN_CALCULATOR_CORP`.
- `/consents` answers `401 SERVICE_BLOCKED: Endpoint not allowed` unless the app is subscribed to the
  consents API product. Subscription changes took a few minutes to reach the gateway.
- Full decoupled connect works (scenario `testdata/live-se-decoupled`): both consents are approved by
  `PUT .../authorisations/{id}` with `MOBILE_ID`, then polling goes `started` → `finalised` (about 4 polls),
  then consent status `valid`. The sandbox has 5 SEK accounts.
- Accounts, balances and transactions work (scenario `testdata/live-se-data`). The page size is capped at
  200 even though `pageSize=500` is sent. `_links.nextPage` is at the top level of the body.
- Sandbox transactions put the counterparty only in `additionalTransactionData.detail`
  (`receiver`, `accountTo`, ...), so the normalized `counterparty` is empty.

Added 2026-10-14:

- **Redirect connect** works (scenario `testdata/live-se-redirect`). The sandbox login page asks for a
  personnummer and a login method; any well-formed dummy number is accepted.
- The login callback comes back to `https://localhost/cb?code=...&state=...` even though
  `http://localhost/cb` was sent. The token exchange accepts `redirect_uri=http://localhost/cb` with that code.
- Both connect consents (`allAccounts`, then `detailed`) are approved on a bank page (`_links.scaRedirect`).
  After approval the browser returns to a bare `https://localhost/cb`, **without any parameters**. The SDK
  accepts that and checks the consent status.
- **Extended history** works (scenario `testdata/live-se-history`). No extra OAuth scope was needed.
  Flow: `transactionsOver90Days` consent for the account's IBAN → redirect approval (bare callback again)
  → status `valid` → `POST .../transactions` answers **HTTP 210** with `statementStatus: signed` (no second
  approval) → download answers `428 RESOURCE_PENDING` while the statement is generated (about a minute),
  then `200` with `statement.zip`.
- The ZIP holds one file, `offline_statement.json`, shaped like an online transactions response
  (`account`, `transactions.booked`). Asked from 2026-05-01, it returned 15 transactions, 2026-05-13 to
  2026-10-14, with no pagination.

## Assumptions to verify against the real sandbox

1. **Production AIS base path** is `/psd2/v5` (inferred from a link pattern); sandbox is `/sandbox/v5`.
2. **Steering links** (`_links`) don't carry `bic`/`app-id`, so the SDK appends them.
3. **Baltic login fields**: `PSU-ID` header is required; `personalID` for Smart-ID/Simple-ID/eParaksts,
   `phoneNumber` for Mobile-ID. Sweden needs none.
4. ~~Consent redirect return carries no usable parameters~~: confirmed in the SE sandbox (bare callback).
5. ~~Extended history approvals~~: SE sandbox needs the consent approval only; the statement request
   came back `signed`. The statement-approval path stays implemented for other countries/production.
6. ~~Archive layout~~: confirmed for SE sandbox (one `offline_statement.json`, online shape).
7. **QR `imageLink`** is resolved relative to `/psd2/` (the spec's example and path disagree).
8. **`allAccounts` consent** is created with `validUntil` = tomorrow.
9. **Scopes that skip approval** aren't mapped to capabilities; pass them via `scope_extra`.
10. **Business accounts** (`PSU-CORPORATE-ID`) are not registered as a variant.
11. The spec examples contain copy-paste errors (wrong paths in some `_links` examples), so real
    recorded responses should become the fixtures.
