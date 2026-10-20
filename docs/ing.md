# ING integration notes

ING runs one PSD2 API for its retail and SME customers in Belgium, Germany, Italy, Luxembourg, the
Netherlands, Romania and Spain. The integration registers those countries, personal and business
(Italy: personal only; Spain's business segment is sole traders). ING Wholesale Banking (country code
`WB`) uses the same API but is not registered yet.

| | Sandbox | Production |
|---|---|---|
| API | `https://api.sandbox.ing.com` | `https://api.ing.com` |
| Authorisation page | `https://myaccount.sandbox.ing.com/authorize/v2/{CC}` | `https://myaccount.ing.com/authorize/v2/{CC}` |
| Server certificate | public CA | public CA |
| Client certificates | ING's published example certificates | eIDAS QWAC + QSealC (or OBIE for UK accounts) |
| Client id | `5ca1ab1e-c0ca-c01a-cafe-154deadbea75` (pre-registered) | returned by ING when you onboard |

Built from ING's developer portal: the OAuth 2.0, Account Information (v4.0.1) and Payment Initiation
(v2.6.0) API references, the PSD2 "Get started" guide, the "Message signatures" guide and ING's sandbox
test-scenario documents (AIS v2.00, March 2026; PIS, April 2026).

## What the integration needs

`Info.Requirements` lists these; `banks/ing/sandbox.env.example` shows where each comes from.

- `client_id`. In the sandbox, the pre-registered app above. In production, ING creates the app when
  you onboard with your eIDAS certificates (`POST /oauth2/applications`, not implemented by the SDK)
  and returns the client id.
- `redirect_url`. Production: registered on the onboarded app. The sandbox consent page accepts
  `https://www.example.com/` (not `https://example.com`, although the app's metadata lists it).
- **QWAC** for mTLS on every call. Build the client with `ing.HTTPClient(tlsCert)`; ING's servers use
  public-CA certificates.
- **QSealC** (`Config.Seal`, key **and** `Certificate`): signs requests. ING identifies the key by the
  certificate's SHA-256 fingerprint, so the certificate is required. RSA keys sign with PS256, P-256
  keys with ES256.

The sandbox needs no account or registration: download ING's four example files (signing and TLS,
certificate and key, valid until December 2028) into `banks/ing/`.

## Flows

**Application token**: `POST /oauth2/token` `grant_type=client_credentials&client_id=...` over mTLS,
unsigned. Valid 15 minutes; the client caches it. ING's older flow signed this request with a
draft-cavage `Signature` and sent the QSealC in `TPP-Signature-Certificate`; the mTLS-only flow
replaces it once the app is onboarded.

**Connect** (redirect only):

1. Redirect to `https://myaccount.ing.com/authorize/v2/{CC}` with `client_id`, `scope`, `state`,
   `redirect_uri`, `response_type=code`. Scopes: `payment-accounts:balances:view` and/or
   `payment-accounts:transactions:view`, from the requested capabilities. No API call is needed for
   this (the older `GET /oauth2/authorization-server-url` is deprecated).
2. Callback `?code=...&state=...` → application token → `POST /oauth2/token`
   `grant_type=authorization_code&code=...&redirect_uri=...` with the application token as bearer.
   The code is valid 10 minutes.
3. `GET /v4/accounts`. ING may still be processing the grant and answer 404 for a few seconds; the
   SDK retries twice (1 s, then 2 s), as ING's docs advise.

**Data**: `GET /v4/accounts`, `/v4/accounts/{id}/balances`, `/v4/accounts/{id}/transactions`
(card accounts: `/v2/card-accounts/{id}/transactions`) with the customer token, `X-Request-ID`,
`Digest`, `Content-Type: application/json` (also on GETs) and `X-JWS-Signature`.

**Request signature** (`X-JWS-Signature`): a detached JWS, `header..signature`.

- Protected header: `{"b64":false,"x5t#S256":<fingerprint>,"crit":["sigT","sigD","b64"],"sigT":<UTC,
  seconds>,"sigD":{"pars":["(request-target)","digest","content-type"],"mId":"http://uri.etsi.org/19182/HttpHeaders"},"alg":"PS256"}`.
- Signed input: `<base64url header>.(request-target): get /v4/accounts?...\ndigest: SHA-256=...\ncontent-type: application/json`.
  The request target is the lower-case method plus path and query.
- **Header name must be lower case** on the payment endpoints. The gateway answers `400
  SignatureError "Missing required 'x-jws-signature' header"` to `X-JWS-Signature` and to Go's
  canonical `X-Jws-Signature`. The SDK sets the name in lower case everywhere.

**Refresh**: `POST /oauth2/token` `grant_type=refresh_token` with the application token. Customer
tokens last 15 minutes. Refresh tokens last up to a year; when the grant is shorter, a refresh returns
no new refresh token and the old one stays valid.

**Disconnect**: `POST /oauth2/token/revoke` `token=<refresh token>&token_type_hint=refresh_token` with
the application token. ING has no consent resource; revoking the refresh token ends the grant.

## Behaviors worth knowing

- **History**: right after the user authorises, all history the online bank has is readable (2 to 10
  years, by country). After that, requests are limited to the last 90 days; more needs a new
  authorisation (ING answers 403). The 180-day grant is reported as `Limits.MaxConsentDays`.
- **Account ids**: `Account.ID` is the `resourceId`, with `card~` in front of card accounts (their
  transactions live under `/card-accounts`), and `~CUR` behind Belgian multi-currency accounts. Those
  list one entry per currency under the same `resourceId` and IBAN; calls for them carry `currency`.
  `StableID` includes the currency, as for every account.
- **Card accounts** (IT, LU, RO; listed in NL too) have a masked PAN instead of an IBAN, identifier
  scheme `MASKED_PAN`, `Type: CARD`, and their own transaction format (`cardTransactions`,
  `transactionDetails`).
- **Amounts** are JSON numbers, signed. The SDK keeps their exact text (`100.00` stays `100.00`).
- **Transactions**: ING always returns `booked`, `pending` and `info` (reservations whose final amount
  is unknown); the SDK filters by `TxQuery.Status` and returns `info` as pending.
  `standingOrderAgreementInformation` (German consumers) is not mapped. `endToEndId` `NOTPROVIDED`
  becomes empty. Unstructured remittance uses `<br>` as a line break; the SDK splits on it.
  `executionDateTime` becomes `TransactionDate`.
- **Pagination**: `limit` up to 100 (default 10; the SDK asks for 100 unless `PageSize` is set). The
  cursor is the `_links.next.href` path, followed as given.
- **Errors**: 401 on a data call → `ErrAccessExpired`. 403 `SERVICE_BLOCKED` → `ErrReauthRequired`
  (`grant_not_valid`): the grant no longer covers the account or more than 90 days were asked for.
  Refresh `400 invalid_grant` ("Refresh token is revoked." / "has expired.") → `ErrReauthRequired`.
  Error bodies come as `tppMessages`, OAuth `error`/`error_description`, or the gateway's
  `{"error":{"code","message"}}`.

## Payments

PIS v2, single payments. The payment is created and read with the application token; the user's
approval on ING's page is the only interactive step, and no customer token is involved.

| SDK type | ING product | Countries |
|---|---|---|
| `sepa` | `sepa-credit-transfers` | BE, DE, ES, IT, LU, NL, RO |
| `sepa_instant` | `sepa-credit-transfers` with `localInstrumentCode: INST` | BE, DE, ES, IT, LU, NL |
| `domestic` | `domestic-credit-transfers` (RON) | RO |
| `crossborder` | `cross-border-credit-transfers` | BE, DE, ES, LU, NL, RO |

Flow:

1. `POST /v2/payments/{product}` with `TPP-Redirect-URI`, `PSU-IP-Address` (required, so
   `PaymentRequest.PSU.IP` is too), `Digest` and `x-jws-signature`. Only fields the caller set are sent.
2. Redirect the user to `_links.scaRedirect`. ING's docs define no parameters on the way back to
   `TPP-Redirect-URI`, so Resume reads the callback only for an OAuth-style `error` and otherwise
   accepts it empty or bare.
3. `GET /v2/payments/{product}/{id}/status` (unsigned). `RCVD` after the redirect means the user did
   not approve → `ErrAuthFailed`; `RJCT` → `*PaymentRejectedError` with `stsRsnInf` as the reason.
4. Cancel: `DELETE /v2/payments/{product}/{id}`, no user approval; for payments not executed yet
   (future-dated). Not offered for instant payments.

- Statuses: ISO 20022 via `internal/bgstatus`, except `ACTC`, which ING uses for "logged in, not yet
  authorised", so it maps to `received`.
- Field rules: creditor name ≤ 70, unstructured remittance one line ≤ 140, end-to-end id ≤ 35, all in
  ING's character set (`a-z A-Z 0-9 ?:()./,'+ -`). Structured RF references are sent as SCOR. A payee
  address must be structured, with town and country; free address lines are rejected before the call.
- `PaymentRequest.Context` and instruction ids are not supported.

## Verified against the real sandbox (NL personal, 2026-10-16)

The NL personal sandbox variant is registered as `sandbox_verified`. Other sandbox variants stay
`experimental`; production variants stay `unverified`.

The sandbox is a stub. Its consent page lists test profiles per country instead of a login, and its
API answers only the requests in ING's test-scenario documents.

Scenarios (`banks/ing/testdata/`):

- `live-nl-connect`: consent page (profile "Hr A van Dijk, Mw B Mol-van Dijk"), code exchange and
  `/v4/accounts`: two current accounts and a credit card account.
- `live-nl-data`: accounts, balances of both current accounts, transactions (booked and pending), and
  a first page with `limit=1` that returns a next link (profile "Alice and Bob").
- `live-nl-disconnect`: refresh, then revoke.
- `live-nl-blocked`: balances for profile "A Van Dijk" → `403 SERVICE_BLOCKED` → `ErrReauthRequired`.
- `live-nl-payment-status`: status of the documented PACT payments: `ACSC` → completed and `RJCT` →
  rejected, both final.

Observed:

- The mTLS-only application token works with the example certificates. Its scope is
  `payment-accounts:orders:create granting`, and the response includes `client_id` and ING's signing
  key (`keys`).
- v4 balances work **without** `balanceTypes`. The test-scenario document (written for v3) asks for
  an exact type; v4 answers with every type the account has.
- `limit=100` and arbitrary date ranges work. Dates are sent as `YYYY-MM-DDThh:mm:ss.000Z`.
- Token responses: `expires_in` 900 (the application token: 905), `refresh_token_expires_in` 2592000
  (30 days). ING's docs show `expires_in` as a string; the sandbox sends numbers. The SDK reads both.
- Revoking one profile's refresh token also revoked another profile's: the stub seems to issue one
  refresh token for every test profile.
- Payment creation: the signed request passes the gateway (a non-matching body gets `404`, not a
  signature error).

## Still assumed

- **Following a next link**: the sandbox answers `500 ING_ERROR 23.2.005` to every v4 next link,
  including the documented pagination profile. The cursor handling is tested against the schema only.
- **Card accounts**: in the NL sandbox card balances and transactions answer `500` (ING's document
  says NL cards are not supported in the sandbox). The card mapping is tested against the schema only.
- **Payment creation end to end**: the sandbox only accepts the documented bodies. Those use an IBAN
  with wrong check digits (`NL69INGB5678901234`), which the SDK rejects before sending, and address
  fields the SDK model doesn't have (department, floor, room, ...). Creation, approval and resume are
  covered by fake-server tests (`payment_test.go`). Cancellation has no sandbox scenario.
- Other countries and the business segment, Belgian multi-currency accounts, the 90-day limit,
  standing orders (German consumers), periodic and bulk payments, and production (which needs
  onboarding with real eIDAS certificates).
