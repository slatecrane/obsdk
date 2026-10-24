# Česká spořitelna integration notes (Czech Republic)

Package `banks/ceskasporitelna`, bank key `ceskasporitelna`, integration `ceskasporitelna-cbs`. Česká spořitelna (ČS,
Erste Group) implements the Czech Banking Association's open banking standard (ČBS / ČOBS) like
[Komerční banka](komercnibanka.md): an OAuth2 login with scope `AISP` or `PISP` at ČS's identity provider (IDP), then
account information and payment initiation. Every call is mutual TLS, carries the portal application's `web-api-key`,
and payment calls are signed with the QSealC in production.

The ČBS data model (accounts, balances, transactions, paging, payment status codes, error bodies) is shared with KB in
[internal/cbs](../internal/cbs/cbs.go). Login, headers, payment bodies and signing stay in each bank's package: they
differ more than they agree.

Sources (read 2026-10-24): the Erste developer portal [developers.erstegroup.com](https://developers.erstegroup.com/docs/apis/bank.csas)
(an SPA; content comes from a GraphQL API that wants a key, so the specs were saved with the pages' own *JSON*
download buttons): *PSD2 - Account Information API v4*, *PSD2 - Payment Initiation API v4* and the *IDP documentation*
(OpenAPI 3), and the tutorials *User authentication / authorization*, *Accounts API / Payments API: Requests examples*,
*How to use QSeal certificate*, and the *Certificates* guide.

## What the integration needs

| | Sandbox | Production |
|---|---|---|
| Access | a free portal account ("Solo"; no company, licence or IČO asked) | PSD2 licence; the portal application's production environment is approved by ČS |
| Application | portal → Create App, usage *Third Party Provider*; connect *Česká spořitelna* with *PSD2 - Account Information API v4* and *PSD2 - Payment Initiation API v4*; turn on OAuth2 (code grant) with the redirect URIs; *Generate credentials* | the same application's production credentials |
| `Extra["api_key"]` | the application's sandbox *API Key* (`web-api-key` header) | the production API key |
| `client_id`, `client_secret` | the application's OAuth2 client (checked) | the production client |
| mTLS (`HTTPClient`) | the **sample PSD2 QWAC** the portal lists under the application's sandbox credentials (certificate + private key; O=EAH_SandBox, issuer *EAH CA Intermediate*, valid to 2036-02-28) | a QWAC uploaded to the portal (*Certificates*) |
| `Config.Seal` | optional (the sandbox doesn't check signatures) | a QSealC; required (refused without) |

Build the client with `ceskasporitelna.HTTPClient(cert)`: ČS's gateway asks for the client certificate by
**renegotiating TLS** after the request line (as KB's does); without a certificate the connection is reset. For obdev
set `OBSDK_TLS_RENEGOTIATE=1` (in `sandbox.env.example`). A self-signed certificate passes the handshake but every call
answers `400 {"errorCode":"bad_request","errorText":"{\"status\":\"INVALID\",\"errorCode\":\"unspecified_error\"}"}`.

The *PSD2 - Accounts Balance API v2* (CISP) is greyed out for a TPP application ("available only for" other app
types) and is not used.

Hosts:

| | Sandbox | Production |
|---|---|---|
| IDP (`/auth`, `/token`, `/revokeext`) | `webapi.developers.erstegroup.com/api/csas/sandbox/v1/sandbox-idp` | `bezpecnost.csas.cz/api/psd2/fl/oidc/v1` |
| AIS | `webapi.developers.erstegroup.com/api/csas/sandbox/v4/account-information/my/…` | `…/api/csas/production/v4/account-information/my/…` |
| PIS | `…/api/csas/sandbox/v4/payment-initiation/my/…` | `…/api/csas/production/v4/payment-initiation/my/…` |

Headers on API calls: `web-api-key`, `user-involved` (`true` when the user is present), `x-request-id`, and with a
PSU `user-ip-address` and `user-agent`. The IDP takes no API key ("Don't use API key for IDP calls").

## Flows

**Connect.** Redirect to `{idp}/auth?response_type=code&access_type=offline&scope=AISP&…` (`access_type=offline` asks
for a refresh token). The user logs in to ČS and confirms the accounts on a consent screen. The code is exchanged at
`{idp}/token` with `client_id` and `client_secret` in the body. A cancelled consent comes back as
`error=access_denied&error_description=USER_CANCELLED_ACCESS`. Access tokens last **5 minutes**; the refresh token
lasts **180 days** and is the access's lifetime (`Session.RefreshExpiresAt`, consent `ais` `ValidUntil`). A refresh
returns no new refresh token. Disconnect posts the refresh token to `{idp}/revokeext`.

**Data.** Same ČBS shapes as KB (see [komercnibanka.md](komercnibanka.md#flows)), read by `internal/cbs`:

- Accounts: `GET /my/accounts`, paged from page 0 (`page`, `size`; all pages are read). Ids are 40 hex digits.
  `identification.other` is the domestic number with the bank code (`0259459101/0800`), kept as `BBAN`.
- Balances: `CLAV` (`interim_available`) and, per the spec, `CLBD` (`closing_booked`).
- Transactions: `GET /my/accounts/{id}/transactions?fromDate&toDate&page&size`. Statuses are `BOOK` and `INFO`
  (entries that do not move the balance); both are reported as booked, the bank's status stays in `Raw`. The
  cursor is the next request's query. `bankTransactionCode.proprietary.code` is sent as a float in exponent form
  (`1.0000101E10`); `internal/cbs` writes it as an integer (`10000101000`).

## Payments

Types: `domestic` (CZK, variable symbol as `CZ` reference, message up to 140 characters) and `sepa` (EUR; payee name
and country required, end-to-end id optional, charges always `SHA`, the only option ČS allows in the EEA). Both take
an optional execution date. Single payments only.

1. **Payment login**: a redirect to the IDP with `scope=PISP`, unless `PaymentRequest.Session` holds a usable payment
   login (refreshed if its token expired).
2. **Create**: `POST /my/payments` with the payment login's token. The response carries
   `paymentIdentification.transactionIdentification` (the payment's id) and `signInfo {signId, hash}`.
3. **Signing URL**: `GET /my/payments/federate/sign/{signId}/hash/{hash}` with header `Callback-Uri` (the redirect
   URL) returns `signingUrl` and a `poll {id, interval}`. The SDK redirects the user to `signingUrl`.
4. **Poll** after the user is back: `GET /my/payments/sign/poll/{pollId}` → `DONE`, `PROCESSING` (a `wait` step with
   ČS's interval; Resume again), `AUTHORIZATION_NOT_STARTED` (the user left), `REJECTED`, `EXPIRED`,
   `ORDER_PROCESSING_FAILED` (all fail with `ErrAuthFailed`).
5. **Status**: `GET /my/payments/{signId}/status` with the payment login's token (so `StatusNeedsSession`):
   `ACTC` (waiting for the signature → `received`), `ACSP`, `ACSC`, `RJCT`. `statusChangeInfo`
   (`INSUFFICIENT_FUNDS`, `CANCELLED`, `FUTURE_VALUE_DATE`, …) becomes `Payment.Reason`. Status is kept 34 days.

No cancellation endpoint exists (`CancelPayment` → `ErrUnsupported`); an unsigned payment expires after 30 days, and a
dated one can only be signed until its date.

### Request signing (production; from the QSeal tutorial, not verified)

Payment calls carry `Date`, `Digest: SHA-256=<base64>`, `TPP-Signature-Certificate` (the QSealC, base64 DER) and
`Signature: keyId="SN=<serial, lower-case hex>,CA=<issuer DN>",algorithm="SHA256withRSA",headers="authorization date
digest web-api-key",signature="<base64>"`, the signing string being `name: value` lines in that order. The unit test
checks the Digest of ČS's worked example. ČS's example writes the issuer's quotes unescaped inside the quoted
`keyId`; the SDK does the same. `Config.Seal.KeyID` overrides the keyId.

## Sandbox (verified 2026-10-24)

Everything is scriptable; nothing needs the user after the portal account:

- **Login page** (`{idp}/auth`): an HTML form with one test client, *Jiří Spokojený*
  (`user=8000-01-01-00.00.00.000001`). *Continue* goes to `{idp}/scopes?…`, a consent page whose *Confirm* is
  `GET {idp}/allow/true?<the authorize query>&user=…&appName=<app name>&accessSeconds=300&refreshSeconds=15552000`
  and answers `302` to `redirect_uri?code=…&state=…` (*Cancel*: `{idp}/deny/USER_CANCELLED_ACCESS`). The code in the
  Location is already URL-encoded.
- **Data is static**: two CZK accounts, one balance (CLAV, dated 2017), seven booked transactions from 2017; paging
  and date filters are ignored.
- **Payments are static stubs**: `POST /my/payments` answers a fixed example whatever is sent (a domestic one, or a
  SEPA one for a SEPA body), the signing URL is `{idp}/sign` (a static page whose button goes to
  `http://localhost`), the poll always says `DONE`, and the status is always `ACTC` with `INSUFFICIENT_FUNDS`.
- **Revoke is a stub**: `200`, and the refresh token still works afterwards.

Recorded scenarios (`banks/ceskasporitelna/testdata/live-cz-*`): connect, data (accounts, both balances,
transactions), refresh, disconnect, a domestic payment with login, a domestic and a SEPA payment reusing the payment
login, payment status.

Not verified: anything with real data or real outcomes (the stubs), the production IDP and hosts, request signing,
`PROCESSING` polls, the business segment (the sandbox has one client).

## Follow-ups

- Instant payments (`instructionPriority: INST`, domestic and SEPA; not for Business 24 accounts): needs a domestic
  instant payment type in the root package, or `sepa_instant`.
- International (`SWIFT`) payments, batch payments (`/my/batchpayments`), standing orders (`/my/standingorders`,
  AIS and PIS).
- Other Erste banks on the same portal (Slovenská sporiteľňa, Erste Bank Hungary, BCR, Erste&Steiermärkische) use
  their own APIs; not researched.
