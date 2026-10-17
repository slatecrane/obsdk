# Rabobank integration notes

Rabobank (the Netherlands) runs its own PSD2 APIs: OAuth 2.0 for consent, Berlin Group-like account
information, and single payment initiation. The integration registers NL, personal and business.
Rabobank's API makes no difference between the two; the segment only labels the session.

| | Sandbox | Production |
|---|---|---|
| API | `https://api-sandbox.rabobank.nl/openapi/sandbox` | `https://api.rabobank.nl/openapi` |
| OAuth (authorize, token) | `https://oauth-sandbox.rabobank.nl/openapi/sandbox/oauth2` | `https://oauth.rabobank.nl/openapi/oauth2` |
| Server certificate | public CA (Sectigo) | public CA (Sectigo) |
| Client certificates | any TLS certificate registered on the app; Rabobank's example signing certificate | eIDAS QWAC + QSealC |
| Client id and secret | an app on the developer portal | an app after PSD2 enrolment |

Built from Rabobank's developer documentation (docs.developer.rabobank.com, PSD2 section): the OAuth
2.0 services, Accounts / Balances / Transactions AIS (v4.0.17), Single Payment Initiation (SEPA,
cross-border, cancel) and the signing guides.

## What the integration needs

`Info.Requirements` lists these; `banks/rabobank/sandbox.env.example` shows where each comes from.

- `client_id` and `client_secret`. On developer.rabobank.com: sign up for Sandbox, then My
  organizations → (sandbox organization) → Apps → Register app. The secret is shown once.
- Subscriptions on the app: **Account Information Sandbox**, **OAuth 2.0 services Sandbox** and
  **PSD2 Single Payment Initiation Sandbox**.
- `redirect_url`, registered on the app as OAuth redirection URI. It is sent as `redirect_uri` on
  authorize and token, and as `TPP-Redirect-URI` for payments.
- **QWAC** for mTLS. Build the client with `rabobank.HTTPClient(tlsCert)`. The certificate must also be
  linked to the app (Configuration → Add certificate, the whole PEM chain); without it every call
  answers `401 Application is not registered with mutual tls`. In the sandbox any certificate passes
  validation; Rabobank publishes an example one (`mTLS-cert.pem`, `mTLS-key.pem`).
- **QSealC** (`Config.Seal`, RSA key **and** `Certificate`). The certificate travels in
  `TPP-Signature-Certificate` and its serial number is the signature's `keyId`, so it is required.
  It is not registered anywhere. Sandbox: Rabobank's example signing certificate
  (`Example-certificate-Sandbox.pem`, serial `0x53311D8E…`, valid until 2100).

## Flows

**Request signing** (every API call; not the token endpoint):

- `Digest: sha-512=<base64 SHA-512 of the exact body>` (an empty string for GET and DELETE).
- `Signature: keyId="<serial, decimal>",algorithm="rsa-sha512",headers="date digest x-request-id",signature="<base64 RSA-SHA512 PKCS#1 v1.5>"`
  over `date: …\ndigest: …\nx-request-id: …` (draft-cavage-http-signatures-10). Payment creation and
  cancellation also sign `tpp-redirect-uri`; the SDK signs it whenever the header is sent.
- `TPP-Signature-Certificate`: the certificate's DER in base64 (the PEM body without line breaks).
- `X-IBM-Client-Id`, `Date`, `X-Request-ID` (UUID).
- The unit tests check our signing strings against the two signatures in Rabobank's documentation
  (made with an older example certificate whose public key is printed there).

**Connect** (redirect only):

1. Redirect to `{oauth}/authorize` with `response_type=code`, `client_id`, `scope`, `state`,
   `redirect_uri`. Scopes from the requested capabilities: `ais.balances.read`,
   `ais.transactions.read-90days`, and `ais.transactions.read-history` for `CapTransactionsHistory`.
2. Callback `?code=…&state=…` (or `?error=access_denied`) → `POST {oauth}/token`
   `grant_type=authorization_code&code=…&redirect_uri=…` with HTTP Basic client id and secret. The
   code is single-use and valid 5 minutes. Rabobank suggests waiting ~1 s before exchanging it; the
   SDK doesn't, since a user's round trip already takes that long.
3. The token response carries `metadata: "a:consentId <id>"` and `consented_on` (epoch seconds). The
   session keeps the consent id under `Consents["ais"]`, valid 180 days from `consented_on`.
4. `GET {api}/payments/account-information/ais/accounts`.

**Data**: `/accounts`, `/accounts/{id}/balances`, `/accounts/{id}/transactions` with the user's token.
`PSU-IP-Address` is sent when `CallOptions.PSU` has an IP: without it Rabobank allows four calls per
day per account for balances and transactions (`Limits.MaxRequestsPerDay`).

**Refresh**: `POST {oauth}/token` `grant_type=refresh_token`, HTTP Basic. Refresh tokens are
single-use (a reused one → `401 invalid_grant` → `ErrReauthRequired`); an access token can be
refreshed 4096 times.

**Disconnect**: `DELETE {api}/oauth2/consents/{consentId}` (signed, no bearer) → 204. The consent
read endpoint (`GET /oauth2/v1/consents/{id}`) is not used.

## Behaviors worth knowing

- **Transactions are booked only.** The spec lists `bookingStatus` `booked`, `pending` and `both`,
  but the API answers `400 FORMAT_ERROR "Currently only bookingStatus booked is allowed"` to the
  other two. The SDK always asks for `booked`; a query for pending alone returns `ErrUnsupported`.
- **Dates**: `dateFrom`/`dateTo` are Zulu date-times. Without either, Rabobank returns only yesterday;
  with `dateTo` alone, the 90 days before it. The SDK always sends `dateTo` (now when `TxQuery.To` is
  zero). `dateFrom` more than eight years back → `400 FORMAT_ERROR`.
- **Pagination**: `size` up to 500 (also the default). The cursor is `_links.next.href`; the SDK
  sends its query (`nextPageToken` and the filters) again on the account's transactions path, so the
  link's path prefix doesn't matter.
- **Transaction fields**: `entryReference` (Rabobank's sequential number per account, which its docs
  advise as the identifier) becomes both `ID` and `EntryReference`. `remittanceInformationStructured`
  is plain text here and becomes `ReferenceNumber`. `raboDetailedTransactionType` and
  `raboTransactionTypeName` become `BankCode` and `BankCodeText`. `endToEndId` `NOTPROVIDED` becomes
  empty.
- **Balances**: `expected` (booked plus pending) has no normalized kind and stays `other`;
  `interimBooked` → `interim_booked`.
- **Accounts** carry IBAN, currency, `ownerName` and `status` (`enabled`, `deleted`, `blocked`, kept
  in `Raw`). `BIC` is always `RABONL2U`.
- **Errors** come in four shapes: Berlin Group `tppMessages` (payments), problem details
  `{"code","title","type"}` (account information), OAuth `error`/`error_description`, and the gateway's
  `{"httpCode","httpMessage","moreInformation"}`. Data calls: 401 → `ErrAccessExpired`; 403 with
  `CONSENT_INVALID` (expired or revoked consent) → `ErrReauthRequired`; 429 → `ErrRateLimited`.

## Payments

Single payments. The payment is created and read with the client id and signature only: no user
token, no login before the signing page, and `PaymentStatus` needs no session.

| SDK type | Rabobank product | Notes |
|---|---|---|
| `sepa` | `sepa-credit-transfers` | EUR. Rabobank sends it as SEPA Instant when the payee's bank is reachable, otherwise as a regular SEPA transfer. There is no separate instant product, so `sepa_instant` isn't offered. |
| `crossborder` | `cross-border-credit-transfers` | Any currency. Requires payee BIC, address (town and country) and charge bearer. BBAN payees (USD) can carry a clearing code (`Agent.ClearingSystem` + `MemberID`, e.g. `USABA`). |

Flow:

1. `POST {api}/payments/payment-initiation/pis/v1/payments/{product}` with `TPP-Redirect-URI` and
   `PSU-IP-Address` (both required) → 201 `{paymentId, transactionStatus: ACTC, _links.scaRedirect}`.
2. Redirect the user to `scaRedirect` (valid 30 minutes; unsigned payments are rejected after that).
3. Resume → `GET …/{product}/{id}/status`. `ACTC` and `PDNG` mean not signed (→ `ErrAuthFailed`), as
   does `CANC` right after the redirect (the user cancelled on Rabobank's page). `RJCT` →
   `*PaymentRejectedError` with the ISO reason from `tppMessages` (e.g. `AM04` insufficient funds).
   `fundsAvailable: false` sets `Reason: insufficient_funds`: Rabobank retries for up to three
   working days.
4. Cancel (future-dated payments): `DELETE …/{product}/{id}` with `TPP-Redirect-URI`. `204` →
   cancelled at once. `202` with `scaRedirect` (`&flow=delete`) → the user signs the cancellation; the
   SDK returns a redirect step and Resume expects `CANC`. Already cancelled → `405 CANCELLATION_INVALID`.

- Statuses: ISO 20022 via `internal/bgstatus`, except `ACTC` and `PDNG` → `received`.
- Field rules: creditor name 2–140, remittance one line ≤ 140 (cross-border: `a-z A-Z 0-9` and
  `./\+?;(),'@ -`), end-to-end id ≤ 35. Description **or** structured reference, not both. RF
  references are sent as `{"reference", "referenceIssuer": "ISO", "referenceType": "SCOR"}`. Dutch
  payment references (betalingskenmerk, issuer `CUR`) have no SDK scheme yet.
- The SEPA body matches Rabobank's documented example byte for byte (test
  `TestPaymentBodyMatchesDocExample` checks the documented digest).
- Periodic payments, bulk payments (pain.001) and funds confirmation are not implemented.

## Verified against the real sandbox (NL personal, 2026-10-17)

The NL personal sandbox variant is registered as `sandbox_verified`. NL business stays
`experimental` (same API, not run under that label); production stays `unverified`.

The sandbox returns static data. Its consent page needs no login, and the redirect lands on the
registered URI with a code.

Scenarios (`banks/rabobank/testdata/`):

- `live-nl-connect`: consent, code exchange (consent id in `metadata`, `expires_in` 3600,
  `refresh_token_expires_in` 432000 = 5 days) and `/accounts`: four EUR accounts of "Rabobank
  Nederland B.V.".
- `live-nl-data`: accounts, balances of two accounts (`expected` and `interimBooked`), an empty
  transactions page, and `dateFrom` 2015 → `400 FORMAT_ERROR` "Date can't be further than 8 years in
  the past."
- `live-nl-refresh`: refresh, then accounts with the new token.
- `live-nl-disconnect`: `DELETE /oauth2/consents/{id}` → 204.
- `live-nl-payment-status`: the documented sandbox payment ids: `ACTC`, `PDNG` → received; `ACSP` →
  in progress (one with `fundsAvailable: false`); `ACSC`, `ACCC` → completed; `RJCT` with `AM04` →
  rejected; `CANC` → cancelled; an unknown id → `404 RESOURCE_UNKNOWN`.
- `live-nl-pay-sepa`, `live-nl-pay-crossborder`: creation → 201 with a fresh payment id and a
  `scaRedirect` to `https://bankieren.rabobank.nl/klanten?paymentinitiationid=…`. Resume's status read
  answers 404: the sandbox only knows its fixed ids.
- `live-nl-pay-cancel`: `204` (cancelled), `405 CANCELLATION_INVALID` (already cancelled), `202` with
  a signing redirect (`&flow=delete`); the status read after it answers 404, as above.

Observed:

- Without a certificate linked to the app, every call → `401 Application is not registered with
  mutual tls`, even though the docs say any certificate passes. After linking Rabobank's example one,
  calls passed immediately.
- `scope` in the token response repeats each scope prefixed with the consent id
  (`<consentId>_ais.balances.read`). The SDK stores it as sent.
- The sandbox has no transactions for any of its accounts, under either scope, for any date range in
  the last eight years.
- Revoking a consent in the sandbox does not stop its tokens: accounts and refresh still worked
  afterwards. Production is documented to answer `403 CONSENT_INVALID`.

## Still assumed

- **Transaction mapping and paging**: the sandbox returns no transactions, so field mapping and
  next links are tested against the schema with a fake server only.
- **Signing a payment**: the sandbox's `scaRedirect` points at the real online bank, and status reads
  of created payments answer 404. Approval and resume are covered by fake-server tests and by the
  status scenarios of the fixed ids.
- `403 CONSENT_INVALID` after revocation or expiry, the four-calls-a-day limit without
  `PSU-IP-Address`, the one-time history read, business accounts, and production (which needs PSD2
  enrolment with real eIDAS certificates).
