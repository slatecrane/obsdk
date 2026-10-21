# BNP Paribas Fortis integration notes (Belgium; also Hello bank! and Fintro)

BNP Paribas Fortis runs one PSD2 API, STET 1.6 served as `psd2/v4` (API version 4.1, released 2026-08-04; v3.3
is deprecated). [banks/bnpparibasfortis](../banks/bnpparibasfortis) registers it on the generic STET adapter
([stet.md](stet.md)) with one bank key per brand, because in production every brand has its own hosts:

| Bank key | Brand | Segments | Sandbox `brand` |
|---|---|---|---|
| `bnpparibasfortis` | BNP Paribas Fortis | personal (Easy Banking), business (Easy Banking Business) | `bnppf` |
| `hellobank` | Hello bank! | personal only | `hb` |
| `fintro` | Fintro | personal, business | `fintro` |

Built and run against the sandbox on 2026-10-21 from the portal's documentation (Getting Started, the AIS,
PIS and funds-confirmation product pages) and the v4 OpenAPI file in
[OpenBanking-BNPPF/resources-stet](https://github.com/OpenBanking-BNPPF/resources-stet).

| | Sandbox | Production |
|---|---|---|
| API | `https://sandbox.api.bnpparibasfortis.com/psd2/v4`, every brand, `?brand=` on every call | `https://regulatory.api.{bnpparibasfortis,hellobank,fintro}.be/psd2/v4` |
| Authorize | `https://sandbox.auth.bnpparibasfortis.com/authorize?brand=…` | `https://services.{brand}.be/SEPL/PSD2/{IND,ENT}/authorize` (IND personal, ENT business) |
| Token | `https://sandbox.auth.bnpparibasfortis.com/token` | `https://regulatory.api.{brand}.be/token` |
| Client auth | `client_id` + `client_secret` in the form | same; the pair comes from the onboarding endpoint |
| mTLS | none | eIDAS QWAC |
| Signature | header required, value not checked | draft-cavage with the QSealC (see below) |
| Data | test users generated per app; payments become transactions | real |

## Access

- **Sandbox:** free, after a manual review. Register on https://developer.bnpparibasfortis.com (registered
  2026-10-20, approved 2026-10-21). Then:
  - add an app under Dashboard > Manage Apps (redirect URI `https://example.com/callback`; the portal checks
    the URL);
  - subscribe it to the psd2/v4 APIs per brand (AIS, Check Availability of Funds, PIS). Subscriptions in one
    app must share a domain and a version;
  - copy the Client ID and Client Secret Key from the app details;
  - click "Generate Test User" in the app's Test Data Domain. It created 12 personal test users with accounts
    spread across the three brands (user name and password shown there). There are no business users.
- **2FA:** the portal login needs a TOTP app; SMS is switched off at the end of October 2026.
- **Production:** a PSD2 licence, a QWAC and a QSealC. The client is created through
  `POST https://regulatory.api.{brand}.be/third-party-onboarding/v1/third-party`: mTLS with the QWAC, the body
  signed as a detached JWS in `x-jws-signature` (PS256, `x5u` to the QSealC PEM). It answers with the client
  id and secret. The SDK does not implement the onboarding. Not done: we have no certificates.

## Flows

- **Connect:** OAuth2 authorization code, scope `aisp`, no PKCE. The code exchange must also send
  `scope=aisp`; without it the sandbox answers `500` (`TokenScope`). The user picks the accounts at the bank,
  or the TPP names up to 10 with `accounts=IBAN+CCY,...` on the authorize URL (not built). There is no consent
  resource and no `PUT /consents`. Production tokens last 180 days; the sandbox's 1 hour; a refresh token
  comes with them.
- **Brands:** a login through the Fortis or Hello bank! page covers accounts of both brands (one test user's
  Fortis and Hello bank! accounts both came back through `brand=bnppf`). The token then only works on that
  brand's API. Fintro is separate.
- **Accounts:** `resourceId` is IBAN + currency (`BE17343577691822EUR`); the currency sits next to
  `accountId`, not in it. `usage` PRIV/ORGA; `psuStatus` Holder, Mandate or Legal representative.
- **Balances:** `CLBD` (closing), `OTHR` (the "operational" balance: booked, real time), `ITAV` (available,
  retail only). `OTHR` comes back as kind `other`.
- **Transactions:** `dateFrom`/`dateTo` are dates; `dateTo` is exclusive and, when left out, planned
  transactions are returned too. At most 2 years per request, 4 years back for Easy Banking. Pages of up to
  100 with a `next` link (`index`, `pageSize`). `resourceId` is a JSON number;
  `additionalTransactionInformation` is an object (statement and operation references, `endToEndReference`,
  `narrative` lines). An account without transactions answers `200` with an empty list. Per-transaction
  details (`/transactions/{id}/details`) are not built.
- **Payments:** `POST /payment-requests` with a client-credentials token (scope `pisp`) and the header
  `businessLineName` (`RPB` personal, `CPB` business; also picks the bank's app on mobile). The body has the
  beneficiary and `requestedExecutionDate` at payment level (`PaymentLevel`), the amount as a string
  (`AmountString`), no `categoryPurpose` (only a few corporate codes are allowed), date-times without
  fractional seconds. The answer has `Location` and a `consentApproval` link; the user approves on the
  bank's page and is sent to `successfulReportUrl` or `unsuccessfulReportUrl` (both must be https). There is
  no confirmation call: the bank executes the payment (`Confirmation: none`). Unapproved payments expire
  after 60 minutes.
- **Status:** `GET /payment-requests/{id}` with a client token: ACTC, ACCP, PDNG (multi-signature or not
  enough money yet), ACSP, ACSC, RJCT. The body's `resourceId` (`29406`) is an internal number, not the id
  from `Location`; the adapter keeps the `Location` id.
- **Cancellation:** only future-dated SEPA payments and standing orders, before execution: `PUT` the payment
  request back with `paymentInformationStatus` `RJCT` and `statusReasonInformation` `DS02`
  (`CancelStatus`). The answer has a `consentApproval` link to `/payment-requests/{id}/cancel/confirmation`;
  the user approves, and the payment ends as `RJCT` with reason `CUST`, which the adapter reads as cancelled.
- **Disconnect:** no API; the tokens are dropped and the user revokes the access in online banking.

## Signing (production; not testable)

`Signature: keyId="<https URL of the QSealC PEM>",algorithm="rsa-sha256",headers="(request-target) (created)
(expires) host x-request-id digest",created=…,expires=…,signature="…"`, with a `Digest` (SHA-256 of the body)
on every request, GET included (the docs ask for "a random hash" there; we send the digest of the empty
body). `expires` may be at most 60 seconds after `created`; we use 30. The portal has a signature validator
(https://developer.bnpparibasfortis.com/signature-validator), not used yet.

## How the sandbox differs from the documentation

- **Test IBANs are not valid IBANs.** The generated accounts fail the IBAN check digits, so the SDK refuses
  them as payee or payer. Payments were made without a payer account (the user picked it at the bank) to
  `BE60652828776570`, a valid IBAN from the bank's examples.
- **The cancellation returns to the payment's report URLs.** The cancellation request carries new report
  URLs, but the bank sends the user back to the original payment's, with that payment's `state`. The
  adapter does not check the state of a cancellation callback; it reads the status.
- **Approval links put the report URL unencoded** in `redirect_uri` (`…&redirect_uri=https://…?error=…&state=…`).
  Harmless: the browser follows the link as is.
- **Dated payments** run 20 minutes after approval regardless of the date (`X-Execution-Delay` header to
  change it); payments dated today are executed at once.

## Verified against the sandbox (2026-10-21, `bnpparibasfortis`, personal)

Connect (a test user with a Fortis and a Hello bank! account), accounts, balances, transactions (the payment booked,
with end-to-end id and bank code), refresh, disconnect; a SEPA payment approved and `ACSC`; a dated payment
approved (`ACCP`) and cancelled with approval (`RJCT` CUST); status read. Scenarios in
`banks/bnpparibasfortis/testdata/live-be-*`.

Not run: `sepa_instant`, the `hellobank` and `fintro` keys (same sandbox, other `brand` value), the business
segment (no business test users), production.

## Not built

International payments (`chargeBearer`, payee address, BBAN), standing orders, file payments (pain.001,
business only), funds confirmation (`POST /funds-confirmations`, scope `cbpi`), the `accounts` and SCA
preselection parameters of the authorize URL, Belgian structured communications (`+++…+++`) as references,
and the onboarding endpoint.

## Payments

| Type | Notes |
|---|---|
| `sepa` | EUR; payer account optional (picked at the bank); description or `RF` reference; `execution_date` up to a year ahead (empty: today); cancellable while not executed, with the user's approval |
| `sepa_instant` | EUR; today only; Belgian structured references only (not built), so description only; not cancellable |
