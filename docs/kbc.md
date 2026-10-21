# KBC Group integration notes (KBC, CBC, KBC Brussels)

KBC Group runs one Berlin Group PSD2 API (NextGenPSD2 1.x, `/psd2/v2`) for its three Belgian brands.
Each brand is its own bank key with its own production host and customers: `kbc`, `cbc` and
`kbcbrussels`. The authorisation server and the sandbox are shared. Every brand registers BE, personal
and business; the API makes no difference between the segments, which only label the session.

| | Sandbox | Production |
|---|---|---|
| API | `https://be.psd2.sandbox.kbc-group.com/psd2/v2` (all brands) | `https://psd2.api.kbc.be/psd2/v2`, `https://psd2.api.cbc.be/psd2/v2`, `https://psd2.api.kbcbrussels.be/psd2/v2` |
| Authorize | `https://be.psd2.sandbox.kbc-group.com/ASK/oauth/authorize/1` | `https://idp.kbc.com/ASK/oauth/authorize/1` (all brands) |
| Token | `https://be.psd2.sandbox.kbc-group.com/ASK/oauth/token/1` | `https://openapi.kbc-group.com/ASK/oauth/token/1` |
| Client certificate | KBC's shared test QWAC (on request) or a real QWAC | eIDAS QWAC |
| Client id | the QWAC's organizationIdentifier | the QWAC's organizationIdentifier |

Built from KBC's developer portal (developer.kbc.be): the AIS swagger (v3.2.0, 2023-07), the PIS swagger
(v2.1.4, 2026-02), the functional documentation pages, the authorisation API guide
(`kbc-user-guide-authorization-api.pdf`, v0.8), the PSD2 sandbox user guide and the sandbox Postman
collection. Production API hosts follow the swagger's `servers` entry (`psd2.api.{kbc|cbc|kbcbrussels}.be`);
the sandbox guide also names `https://openapi.kbc-group.com/psd2/v2`.

## What the integration needs

- **QWAC** for mTLS on every call, including the token endpoint. Build the client with
  `kbc.HTTPClient(tlsCert)`. No QSealC: nothing is signed.
- `client_id`: the organizationIdentifier (OID 2.5.4.97) of the QWAC, e.g. `PSDBE-NBB-0123456789`.
  `kbc.ClientID(cert)` reads it. There is no registration and no client secret: the certificate
  registers the TPP on its first call.
- `redirect_url`: sent as `TPP-Redirect-URI` (consents and payments) and as `redirect_uri` (authorize
  and token, matched exactly). KBC asks for HTTPS.
- `PSU.IP` for Connect and InitiatePayment (`PSU-IP-Address` is mandatory there).

**Sandbox access:** the sandbox rejects calls without a client certificate (`401 TOKEN_INVALID "Full
authentication is required"`, checked 2026-10-17). TPPs without a live QWAC mail developer@kbc.be for
the shared test QWAC and key; everyone using it shares the same two dummy users and accounts. A live
QWAC gets its own two dummy users and accounts on its first call.

## Flows

**Connect** (AIS, OAuth2 authorisation code with PKCE):

1. `POST /consents` with `TPP-Redirect-URI` and `PSU-IP-Address`. KBC supports one account per consent:
   `access.balances` and `access.transactions` hold the same single IBAN, or are empty, in which case
   the user picks the account on KBC's page (functional documentation). The SDK sends the IBAN from
   `ConnectRequest.Values["iban"]` when given, else empty arrays. `transactions` is left out when only
   accounts/balances are requested. `recurringIndicator: true`, `frequencyPerDay: 4`,
   `combinedServiceIndicator: false` (the only value KBC supports), `validUntil` today + 90 days (or
   `ConsentValidityDays`, at most 180).
2. Redirect to `/ASK/oauth/authorize/1` with `client_id`, `redirect_uri`, `response_type=code`,
   `scope=AIS:<consentId>`, `state`, `code_challenge` (S256) and the brand: `mainCompany=0001` (KBC,
   KBC Brussels) or `0002` (CBC), plus `company=9998` for KBC Brussels. `language` (NL/FR/DE/EN) from
   `ConnectRequest.Language`.
3. Callback: `?code=…&state=…`, or `?error=access_denied&error_description=user+cancelled` (or
   `technical+error`). For `invalid_scope` and `unauthorized_client` KBC sends no state. The code is
   valid for 2 minutes.
4. `POST /ASK/oauth/token/1` (form): `client_id`, `grant_type=authorization_code`, `code`,
   `redirect_uri`, `code_verifier`. No client secret with an eIDAS certificate. The response holds
   `access_token` (30 minutes), `refresh_token` and `scope` (`AIS`, without the consent id).
5. `GET /accounts?withBalance=true` with `Authorization: Bearer` and `Consent-ID`.

**Refresh**: `grant_type=refresh_token`, `refresh_token`, `client_id`. Refresh tokens rotate (the old
one stops working) and for AIS their lifetime slides with use, up to the consent's end. Near the end
KBC returns no new refresh token; the current one stays in the session. Refreshing one session from
two places at once makes all but one fail.

**Disconnect**: KBC's specification has no consent deletion. The SDK tries the Berlin Group
`DELETE /consents/{id}` and reports anything but 200/204 as a failure, leaving the session as it was.

**Data**: `GET /accounts` (balances inline), `GET /accounts/{id}/balances`,
`GET /accounts/{id}/transactions?bookingStatus=booked&dateFrom=…&dateTo=…`.

## Behaviors worth knowing

- Only `closingBooked` balances and only `booked` transactions. A query for pending alone returns
  `ErrUnsupported`.
- `dateFrom` is mandatory; the SDK sends today − 90 days when `TxQuery.From` is zero.
- Paging: `_links.next` is a plain string (not `{href}`), relative and starting with `/psd2/v2` in
  Yolt's fixtures. The cursor is that link; absolute links, links with or without `/psd2/v2`, and the
  `{href}` form are accepted. A next link equal to the page just read ends paging (a guard Yolt's
  provider also has).
- `remittanceInformationStructured` is a plain string in transactions (Belgian structured
  communication `+++…+++`); it goes to `ReferenceNumber`. `bankTransactionCode` goes to `BankCode`,
  `proprietaryBankTransactionCode` when the former is absent. Exchange rates stay in `Raw`.
- Account `BIC` is the brand's (KREDBEBB for KBC and KBC Brussels, CREGBEBB for CBC); KBC doesn't send it.
- Errors: Berlin Group `tppMessages`; the token endpoint answers OAuth errors (`invalid_grant`, ...);
  the API gateway may answer problem details (`title`, `detail`) or `{"status","message"}`. 401
  distinguishes `CONSENT_EXPIRED` and `CONSENT_INVALID` (→ `ReauthError`) from token errors (→
  `ErrAccessExpired`).

## Payments

Single payments, created without a user token (QWAC only), approved on KBC's page (`scaRedirect`),
status read the same way.

| Type | Product | Notes |
|---|---|---|
| `sepa` | `sepa-credit-transfers` | KBC executes it as SEPA Instant where possible, else as a classic SCT |
| `sepa_instant` | `instant-sepa-credit-transfers` | today only (no `execution_date`) |
| `crossborder` | `cross-border-transfers` | non-SEPA, to an IBAN; KBC's spec says EUR only. `creditorBankCode` from `Agent.MemberID`, `chargeBearer` DEBT/CRED/SHAR |

- `requestedExecutionDate` is mandatory: without `ExecutionDate` the SDK sends today in Brussels.
- `debtorAccount` is optional; without it the user picks the account at KBC (Yolt's notes confirm a
  payment without debtor works).
- `creditorAddress` needs `country`; free address lines are not accepted.
- References go in `remittanceInformationStructured` with `referenceType` `SCOR`: `RF` as issuer `ISO`,
  `BE` (Belgian structured communication, 12 digits) as issuer `BBA`. Issuer `BBA` follows Febelfin's
  standard and is not yet checked against KBC's specification or sandbox (2026-10-21).
- Statuses: `RCVD` after creation and while unsigned; `ACSP` once signed (sandbox: balance reduced);
  `ACSC` settled; `RJCT`; `CANC` when the user cancels on KBC's page.
- KBC's character patterns (`^[a-zA-Z0-9/-?:().,'+-]+$`) leave out the space although its own examples
  (`John Doe`) have one; the SDK does not enforce them.
- No cancellation endpoint; future-dated payments can't be withdrawn through the API.
- Not implemented: periodic payments (`/periodic-payments/sepa-credit-transfers`) and bulk pain.001
  files (`/bulk-payments/pain.001`, up to 5 files, signed separately in the Business Dashboard), and
  `GET /payments/{product}/{id}` (would give the debtor account).

## Verified

Nothing against the real sandbox yet: waiting for KBC's test QWAC (requested 2026-10-17). All variants
are `experimental`: unit tests against a fake server, and the synthetic scenarios `be-connect`,
`be-data`, `be-pay-sepa` built from the spec, the Postman collection and Yolt's open-source KBC/CBC
provider fixtures.

## Still assumed

- The empty-array (bank-offered) consent. The swagger says "none or one single IBAN" and the
  functional page says the user selects accounts at KBC, but Yolt's provider (API 2.0.6) asked for the
  IBAN upfront. If KBC refuses empty arrays, Connect needs `Values["iban"]`.
- The consent's maximum `validUntil` (not documented; 90 days default, 180 cap).
- The shape of the payment callback (assumed to carry no parameters, or `error`), and whether
  `scaRedirect` is absolute (relative links are resolved against the API host).
- `DELETE /consents/{id}`, the exact 401/403 codes, `ACCESS_EXCEEDED`, CBC and KBC Brussels (same
  sandbox), business accounts, and production.
