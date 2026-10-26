# Komerční banka integration notes (Czech Republic)

Package `banks/komercnibanka`, bank key `komercnibanka`, integration `komercnibanka-cbs`. Komerční banka (KB,
Société Générale group) implements the Czech Banking Association's open banking standard (ČBS, "Czech Open Banking
Standard", COBS): OAuth2 login with scope `aisp` or `pisp`, then account information and payment initiation, with
KB's deviations from the standard listed in its manuals. Nothing is signed; every call is mutual TLS.

The ČBS data model (accounts, balances, transactions, paging, payment status codes, error bodies) lives in
[internal/cbs](../internal/cbs/cbs.go), shared with [Česká spořitelna](ceskasporitelna.md); login, headers, payment
bodies and signing stay here. Moneta follows ČOBS v7 too, but its sandbox needs a licence; ČSOB has no public portal.

Sources (read 2026-10-23): KB's developer portal [developers.kb.cz](https://developers.kb.cz) (an SPA; each service's
OpenAPI file and guide links are served base64-encoded at `https://developers.kb.cz/api/apis/<code>`, e.g.
`TppOAuthSandboxCz-v1`, `AispSandboxCz-v2`, `PispSandboxCz-v2`), the sandbox guides linked from there, and the
production manuals on [kb.cz/en/kbapi/psd2-services](https://www.kb.cz/en/kbapi/psd2-services): *Third Party
Registering & Authorising Process Manual* v6, *Account Information Service Manual AIS (v2)* v12 (2026-03-18),
*Payment Initiation Service Manual* v11.

## What the integration needs

| | Sandbox | Production |
|---|---|---|
| Access | a free account on developers.kb.cz; KB says no licence is needed ("A licence issued by the CNB is not required for the KB API Sandbox") | PSD2 licence (EBA register and a CNB JERRS notification for CZ) |
| mTLS (`HTTPClient`) | KB's *PSD2 Sandbox Test Certificate*: logged in, service *OAuth2 for PSD2 API CZ Sandbox v1* → *PSD2 Sandbox Test Certificate* (a `.p12`, password on the same page; issued by "KB Interni CA Technicka", valid to 2027-09-30) | a QWAC or QSealC from I.CA or another QTSP KB has onboarded, sent (public part only) to api@kb.cz for registration |
| `client_id`, `client_secret` | not checked (any value) | from KB's dynamic registration (below) |
| `redirect_url` | anything for the login; the signing page wants `https` | one of the (up to three) URIs registered for the client |
| `Extra["tpp_name"]` | required (`TPP-Name` header, no diacritics) | the TPP's name |
| `Extra["tpp_id"]` | optional | the licence number (`TPP-Identification`) |

Build the client with `komercnibanka.HTTPClient(cert)`: KB's gateway asks for the client certificate by
**renegotiating TLS** after the request, which Go refuses unless allowed (`tls: no renegotiation`); the helper allows
it once per connection. For obdev set `OBSDK_TLS_RENEGOTIATE=1` (in `sandbox.env.example`).

Hosts:

| | Sandbox | Production |
|---|---|---|
| Login | `api-gateway.kb.cz/sandbox/oauth2-authorization-ui/v3/` | `login.kb.cz/autfe/ssologin` |
| Token / revoke | `api.kb.cz/sandbox/oauth2/v1/{token,revoke}` | `api.kb.cz/serverapi/oauth2/v1/{token,revoke}` |
| AIS | `api.kb.cz/sandbox/aisp/v2/my/…` | `api.kb.cz/serverapi/aisp/v2/my/…` |
| PIS | `api.kb.cz/sandbox/pisp/v2/my/payments…` | `api.kb.cz/serverapi/pisp/v2/my/payments…` |

### Production client registration (not run)

KB issues no API keys. A TPP registers its application once, over mTLS with the registered certificate, and gets
`client_id` and `client_secret` (the SDK does not wrap this; it is a one-off):

```sh
curl --cert qwac.pem --key qwac.key -H 'Tpp_id: <licence number>' -H 'Content-Type: application/json' \
  https://api.kb.cz/serverapi/oauth2/v1/register -d '{"application_type":"web",
  "redirect_uris":["https://tpp.example/cb"],"client_name":"…","logo_uri":"https://…","contact":"…","scopes":["aisp","pisp"]}'
```

`GET/PUT/DELETE /register/{client_id}` read, change and delete the registration; `POST /register/{client_id}` issues
a new secret. The scopes are checked against the certificate's PSD2 roles.

## Flows

**Connect.** Redirect to the login with `scope=aisp` (KB takes one scope per login). The user logs in to KB's
internet banking and grants access to their payment accounts: there is no consent resource and no account choice
in the API. The code is exchanged at the token endpoint with `client_id` and `client_secret` in the body. Access
lasts **180 days** (EU 2022/2360); the session's consent `ais` gets that `ValidUntil`, and its account list is
filled with the IBANs found at Connect. Access tokens last an hour.

**Data.**

- Accounts: `GET /my/accounts`, paged (`page`, `size`; all pages are read; KB sends `nextPage: 0`, not `null`, on
  the last page of this list, so the next page counts only when it moves forward). A multi-currency account is
  listed once per currency, same IBAN, different id. Account ids are encrypted and **change on every listing**;
  older ids keep working (checked in the sandbox across tokens and a refresh). Match accounts with `StableID`. The
  ids are base64 and can contain `/` and `+`, so they are path-escaped.
- Balances: `GET /my/accounts/{id}/balance` gives `CLAV` (available, `interim_available`) and `PRCD`. ISO 20022
  calls PRCD "previously closed booked", but KB calls it the current balance and dates it now, so it is
  `interim_booked`. `creditLine` stays in `Raw`.
- Transactions: `GET /my/accounts/{id}/transactions?fromDate&toDate&page&size` (dates as `YYYY-MM-DD`). Booked
  (`BOOK`) and pending (`PDNG`, e.g. card holds) items come together, with no filter: items of a status the query
  didn't ask for are dropped from the page, so a page may hold fewer items than `size` (the cursor still comes from
  KB's `nextPage`). The cursor is the next request's query (`page` plus the filters). Up to 2 years of history;
  more than 90 days back only within 5 minutes of the login (KB's reading of the RTS). Mapping: `entryReference` is
  the id, the counterparty is the creditor of a debit and the debtor of a credit, the variable symbol
  (`VS:…` among the structured references, unless 0) is `ReferenceNumber`, `bankTransactionCode.proprietary.code`
  (a ČBS number) is `BankCode`, `additionalTransactionInformation` is `BankCodeText`.

**Refresh** sends `grant_type=refresh_token` (plus `redirect_uri`, which the sandbox insists on: `400 "Required
query parameter 'redirect_uri' is missing."`). KB issues no new refresh token; the old one stays valid.
**Disconnect** revokes the refresh token at `/revoke` (the user can also revoke access in internet banking).

## Payments

| Type | What KB calls it | Notes |
|---|---|---|
| `domestic` | TUZEM (`DMCT`) | CZK, to a Czech IBAN; the variable symbol as `obsdk.ReferenceCZ` (1–10 digits), sent as `VS:<digits>` in `remittanceInformation.structured.creditorReferenceInformation.reference`; a message of up to 140 characters (CERTIS set) |
| `sepa` | SEPA (`ESCT`) | EUR, payee name required, BIC optional; message only (KB ignores the structured reference for SEPA and parses symbols from the message) |

The account to pay from is required (KB's signing page doesn't let the user pick one); `debtor.currency` picks the
sub-account of a multi-currency account (default: the amount's currency). The payment's instruction id is the
transfer's `InstructionID`, else the idempotency key, reduced to letters and digits: KB refuses anything else
(`400 RR10 "Invalid charset"`).

Flow, two redirects:

1. Login with `scope=pisp` (skipped when `PaymentRequest.Session` is an earlier payment login whose token is valid
   or can be refreshed; an AIS token gets `401` on payments).
2. `POST /my/payments` with that token (`Date` and `User-Involved` headers) → `transactionIdentification`, a
   `signId`, status `ACTC`.
3. `POST /my/payments/{id}/sign/{signId}` with `{"authorizationType":"USERAGENT_REDIRECT","redirectUrl":…}` (KB's
   spelling is `authorizationType`, its manual says `authorisationType`; the sandbox refuses the latter with
   `FIELD_MISSING`) → `href.url` on KB's signing page (`method: GET`; a POST would be refused by the SDK). The
   signature must be started within 5 minutes of creation.
4. The user signs and comes back to `redirectUrl`, **without code or state** (production may add `changeInfo`
   with a moved due date). The SDK then reads `GET /my/payments/{id}/status`, which needs the certificate only: `ACTC`
   (still unsigned) fails the step with `ErrAuthFailed` and the payment, `RJCT` with `PaymentRejectedError`.

Status mapping: `ACTC` is `received` here (created, waiting for the signature), `ACSP` `in_progress`, `ACSC`
`completed` (final), `RJCT` and the non-ISO `RJCR` `rejected`. Every step from the payment login on carries that
session, the final one included, so it can be reused.

No future-dated payments: KB executes the same business day (before 20:30, later ones the next business day), and
its manual says forward dates are refused (except for KB+ accounts). Signed payments are **irrevocable**:
`CancelPayment` returns `ErrUnsupported`. (`DELETE /my/payments/{id}` deletes only an unsigned one; the sandbox
answers `400 NARR "Payment has already been authorized"` otherwise.)

Not implemented: instant domestic payments (`instructionPriority: INST`; the sandbox answers `400 OFFD "Offline
Debtor Agent"`), foreign payments (ZPL; they need the payee's full address), reading the user's standing orders
(AIS `/my/standingorders`; no root interface yet), batch payments, the balance check (`POST /my/payments/balanceCheck`,
CISP), the newer one-SCA payment API (`/pispsca/v2`, RAR authorisation, sandbox only so far), and KB's Slovak
branch (KBSK), which has its own API and manuals.

### Standing orders

`domestic` only (CZK), as `PaymentRequest.Schedule` (spec: `Info.StandingOrderSpec("CZ", seg, "domestic")`). They live
on **PIS v1** (`/pisp/v1/standingorders`; v2 has none), with the same payment login and signing page as payments:

1. `POST /standingorders` with `standingOrderIdentification.instructionIdentification`, `amount`,
   `standingOrder.execution {mode, modeDue, interval}`, `validity.lastExecutionDate`, `requestedExecutionDate` (the
   first payment), `debtorAccount` (IBAN + currency), `creditorAccount`, and the remittance (message, `VS:` symbol).
   The answer is flat (not wrapped in `paymentRequest` as for payments): `standingOrderIdentification.transactionIdentification`,
   `signInfo`, `instructionStatus` `ACTC` or `ACWC` (accepted with a change; `statusChangeInfo` becomes `Payment.Reason`).
   KB uses the message as the order's `alias`.
2. `POST /standingorders/{id}/sign/{signId}` with `USERAGENT_REDIRECT` → KB's signing page, as for payments.
3. After the return, `GET /standingorders/{id}/status` (certificate only): `ACSP` → `accepted` (KB says it may still
   turn into `RJCT`, so not final), `ACSC` → `accepted` and final, `RJCT`/`RJCR` → `rejected`; `ACTC`/`ACWC` → not
   signed (`ErrAuthFailed`). `PaymentStatus` reads the same resource.

Mapping of `Schedule`:

| `Schedule` | KB |
|---|---|
| `Frequency` `daily`, `weekly`, `every_two_weeks`, `monthly`, `every_two_months`, `quarterly`, `semiannual`, `annual` | `interval` `DAILY`, `WEEKLY`, `BI_WEEKLY`, `MONTHLY`, `BI_MONTHLY`, `QUARTERLY`, `HALFYEARLY`, `YEARLY` (`BI_WEEKLY` is in the manual, not in the OpenAPI enum; the sandbox takes it) |
| `StartDate` | `requestedExecutionDate`; D+2 business days per the manual; its day is the day of every payment (`modeDue: DUE_DAY_OF_MONTH`, also for days 29 to 31) |
| `EndDate` | `mode: UNTIL_DATE` + `validity.lastExecutionDate`; without it (and `Count`) `UNTIL_CANCELLATION` |
| `Count` | sent as `UNTIL_DATE` with the last payment's date, worked out by the SDK (see below) |
| `EndOfMonth`, `NonBusinessDay` | not offered: KB refuses `DUE_LAST_DAY_OF_MONTH`, `DUE_OR_NEXT_DAY_OF_MONTH` and `DUE_OR_BEFORE_DAY_OF_MONTH` (`400 FIELD_INVALID standingOrder.execution.modeDue`) |

**Count workaround.** KB accepts `AFTER_MAX_ITERATION_EXCEEDED` with `validity.maxIterations` (the manual's field;
the OpenAPI enum misspells the mode `FTER_…` and has no `maxIterations`), but turns it into `UNTIL_DATE` one interval
too late: 12 monthly payments from 2026-11-05 came back ending on 2027-11-05 (13 payments). The SDK therefore sends
`UNTIL_DATE` with start + (count − 1) intervals, on the start's day or the month's last day when that month is shorter.

Not used: `intervalDue`, `exceptions` (stoppages, breaks), `IRREGULAR` and `MAX_AMOUNT_EXCEEDED` (unsupported per the
manual), and `PUT` (change). **Cancellation:** the manual lists `DELETE` as unsupported, so `CancelPayment` returns
`ErrUnsupported`. The sandbox does answer it: an unsigned order is deleted (`204`, status then `RJCT`), a signed one
returns a new `signInfo` (`OPEN`), so deleting it would take the user's signature. Revisit if KB documents it.

## Sandbox

A stub. `sandbox_verified` on 2026-10-23 with obdev (scenarios `banks/komercnibanka/testdata/live-cz-*`):

- Connect, accounts (5: two CZK current/savings accounts and a multi-currency account listed as USD, EUR and CZK),
  balances (CZK and the EUR sub-account), transactions (empty), refresh, disconnect.
- A domestic payment with a message and a variable symbol: payment login, created (`ACTC`), signed, `ACSP`;
  a second one reusing the payment login (no login redirect); status read with the certificate only.
- 2026-10-26, standing orders: monthly with an end date, a message and a variable symbol (`ACSP`); every two weeks
  with a count (KB echoed the SDK's last date); quarterly from the 31st on a saved payment login; status read.
  The sandbox validates (unknown interval → `FIELD_INVALID`, past start → `400 NARR "Expired Execution date"`) but
  takes a start tomorrow (the manual says D+2).

What the sandbox does and doesn't do:

- **Login.** The login page asks for a test client name (any text) and builds the code in the browser: base64 of
  `{"userId": <name>, "scopes": <scope split on ",">}` (`js/main.js`). obdev runs can be scripted that way; every
  name sees the same accounts.
- **Signing page** (`api.kb.cz/sandbox/authfe/ssologin?SAMLRequest=…`) redirects straight back to `redirectUrl`,
  signed. `redirectUrl` must be `https` (`400 FIELD_INVALID redirectUrl` for `http://localhost`).
- **Transaction history is empty** for every account and date range, so transaction mapping is tested against
  KB's manual examples only.
- **Only domestic payments can be signed.** A SEPA payment (EUR to a foreign IBAN) is created, but its signature
  answers `500 ERR_CODE_500 "Service unavailable"`; KB's test data lists the accounts as "domestic payments only".
  `sepa` is therefore built from the manual and unverified.
- No balance or amount checks; future dates are accepted (production refuses them).
- `/revoke` answers 204 but the tokens keep working.

## Errors

KB answers `{"errors": [{"error" | "code", "scope", "message"}]}` (both `error` and `code` occur). Mapped:
`401` on AIS/PIS → `ErrAccessExpired`; `400 NARR` on AIS (`AccessDenied - …`) → `ReauthError`; `invalid_grant` on
refresh → `ReauthError`, on the code exchange → `ErrAuthFailed`; `429` → `RateLimitedError`. `APIError.RequestID`
is KB's `x-response-id` (or the gateway's `gwcorrelationid`), which KB's support (api@kb.cz) asks for along with the
time, IP and environment.
