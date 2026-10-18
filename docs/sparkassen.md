# Sparkassen integration notes (Finanz Informatik XS2A)

Finanz Informatik runs one Berlin Group NextGenPSD2 interface for the German Sparkassen-Finanzgruppe:
about 345 Sparkassen, the Landesbanken (NORD/LB, LBBW, Landesbank Saar, ...) and Weberbank. It is
the first bank on the generic Berlin Group adapter ([berlin-group.md](berlin-group.md)): bank key
`sparkassen`, DE, personal and business.

| | Sandbox | Production |
|---|---|---|
| API | `https://xs2a-sandbox.f-i-apim.de:8444/fixs2a-env/xs2a-api/<BLZ>/v1` | `https://xs2a.f-i-apim.de:8443/fixs2aop-env/xs2a-api/<BLZ>/v1` |
| Versions | `GET .../xs2a-api/<BLZ>/versions` lists the institution's URL and spec version | same |
| Client certificate | PSD2 **test** QWAC from a listed trust centre (e.g. Bundesdruckerei) | eIDAS QWAC; KID/ZAD licence (BaFin, or passported) |
| OAuth client id | the QWAC's organizationIdentifier (subjectNcaId) | same |

Built on 2026-10-18 from Finanz Informatik's documentation package, published by Star Finanz on its
behalf at https://www.starfinanz.de/services/xs2a/ (`xs2a-documentation.zip`, care package of
2022-10-19 with a bank code list of 2026-09-21): ReadMe v1.4, Implementer Options v3.2, Redirect
handbook v1.4, pushTAN 2.0 handbook v1.3, Account Transactions Query v1.0, ownerName v1.0, the sandbox
configuration and the bank code list. The package mentions OpenAPI files but does not contain them, so
field shapes follow the Berlin Group 1.3.x standard and the handbooks' examples.

## What the integration needs

- **QWAC** for mTLS on every call (`sparkassen.HTTPClient(cert)`). No QSealC: request signing is not
  required (IO1).
- `bank_code` (`Config.Extra`): the Sparkasse's BLZ, which is part of every URL. `sparkassen.BankCode`
  also accepts an IBAN and takes the code from it. It is needed to connect or pay; after that the
  session, the flow state and the payment reference carry it, so `Restore` and later calls work without
  it. A client configured for another bank code refuses a session from a different one.
- `client_id` and `redirect_url`: redirect approach only (see below).
- `PSU.IP`: without `PSU-IP-Address` an account call counts as unattended and uses up the consent's
  `frequencyPerDay` (4).

## Flows

Finanz Informatik picks the approach from `TPP-Redirect-Preferred`: missing or `true` means redirect,
`false` embedded. The SDK sends it on every request, from `ConnectRequest.Method` /
`PaymentRequest.Method` (`redirect`, the default, or `embedded`).

**Redirect = OAuth SCA approach** (redirect handbook):

1. `POST /v1/consents` (or `/v1/payments/{product}`) with `TPP-Redirect-URI` and `TPP-Nok-Redirect-URI`.
   The response has a `scaOAuth` link (the handbook also calls it `scaOAuth2`; both are read) instead
   of `scaRedirect`.
2. `GET` that link: RFC 8414 metadata with `authorization_endpoint` (the Sparkasse's online banking)
   and `token_endpoint`.
3. The user goes to the authorization endpoint with `response_type=code`, `client_id`,
   `scope=AIS:<consentId>` or `PIS:<paymentId>`, `state`, `code_challenge` and
   `code_challenge_method=S256`. The handbook documents no `redirect_uri` parameter (the bank uses
   `TPP-Redirect-URI`), so none is sent (`Profile.OAuthNoRedirectURI`). The user logs in, sees the
   resource, picks the TAN method and approves.
4. Back at `TPP-Redirect-URI?state=…&code=…`, or at the Nok URI on failure.
5. Consents: `POST token_endpoint` with `grant_type=authorization_code`, `code`, `client_id`,
   `code_verifier` within 10 minutes. Access token one hour (`expires_in` is a string in the
   example), refresh token 180 days. Payments: the code is not exchanged; the status decides.

Account list, balances, transactions and account details need `Authorization: Bearer`. `Refresh`
checks the consent's status, then renews the access token with `grant_type=refresh_token`. A rejected
refresh token is a `ReauthError`.

**Bank-offered consent:** Finanz Informatik has no `allPsd2` consent (IO30), so a redirect connect
sends empty account lists and the user picks the accounts at the bank (the sandbox picks
`DE86999999990000001000`). With `ConnectRequest.Values["iban"]` the consent is dedicated to those
IBANs instead.

**Embedded** (IO5, IO29: explicit start always):

1. `POST /v1/consents` with `TPP-Redirect-Preferred: false`. An embedded connect needs the IBANs in
   `Values["iban"]`, since the user can't pick accounts.
2. `startAuthorisationWithPsuAuthentication`: `POST .../authorisations` with `PSU-ID` and
   `psuData.password` (the online banking login and PIN, asked for in one input step).
3. `selectAuthenticationMethod` when the user has several: smsTAN, pushTAN, chipTAN manual
   (`CHIP_OTP`/`HHD1.3.2`), optical (`HHD1.3.2OPT`) or QR (`HHD1.3.2QR`). chipTAN USB isn't offered.
4. `authoriseTransaction` with the TAN. chipTAN optical and QR send what the TAN generator reads in
   `challengeData.data`; it reaches the app as `Step.Challenge.Code` (the flicker code to animate,
   or the QR content), with the instructions in `Challenge.Text`.

**pushTAN 2.0** (pushTAN 2.0 handbook): users whose S-pushTAN app supports it are always offered two
methods, `PUSH_OTP` (type the TAN) and `PUSH_DEC` (confirm in the app). Picking `PUSH_DEC` makes the
bank answer `ASPSP-SCA-Approach: DECOUPLED`, `scaStatus: started` and only a `scaStatus` link. The
adapter then returns wait steps and polls the authorisation until `finalised` / `exempted` or
`failed` (time out after 12 minutes, user refused, or an outdated app: `psuMessage` "3015 -
Abrufversuch durch inkompatiblen Client"; pick `PUSH_OTP` then). The SDK shows both methods and
leaves the choice to the user.

**Disconnect:** `DELETE /v1/consents/{id}`, with the bearer token when there is one.

## Data

- **Accounts** (`GET /v1/accounts?withBalance=true`): `ownerName` is always sent (no extra consent
  needed), plus `name`, `product`, `cashAccountType`, `bic`. Accounts are identified by IBAN only.
- **Balances:** `closingBooked` and `interimAvailable`.
- **Transactions: camt.052 only** (IO31: JSON transactions "NO"). The SDK asks with
  `Accept: application/xml` (`Profile.XMLTransactions`) and parses every `Ntry`
  ([camt.go](../internal/berlingroup/camt.go)). Amount signed from `CdtDbtInd`; `Sts` BOOK/PDNG;
  `AcctSvcrRef` as the id; counterparty from `RltdPties` (creditor for debits, debtor for credits);
  `Ustrd` lines as remittance; `CdtrRefInf/Ref` as the reference; `BkTxCd` as `BankCode`
  (`PMNT-RCDT-ESCT`, else the German GVC such as `NTRF+166+9310`); `AddtlNtryInf` as
  `BankCodeText`. An entry with several transactions (a batch) keeps only the entry's data. Each
  transaction's `Raw` is the entry's XML as a JSON string; the page's `Raw` is the whole document.
- `bookingStatus` booked, pending and both. Pending entries exist only for the current day; dates are
  ignored for them. `information` (standing orders, JSON) is not used.
- `dateFrom` defaults to 90 days back. Only the first transactions call after the consent may reach
  further back; later calls are cut to 90 days. Sparkassen can limit history per channel, and a longer
  request then returns what is allowed.
- `deltaList`, `entryReferenceFrom` and paging: camt has no continuation, so the page never has a
  next cursor. `withBalance` is not supported on transactions.

## Payments

| Type | Product | Notes |
|---|---|---|
| `sepa` | `sepa-credit-transfers` | `execution_date` for future-dated payments |
| `sepa_instant` | `instant-sepa-credit-transfers` | today only |

- The debtor IBAN is required. No structured creditor reference: the shape Finanz Informatik expects
  is not documented in the package, so the spec leaves it out. Creditor address and BIC are optional.
- Statuses: `RCVD` until approved; `ACCP`, `ACTC`, `ACSC`, `ACCC`, `PART`; `PATC` for an instant
  payment not yet fully executed; `RJCT` with the reason in `psuMessage` ("{No.} - {Text}"), which the
  SDK puts in `Payment.Reason`.
- **Cancellation:** a payment that is not approved yet can be deleted (`CancelPayment`; IO43 allows it
  for every single-payment product before authorisation). An approved one can't (`Cancellable: false`):
  after authorisation IO43 allows it only for pain.001 single payments and periodic payments, so a
  future-dated JSON payment stays.
- Not implemented: `target-2-payments` and `cross-border-credit-transfers` (field shapes not in the
  package), the pain.001 products, bulk payments (also instant), periodic payments, multilevel SCA
  (a second signature: the redirect then returns its code only after the last one).

## Errors

The adapter's Berlin Group mapping applies: `CONSENT_EXPIRED`, `CONSENT_INVALID`, `CONSENT_UNKNOWN` →
`ReauthError`; `ACCESS_EXCEEDED` → rate limited; wrong PIN or TAN during authorisation
(`PSU_CREDENTIALS_INVALID`, `SCA_INVALID`) → `ErrAuthFailed`; `RJCT` → `PaymentRejectedError`.

## Sandbox

The sandbox needs a PSD2 test QWAC from one of the trust centres Finanz Informatik lists; there is no
registration. Its behaviour is driven by fixed values (sandbox configuration of 2019-09-11):

| What | Values |
|---|---|
| PSU-IDs | `chipTAN`, `smsTAN_singleMed`, `smsTAN_multiMed`, `pushTAN_singleMed`, `pushTAN_multiMed`, `chipTAN_noSCA`, `smsTAN_noSCA`, `iTAN` (unsupported type), `blockedUser`, `pushDecTAN` (pushTAN 2.0) |
| PIN | `okok1` valid, `nok12` invalid |
| TAN | `111111` valid, `123456` invalid, `999999` blocked |
| IBANs | `DE86999999990000001000` (available, balances and transactions), `DE59…1001` (transactions only), `DE12…1002` (banking error / no transactions), `DE05…1003` (no rights), `DE75…1004` (no funds), `DE48…1005` (limit exceeded), `DE75…1006` (no funds, batch), `DE98999999990000009999` (receiving) |
| Consent ids | revoked `30e736a3-…`, invalid `e7d8705b-…`, expired `03adae3b-…`, access exceeded `0b1f5a41-…` |

The sandbox's transactions differ from production: always 90 days, a 0.00 EUR opening balance and one
booked 1 EUR entry per day; pending entries and standing orders are static. Its test IBANs use bank
code `99999999`; whether other codes work there is not documented.

```sh
cp banks/sparkassen/sandbox.env.example banks/sparkassen/sandbox.env   # fill in
set -a; . banks/sparkassen/sandbox.env; set +a
go run ./cmd/obdev connect -method embedded     # PSU-ID chipTAN, PIN okok1, TAN 111111
go run ./cmd/obdev connect                      # redirect (OAuth): paste the callback URL
```

## Verified

Nothing against the real sandbox yet: no test QWAC. All variants are `experimental` (sandbox) or
`unverified` (production). Covered offline:

- The adapter's OAuth SCA approach, bank-code routing and camt parsing against a fake bank and in unit
  tests (`internal/berlingroup/oauth_test.go`, `camt_test.go`).
- Hand-written scenarios in `banks/sparkassen/testdata`, built from the handbooks' examples and the
  sandbox configuration: `de-hand-redirect-connect` (OAuth with PKCE, token, accounts),
  `de-hand-redirect-refused`, `de-hand-embedded-pushtan-decoupled` (PUSH_DEC → decoupled polling),
  `de-hand-embedded-wrong-pin`, `de-hand-data` (accounts, balances, camt.052 booked and pending,
  refresh with the refresh token), `de-hand-consent-expired`, `de-hand-embedded-pay-chiptan`
  (chipTAN optical challenge), `de-hand-pay-no-funds`.

Assumed and to check on the first sandbox run: the OAuth server's real paths and whether its token
endpoint wants anything beyond the handbook's four fields; the exact camt.052 version and whether
several reports arrive in one body; the field names Finanz Informatik expects for addresses and
structured references; the sandbox's accepted bank codes; consent validity limits (90 days are asked).
