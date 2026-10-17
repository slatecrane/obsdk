# Handelsbanken integration notes

Handelsbanken runs its PSD2 APIs from one developer portal for Sweden, Great Britain, the Netherlands
and Luxembourg. The integration registers personal and business customers in SE, GB and NL, and
personal customers in LU, for account information and payments. Handelsbanken Norway has its own
portal, run by a service partner, and is not covered.

| | Sandbox | Production |
|---|---|---|
| API | `https://sandbox.handelsbanken.com/openbanking` | `https://api.handelsbanken.com/openbanking` |
| Token endpoint | `{API}/oauth2/token/1.0` | `https://api.handelsbanken.com/mlurd/oauth2/token/1.0` |
| Client authentication | `X-IBM-Client-Id` header (+ `client_id` in token requests) | the same, over mutual TLS |
| Certificate | none | QWAC (or UK OBWAC), via `Config.HTTPClient` |
| User login | none: `X-Sandbox-User` header names the test user | Handelsbanken's login page, or Mobile BankID |

Built from the portal's technical guidelines, the sandbox guides, the attribute and payment
implementation documents (PDF), and the OpenAPI documents shown after login (Consents 1.1.0,
Accounts 2.1.30, Accounts GB / NL / LU, Payments SE Private and Corporate 2.0.3, Payments GB / NL /
LU).

## What the integration needs

`Info.Requirements` lists these; `banks/handelsbanken/sandbox.env.example` shows where each comes from.

- `client_id` of an app on developer.handelsbanken.com. The sandbox issues 32 hex digits, production
  a UUID. The app also gets a secret, which the API never uses.
- The app must be subscribed to every product used: Consents, Account Information (and the GB, NL,
  LU variants), Payment Initiation SE Private / SE Corporate / GB / NL / LU.
- `redirect_url`: the app's one registered redirect URI (only one per app).
- Production: the QWAC as the mTLS client certificate in `Config.HTTPClient`, after enrolling through
  the Third Parties and Subscriptions APIs (not part of the SDK).
- Sandbox: `Config.Extra["sandbox_user"]`, a user from the sandbox test data
  (`SANDBOX-INDIVIDUAL-SE-1`, `SANDBOX-CORPORATE-NL-2`, ...).

## Paths per country

| | Consent | Accounts | Payments |
|---|---|---|---|
| SE | `POST /psd2/v1/consents` + `Country: SE` | `/psd2/v2/accounts` + `Country: SE` | `/psd2/se/v2/payments/{private\|corporate}/...` |
| GB | `POST /psd2/gb/v1/consents` | `/psd2/gb/v1/accounts` | `/psd2/gb/v1/payments/{product}` |
| NL | `POST /psd2/nl/v1/consents` | `/psd2/nl/v1/accounts` | `/psd2/nl/v1/payments/{product}` |
| LU | `POST /psd2/lu/individual/v1/accounts/consents` | `/psd2/lu/individual/v1/accounts` | `/psd2/lu/v1/payments/{product}` |

Every API call carries `X-IBM-Client-Id`, `TPP-Request-ID` and `TPP-Transaction-ID`, and
`PSU-IP-Address` when known. Business calls that create something carry `PSU-Corporate-ID` and
`PSU-Corporate-ID-Type: BANK`.

## Flows

**Connect**:

1. Client credentials token: `POST {token}` with `grant_type=client_credentials&scope=AIS&client_id`.
   Fetched per operation (clients are stateless); it lasts 24 hours.
2. Consent: `POST .../consents` with `{"access": "ALL_ACCOUNTS"}` (the only value). Business: the
   company id goes in `PSU-Corporate-ID` (SE: 10-digit organisation number, NL: 6-digit corporate
   number, GB: the literal `UNKNOWN`). Without one, `Connect` first returns an input step asking
   for `corporate_id`. The response has `consentId` and `scaMethods` with the authorisation links.
3. Approval, with the link of the chosen method:
   - **Redirect** (all countries, the default): the link plus `response_type=code`,
     `scope=AIS:<consentId>`, `client_id`, `state`, `redirect_uri`. The callback brings `code`, which
     is exchanged with `grant_type=authorization_code` and the same `scope`.
   - **Decoupled** (Sweden only, Mobile BankID): `POST` the link with `client_id`, `scope`,
     `psu_client_ip`, `psu_id` (the personnummer, optional; not for business) and
     `bisa_same_device: true`. The answer has `auto_start_token` (or `qr_code`), `sleep_time` and a
     token link. The SDK polls that link (a `StepWait` with `WaitFor` = `sleep_time`) until `result`
     is `COMPLETE`, which carries the tokens. `outstandingTransaction`, `noClient`, `started` and
     `userSign` mean "still waiting"; an `error` (`mbid_user_cancelled`, `mbid_transaction_expired`,
     ...) is `ErrAuthFailed`.
4. Accounts: `GET .../accounts`.

**Refresh**: `grant_type=refresh_token`. The refresh token does not rotate.

**Disconnect**: the Consents API only creates consents. There is no call to read or delete one (the
sandbox answers `404` to both), so `Disconnect` drops the tokens and reports the consent under
`Failed`. The consent stays valid at the bank until it expires or the user withdraws it there.

## Behaviors worth knowing

- **Consent lifetime** is fixed by the bank: 180 days, 90 in GB. The request has no validity field.
- **Balances** come with the account (`GET .../accounts/{id}?withBalance=true`, also inline in the
  list): `AVAILABLE_AMOUNT` (interim available; includes reservations and credit), `CURRENT` (interim
  booked), `VALUE_DATE` and `CLEARED` (GB business; both `other`).
- **Account numbers**: `iban`, plus `bban` and `clearingNumber`. In Sweden the SDK's `BBAN` is
  clearing number + account number (the full Swedish account number); elsewhere it is the bank's
  `bban`. `accountType` is the product name ("Privatkonto", "Checkkonto"); `ownerName` the owner.
- **Transactions**: `dateFrom` / `dateTo` as `YYYY-MM-DD` (SE, GB, LU). Each one has
  `creditDebit` (`CREDITED` / `DEBITED`; the SDK signs the amount), `status` (`BOOKED` /
  `PENDING`), `remittanceInformation`, the balance after it, and outside GB `debtorName` /
  `creditorName` (the counterparty). GB has only `valueDate`. Dates may come as ISO timestamps;
  the SDK keeps the date.
- **No pagination**: a request is capped (SE personal: 1000 items or 24 months, corporate up to
  2900) and answered `206` with a message to narrow the dates. `NextCursor` stays empty unless a
  `next` link ever appears.
- **Errors**: the gateway answers `{"httpCode", "httpMessage", "moreInformation"}`; the token
  endpoints answer OAuth style. 401 on a data call → `ErrAccessExpired`; 403 → `ErrReauthRequired`;
  a failed refresh → `ErrReauthRequired`; 429 → `ErrRateLimited`.

## Payments

The TPP creates the payment with a client credentials token (`scope=PIS`). The user approves it like
a consent, with the scope `PIS:<id>`, by redirect or (Sweden) Mobile BankID. The token from that
approval executes the payment with a `PUT`. The status is read with a client token, so
`PaymentStatus` needs no session.

| SDK type | Where | Product | Payee | Notes |
|---|---|---|---|---|
| `domestic` | SE, both segments | `sek-credit-transfer` in a **signing basket** | IBAN (Swedish), BBAN (clearing + account), BANKGIRO, PLUSGIRO | Up to 30 transfers (business 100) with one approval. A message or an OCR reference (1-140) is required. Payee name required for IBAN / BBAN. |
| `internal` | SE, both segments | `handelsbanken-domestic-credit-transfer` | a Handelsbanken account | Any currency. The message (max 14) is shown on both accounts. |
| `sepa` | SE business | `sepa-credit-transfer` | IBAN | Payee town and country required; `chargeBearer` must be `SHAR`. |
| `sepa` | NL (both), LU | `sepa-credit-transfer` | IBAN | `chargeBearer` `SLEV`; NL business takes an end-to-end id; LU takes a date, NL does not. |
| `domestic` | GB | `british-domestic-credit-transfer` | SORT_CODE_ACCOUNT | Faster Payments. Reference max 18, characters `A-Z a-z 0-9 . - /`. Payee country defaults to GB. |

- The payer account is required everywhere. In Sweden it is a Handelsbanken account; the SDK takes
  clearing + account number, the bare 8-9 digits, or the IBAN, and sends the 8-9 digits.
- A basket is one SDK payment: `Payment.ID` is the signing basket id. The basket answers
  `SUCCEEDED`, `FAILED` or `PARTIAL_FAILURE`; the SDK reads each transfer's status and sums them up
  (the least advanced status; `partially_accepted` when some were rejected).
- **Statuses**: `ACTC` is a created payment that waits for approval (received); after execution
  `ACCP` (accepted), `ACSC` / `ACCC` (completed), `RJCT`, `CANC`.
- **Cancel** (Sweden, a payment with one transfer, not executed yet, i.e. future-dated):
  `POST .../{product}/{paymentId}/cancellation-authorizations` with the payment's original payload
  (the bank requires it), the user approves `PIS:<cancellationId>`, then `PUT` executes it. The
  payload travels in `Payment.Ref`, so the ref holds the account numbers and names of the payment.
- Not implemented: cross-border (`cross-currency-credit-transfer`: needs the payer's phone or e-mail
  and central bank reporting codes), personal SEPA in Sweden (also through cross-currency),
  `other-bank-domestic-credit-transfer` (immediate debit; the basket covers the same payees),
  short-term consents, Confirmation of Funds, card accounts, and PIS API v1 (switched off on
  2026-11-15).

## Verified against the real sandbox (2026-10-17)

Every sandbox variant is registered as `sandbox_verified`; production stays `unverified`.

The sandbox needs no login. The authorize call answers at once with a `302` to the redirect URI, so
the SDK calls it itself with `X-Sandbox-User` and hands the callback URL over as the redirect step.
Mobile BankID always completes. Business consents take the sandbox user's name as the company id.

Scenarios (`banks/handelsbanken/testdata/`):

- `live-se-personal`, `live-se-business`, `live-gb-personal`, `live-gb-business`,
  `live-nl-personal`, `live-nl-business`, `live-lu-personal`: connect (redirect), accounts,
  balances, transactions; SE personal also refresh.
- `live-se-personal-decoupled`: connect with Mobile BankID.
- `live-se-pay-bankgiro`: a basket with one Bankgiro + OCR transfer, approved with BankID, `ACCP`.
- `live-se-pay-cancel`: a future-dated payment to a Swedbank account (`ACCP`), cancelled (`CANC`),
  status read.
- `live-se-pay-internal`: a transfer between the user's accounts, `ACCC`.
- `live-se-business-pay-sepa`, `live-nl-pay-sepa`, `live-lu-pay-sepa`, `live-gb-pay-domestic`:
  created, approved, executed (`ACCP`, LU `ACSC`).

Also run without recording: a business basket payment to Bankgiro + OCR (`ACCP`), refresh in other
variants, and Disconnect.

Observed:

- Sandbox client ids are 32 hex digits; the token endpoint issues tokens for any client id, the API
  gateway then refuses unknown ones (`401 "Invalid client id or secret."`).
- Account and AIS tokens: `expires_in` 86400; payment tokens 900. The sandbox's tokens never expire.
- The sandbox's data is static: every SE personal account holds 100 000.00 and gets one transaction
  a day.
- The NL sandbox rejects `dateFrom` / `dateTo` in every format tried (`YYYY-MM-DD`, `YYYYMMDD`, ISO
  timestamps): `400 "Invalid date format (dateFrom)"`. In the NL sandbox the SDK leaves the dates out
  and filters itself; production gets them like elsewhere.
- The LU sandbox writes amounts as `{"amount", "currency"}` in objects named `balanceAmount` /
  `transactionAmount`, against its spec (`amount: {"content", "currency"}`). The SDK reads both. Its
  transactions have no amount at all, and its `VALUE_DATE` balance no amount (skipped).
- A business consent with a company id the sandbox doesn't know fails with `500 "Unexpected
  error"`; `UNKNOWN` outside GB gives `400 "Invalid PSU-Corporate-ID."`.
- Cancelling a business payment fails in the sandbox with `500 "Internal server error occurred."`,
  even with the documented payload; personal cancellations work.

## Still assumed

- Production: the login page behind the authorisation link, BankID with real apps, the token
  endpoint on `/mlurd/`, mutual TLS. Error bodies other than the gateway's.
- Pending transactions, `206` responses and the item caps: the sandbox shows none.
- Business cancellation (sandbox error above), NL transaction dates in production.
- GB business payments: built like personal ones, not run.
