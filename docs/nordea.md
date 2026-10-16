# Nordea integration notes

Nordea runs one PSD2 API for its personal and business customers in Denmark, Finland, Norway and
Sweden. The integration registers the four countries, both segments, for account information.
Payments use the Single SCA API and are registered for personal customers.

| | Sandbox | Production |
|---|---|---|
| API | `https://api.nordeaopenbanking.com` | `https://open.nordea.com` |
| Client authentication | client id + secret headers, HTTP Signature | the same |
| Signing key | the static QSealC from the developer portal | your eIDAS QSealC (enrolled with Nordea) |
| Mutual TLS | no | no |

Built from Nordea's developer documentation (Access Authorisation v5, Accounts v5, Business Accounts v4,
Payments API Single SCA v4, PIS 2SCA for the field rules) and the public Postman collections at
github.com/NordeaOB/swaggers.

## What the integration needs

`Info.Requirements` lists these; `banks/nordea/sandbox.env.example` shows where each comes from.

- `client_id` and `client_secret` of an app on developer.nordeaopenbanking.com. Both go in every
  request (`X-IBM-Client-Id`, `X-IBM-Client-Secret`).
- `redirect_url` registered on the app.
- **QSealC** (`Config.Seal`, RSA): signs every request. No certificate is sent; Nordea identifies the
  key through the app. In the sandbox, use the static key from the portal's zip (`.p12`, password
  `1111`). Its certificate expired in 2021, but the sandbox still accepts its signatures.

## Request signing

An HTTP Signature (draft-cavage) in the `Signature` header:

- `keyId` is the client id, `algorithm="rsa-sha256"` (PKCS #1 v1.5).
- Signed headers: `(request-target) x-nordea-originating-host x-nordea-originating-date`, plus
  `content-type digest` when there is a body. `(request-target)` is the lower-case method plus path
  and query.
- `X-Nordea-Originating-Host` is the API host; `X-Nordea-Originating-Date` an RFC 7231 date.
- **Form bodies** (token endpoints): the `Digest` is the SHA-256 of the fields sorted by name and
  joined as `name=value` with the values **not** URL-encoded, the way Nordea's Postman script builds
  it. A digest of the encoded body is rejected with `401 error.digest.invalid`.

## Flows

**Connect** (redirect):

1. `POST /{personal|business}/v5/authorize` with `country`, `scope`, `duration` (minutes; the SDK
   sends `ConsentValidityDays`, default 90, at most 180), `redirect_uri`, `state`,
   `account_list: ["ALL"]`. Nordea answers `302` with `Location` = its login page. The client does
   not follow the redirect: `Location` becomes the `StepRedirect` URL.
2. Callback `?code=...&state=...` → `POST /{segment}/v5/authorize/token` (form,
   `grant_type=authorization_code`).
3. Accounts: `GET /personal/v5/accounts` or `GET /business/v4/accounts`.

Scopes: `ACCOUNTS_BASIC` and `ACCOUNTS_DETAILS` always; `ACCOUNTS_BALANCES` and
`ACCOUNTS_TRANSACTIONS` from the requested capabilities.

**Refresh**: `grant_type=refresh_token` on the same endpoint. Refresh tokens are one-time use; each
refresh returns a new one.

**Disconnect**: `POST /{segment}/v5/authorize/token/revoke` with `{"token": <refresh token>}`.

Decoupled login (BankID, Nordea ID app without a redirect) exists at Nordea but is not implemented.

## Behaviors worth knowing

- **Balances** are part of the account: `available_balance` (interim available), `booked_balance`
  (interim booked) and `value_dated_balance` (other). `Accounts` returns them inline; `Balances` reads
  the account details (`GET .../accounts/{id}`).
- **Account ids** are Nordea's `_id`. Account numbers come as `IBAN` and `BBAN_SE` / `BBAN_DK` /
  `BBAN_NO` (scheme `BBAN` in the SDK). The owner is `account_holder` (business) or the `OWNER` role;
  `account_name` becomes `Name`.
- **Transactions**: `from_date` / `to_date` as dates; without them Nordea returns two months. Status
  `billed` is booked, anything else (reservations) pending. `message` (or `narrative`) becomes the
  remittance line, `type_description` the bank code text, `reference` the reference number.
- **Pagination**: the cursor is `continuation_key`. The next link's path differs between the sandbox
  (`/v5/accounts/...`) and production (`/personal/v5/accounts/...`), so only the key is kept and the
  query (with its dates) is rebuilt on each page.
- **History**: 90 days without a new SCA; the consent lasts up to 180 days.
- **Errors**: `{"group_header": {...}, "error": {"failures": [{"code", "description"}]}}`. 401 on a
  data call → `ErrAccessExpired`; 403 → `ErrReauthRequired`; a failed refresh → `ErrReauthRequired`.

## Payments

Single SCA API (personal, v4). The payment is created without a user token; the user's signature on
Nordea's page is the only interactive step.

| SDK type | Country | Endpoint | Creditor schemes | Reference |
|---|---|---|---|---|
| `sepa` | FI | `sepa-credit-transfer` | IBAN | RF |
| `sepa_instant` | FI | `sepa-credit-transfer`, `urgency: express` | IBAN | RF |
| `domestic` | SE (SEK) | `domestic-credit-transfer` | IBAN, BBAN, BANKGIRO (`BGNR`), PLUSGIRO (`PGNR`) | OCR (Bankgiro / Plusgiro only) |
| `domestic` | DK (DKK) | `domestic-credit-transfer` | IBAN, BBAN | RF |
| `domestic` | NO (NOK) | `domestic-credit-transfer` | IBAN, BBAN | KID (scheme `KID`, sent as `OCR`) |

Flow:

1. `POST /personal/v4/payments/authorization/{product}` with `payment` (amount, currency, creditor,
   **debtor** and **external_id** are required) and `authentication` (`state`, `redirect_uri`).
   The response has only links: `redirect` (the signing page) and `status`, which carries the payment id.
2. The user signs; Nordea redirects to `redirect_uri?success=true&state=...&auth_code=...&response_code=...`.
3. `GET /personal/v4/single-sca-payments/{id}/status`, no user token needed.
4. The `auth_code` is exchanged for a token (the same token endpoint as login). The SDK returns it as
   `Step.Session`: Nordea deletes payments only with that token.
5. Cancel: `DELETE /personal/v4/single-sca-payments` with `{"payments": [{"payment_id"}]}` and that
   token, for payments not executed yet (future-dated). `CancelPayment` needs the session from step 4.

- `success` other than `true` → `ErrAuthFailed` (with the payment); `Rejected`, `InsufficientFunds`,
  `LimitExceeded` → `*PaymentRejectedError`.
- Statuses: `PendingUserApproval` and the `UserApproval*` statuses → received; `Confirmed` →
  accepted; `OnHold` → in progress; `Paid` → completed; `Cancelled`, `Stopped`, `Deleted` →
  cancelled (the sandbox reports `Deleted`, which Nordea's table doesn't list).
- A message and a reference can't be combined (FI, DK, SE giro); the SDK rejects the request before
  sending it. Plusgiro messages are at most 25 characters. The payee name is not sent for Bankgiro.
- Not implemented: cross-border (needs a structured address and BIC), own transfers, Danish giro
  forms, recurring payments, business payments (a separate API with agreement selection), the 2SCA
  API and decoupled BankID signing.

## Verified against the real sandbox (2026-10-16)

The FI sandbox variants (personal and business) are registered as `sandbox_verified`. Other sandbox
variants stay `experimental`; production stays `unverified`.

The sandbox needs no test user: `POST /authorize` redirects straight back to the redirect URI with a
code, and payment signing goes through a mock page (`/personal/nasa-mock/ssca/...`) that redirects
back by itself.

Scenarios (`banks/nordea/testdata/`):

- `live-fi-personal-connect`, `live-fi-personal-data`: connect (3 accounts), accounts, balances,
  transactions with `from_date`, and a second page through `continuation_key`.
- `live-fi-personal-disconnect`: refresh, then revoke.
- `live-fi-business`: business connect (2 accounts on `/business/v4`), balances, transactions.
- `live-fi-pay-sepa`, `live-se-pay-bankgiro`: payment created, signed, status `Paid`; the payment
  token is returned.
- `live-fi-pay-cancel`: future-dated payment (`Confirmed`), then deleted (`Deleted`).

Also run without recording: personal connect and accounts in SE, DK and NO (IBAN plus `BBAN_*`
numbers); FI instant, DK and NO domestic and a NO KID payment, all `Paid`.

Observed:

- The sandbox signature check accepts the expired portal certificate's key, with `keyId` = the
  client id. (The docs also mention a static `clientId` keyId for the sandbox; Nordea's own Postman
  collection records a `401 "KeyId claim doesn't match to Client Id"` for a mismatch.)
- Access tokens: `expires_in` 3599. Payment details also work with the payment token.
- Payment creation without `debtor` or `external_id` is rejected (`error.validation`).
- Status reads carry a sandbox warning ("We are experiencing technical difficulties accessing the
  latest payment details") in `tpp_messages`.

## Still assumed

- Production login pages, account selection and the 302 from `/authorize` (the sandbox redirects
  straight to the callback).
- Pending transactions: every sandbox transaction is `billed`.
- The 90-day limit and its error, 403 handling, rate limits.
- Business payments, cross-border, and SE/DK/NO account information for business customers.
