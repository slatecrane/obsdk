# Revolut integration notes

Revolut's Open Banking API follows the UK OBIE Account and Transaction API. The same API serves UK
customers and EEA customers (Revolut's EEA entity), so the integration registers GB and the EEA
countries, personal and business. Sandbox and production differ only in hosts and certificates:

| | Sandbox | Production |
|---|---|---|
| API (token, consents, accounts) | `https://sandbox-oba-auth.revolut.com` | `https://oba-auth.revolut.com` |
| Consent page | `https://sandbox-oba.revolut.com/ui/index.html` | `https://oba.revolut.com/ui/index.html` |
| Server certificate | OpenBanking Pre-Production Root CA (embedded) | public CA |
| Client certificates | issued by Revolut from your CSR | OBIE or eIDAS QWAC / QSealC |

Built from the public API reference and the "Get account and transaction information" tutorial.

## What the integration needs

`Info.Requirements` lists these; `banks/revolut/sandbox.env.example` shows where each comes from.

- `client_id` from the developer portal (one per environment). No client secret: the client
  authenticates with mTLS (`tls_client_auth`).
- `redirect_url`, registered in the portal without variable parameters.
- **Transport certificate** for mTLS on every call, `/token` included. Build the HTTP client with
  `revolut.HTTPClient(env, tlsCert)`: it presents the certificate and, in the sandbox, trusts the
  OpenBanking Pre-Production Root CA (`revolut.SandboxRoots()`), which no system trust store has.
- **Signing key** (`Config.Seal`, RSA): signs the request object with PS256. `Seal.KeyID` must be the
  `kid` of the key in the **JWKS URL registered in the portal**; Revolut fetches the public key from
  there. `go run ./cmd/obdev jwks` prints a JWKS for the configured key.

## Flows

**Connect** (redirect only):

1. `POST /token` `grant_type=client_credentials`, `scope=accounts` → client token (about 40 minutes).
2. `POST /account-access-consents` with permissions derived from the requested capabilities
   (accounts: `ReadAccountsBasic`, `ReadAccountsDetail`; balances: `ReadBalances`; transactions:
   `ReadTransactionsBasic|Detail|Credits|Debits`). `ExpirationDateTime` is sent only when
   `ConsentValidityDays` is set; otherwise the consent lasts as long as the refresh token.
3. Request object: JWT with `response_type=code id_token`, `client_id`, `redirect_uri`,
   `aud` = API host, `scope=accounts`, `state`, `nbf`, `exp` (30 minutes; Revolut allows at most 60),
   and `claims.id_token.openbanking_intent_id.value` = consent id.
4. Redirect to the consent page with `response_type`, `client_id`, `redirect_uri`, `scope`, `request`
   **and `state`**.
5. Callback `?code=...&id_token=...&state=...` → `POST /token` `grant_type=authorization_code`.
   The code is valid for two minutes.
6. `GET /accounts`; the session and accounts come back on `StepDone`.

**Data**: `GET /accounts`, `/accounts/{id}/balances`, `/accounts/{id}/transactions` with
`x-fapi-financial-id: 001580000103UAvAAM`, an `x-fapi-interaction-id`, and the PSU's IP / user agent
when given.

**Refresh**: `POST /token` `grant_type=refresh_token`. Refreshing invalidates the previous access token.

**Disconnect**: new client token, then `DELETE /account-access-consents/{id}`.

## Behaviors worth knowing

- Several currency accounts share one IBAN and sort code. `Account.ID` (`AccountId`) is unique per
  currency; `StableID` includes the currency (as for every bank).
- Amounts are unsigned with `CreditDebitIndicator`; the SDK signs them. The counterparty is the
  creditor of a debit and the debtor of a credit, falling back to `MerchantDetails.MerchantName`.
  `SupplementaryData.StartedDate` (offline card payments) becomes `TransactionDate`.
- The API returns booked and pending transactions together; the SDK filters by `TxQuery.Status`
  (booked only by default).
- **Pagination.** The docs page backwards in time: the next page is requested with
  `toBookingDateTime` = the oldest `BookingDateTime` of the current page (exclusive, second
  precision). `Links.Next` is documented as optional. The SDK uses `Links.Next` when present,
  otherwise an opaque cursor that asks for one second more and skips transactions it already returned
  from that second, so nothing is duplicated or lost at page boundaries. A listing ends with a request
  that returns nothing new. Limit: if a single second holds more transactions than one page, the rest
  of that second can't be requested.
- 401 on a data call means an expired token *or* a revoked consent (same code and text). The SDK
  reports `ErrAccessExpired`; the following refresh fails with `ErrReauthRequired` if the consent is gone.
- The `id_token` in the callback is not validated; the code exchange over mTLS authenticates the result.

## Verified against the real sandbox (GB personal, 2026-10-14)

The GB personal sandbox variant is registered as `sandbox_verified` (scenarios `live-gb-*`). Other
sandbox variants stay `experimental`; production variants stay `unverified`.

- Client-credentials token, consent creation, consent page, code exchange, accounts, balances,
  transactions, refresh and disconnect all work as described above.
- The sandbox API's server certificate chains to the OpenBanking Pre-Production Root CA.
- The sandbox and production certificates come from one CSR: `transport.der` and `signing.der` share
  `private.key`.
- **Without a JWKS URL in the portal**, the consent page accepts the request, lets the user sign in,
  and then fails with "Oops! An error occurred while processing your request". Registering the JWKS
  (kid `obsdk-sandbox`) fixed it.
- **`state` must also be in the consent page's query.** With `state` only inside the request object,
  the sandbox redirects back with `state=null`.
- The sandbox test user signs in with a phone number and passcode and is shown a confirmation code.
- Token responses: client token `expires_in: 2399`; user token `expires_in: 3599`, plus
  `refresh_token_expires_at` 50 years out (UK) and an `access_token_id`. Refresh returns no new
  refresh token.
- Balances: one `InterimAvailable` balance per account.
- After disconnect, data calls get `401 UK.OBIE.Resource.Unauthorized` "Access token is invalid or
  expired" and refresh gets `401 UK.OBIE.Resource.Unauthorized` "Unable to validate refresh token".

## Payments

OBIE v3.1 payment initiation, from Revolut's "Initiate your first payment" and "Work with JSON Web
Signatures" guides.

| SDK type | Countries | Endpoints |
|---|---|---|
| `domestic` | GB | `domestic-payment-consents` / `domestic-payments` (GBP, `UK.OBIE.SortCodeAccountNumber`) |
| `sepa` | EEA | the same domestic endpoints in EUR (`UK.OBIE.IBAN`) |
| `crossborder` | all | `international-payment-consents` / `international-payments` |
| any, with `execution_date` | | the `-scheduled-` variants (`Permission: Create`, `RequestedExecutionDateTime` at 12:00 UTC); beta at Revolut |

Flow:

1. Client token with `scope=payments`.
2. `POST ...-payment-consents` with `x-idempotency-key` and `x-jws-signature`.
3. Request object with `scope=payments`, then redirect.
4. The callback's code is exchanged for a payment token (valid 24 hours).
5. `POST ...-payments` with the consent's `Initiation` and `Risk` byte for byte, signed again.
6. Status: `GET ...-payments/{id}` with a client token.

Cancellation is not offered.

- **Body signature**: a detached JWS (`header..signature`) over the exact body bytes.
  - The header is `typ: JOSE`, `alg: PS256`, `kid`, `crit: ["http://openbanking.org.uk/tan"]`, plus
    that claim set to the root domain of the JWKS URL.
  - The SDK takes the domain from `Config.Extra["jws_tan"]`. Revolut wants the JWKS URL's full host:
    the sandbox rejected `githubusercontent.com` (`400 Invalid 'http://openbanking.org.uk/tan'
    signature header value`) and accepted `raw.githubusercontent.com`.
  - The JWKS key must carry `x5c` with the signing certificate (`obdev jwks` adds it).
- **Remittance**: one line, sent as `RemittanceInformation.Reference`, the reference the payee sees. It is
  at most 18 characters for GBP (Faster Payments) and 35 otherwise. End-to-end ids are at most 31
  characters for Faster Payments. Generated ids are shortened UUIDs.
- **Consent**: consumed by the first payment attempt, whatever its outcome.
- **Statuses**:
  - `Pending` → accepted; `AcceptedSettlementInProcess` → in progress;
    `AcceptedSettlementCompleted` → completed (final); `Rejected` → rejected (final).
  - Scheduled payments only report `InitiationPending/Completed/Failed`, that is, whether the
    schedule was set up.

Sandbox (2026-10-14): once the portal app had the payments scope, a GBP domestic consent was
accepted with the signature above. The approval and payment submission are not recorded yet.

## Still assumed

- **Transactions**: the sandbox test user has three empty accounts (GBP, USD, EUR), so transaction
  mapping and pagination were tested only against the documented schema (`revolut_test.go`), not real
  data. Whether the API sends `Links.Next`, and its page size, are unknown.
- Business accounts, EEA customers and production are unverified.
- Error bodies other than the 401s above (400 permission errors, 403, 429) are mapped from the
  documented OBIE shape.
