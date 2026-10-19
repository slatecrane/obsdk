# Samlink integration notes (Säästöpankki, Oma Säästöpankki; Finland)

Samlink runs the PSD2 interface of two Finnish savings-bank groups, about 0.7M customers together:

| Bank key | Bank | Production API | OAuth (production) |
|---|---|---|---|
| `saastopankki` | Säästöpankki (Savings Banks Group: Säästöpankki Optia, Myllykosken Säästöpankki and the other member banks) | `https://sp-psdapi.samlink.fi/psd2` | `https://authservice.samlink.fi/sp/oauthproxy/…` |
| `omasp` | Oma Säästöpankki | `https://omasp-psdapi.samlink.fi/psd2` | `https://authservice.samlink.fi/omasp/oauthproxy/…` |

Both are registered by [banks/samlink](../banks/samlink) on the generic Berlin Group adapter
([berlin-group.md](berlin-group.md)), FI, personal and business. POP Pankki left Samlink in May 2026 and
is now on Crosskey ([crosskey.md](crosskey.md)).

Built and run against the sandbox on 2026-10-19 from Samlink's developer portal: the technical
documentation (`/tech-doc`), sandbox documentation (`/sandbox-doc`), FAQ and, after login, the API pages
(PSD2 API v1 and v2, Sandbox-oauth, Sandbox-management).

| | Sandbox | Production |
|---|---|---|
| API | `https://sml-prod-psd2.azure-api.net/psd2` (both banks) | per bank, above |
| App key | `Ocp-Apim-Subscription-Key` (portal subscription key) | `apikey` (from the TPP registration API) |
| mTLS | none | none (Samlink does not require a QWAC) |
| Signature | none | QSealC: Digest, Signature (`rsa-sha256`, `keyId="SN=…,CA=…"`), `TPP-Signature-Certificate` |
| Token endpoint auth | HTTP Basic (client id and secret from the sandbox registration) | `private_key_jwt` signed with the QSealC; client id = the QSealC's organizationIdentifier |
| Approach | OAuth redirect (`scaOAuth`) | same |
| Data | dynamic: payments show up as pending transactions | real |

## Access

- **Sandbox:** free. Sign up on https://developer.samlink.fi, subscribe to the APIs (Get Started →
  Subscribe) and copy the subscription key from the profile page. Then register an application once:

  ```sh
  curl -X POST https://sml-prod-psd2.azure-api.net/mngmt/management/tpp-register-app \
    -H "Ocp-Apim-Subscription-Key: $KEY" -H 'Content-Type: application/json' \
    -d '{"client_name":"obsdk","client_description":"obsdk","redirect_uris":["https://www.example.com/callback"]}'
  ```

  The answer carries `client_id` and `client_secret`. `POST /mngmt/management/reset` wipes your payments
  and consents; `POST /mngmt/management/execute-future-dated-payments` (optional `dateUntil` header)
  executes dated payments.
- **Production:** register with the TPP registration API (`PUT https://reg.samlink.fi/tpp-registration/v1/tpp/{organizationIdentifier}`,
  signed with the QSealC, body `{"shortName": …}`), which returns the API key; then register the QSealC
  (`POST /tpp-registration/v1/certificate`). Not done: we have no QSealC.

## Flows

- **Consent:** `POST /v2/consents` with empty `accounts`, `balances` and `transactions` lists (Samlink
  refuses `allPsd2`/`allAccounts`); the user picks the accounts at the bank. `validUntil` at most 180 days
  ahead (the sandbox refuses more, the documentation says it clamps), `frequencyPerDay` at most 4. The
  answer has a `scaOAuth` link to RFC 8414 metadata; the user approves at `authorization_endpoint` with
  scope `AIS:<consentId>`, and the code is exchanged at `token_endpoint` (with PKCE). Account calls carry
  the bearer token and `Consent-ID`; `Refresh` checks the consent status and uses the refresh token.
- **Payments:** `POST /v1/payments/sepa-credit-transfers`, then the same OAuth redirect with scope
  `PIS:<paymentId>`. The code is not exchanged; the status decides. The debtor account is optional (the
  user picks it at the bank). `requestedExecutionDate` makes a dated payment, 1 day to 5 years ahead.
- **Disconnect:** `DELETE /v2/consents/{id}` (status `terminatedByTpp`).

## How Samlink differs from the standard

Handled by profile knobs of the adapter:

- **Two path versions:** consents, accounts, card accounts and funds confirmations are on `/v2`, payments
  on `/v1` (`AISPathVersion`). `/v1` AIS still answers but is the older version.
- **Bank-offered consent** only (`ConsentBankOffered`).
- **Token endpoint authentication** (`OAuthClientAuth`): HTTP Basic plus the subscription key in the
  sandbox, a `private_key_jwt` client assertion in production (RS256, `iss` = `sub` = client id,
  `aud` = token endpoint, `jti`, `iat`, `exp`; Samlink refuses repeated header keys, so the header is just
  `alg`, `typ` and the seal's `kid` when set). The production assertion is built from the documentation and
  unit-tested only.
- **The payment reference is `endToEndIdentification`** (`ReferenceInEndToEnd`): a Finnish reference
  (viitenumero, `obsdk.ReferenceFI`) or RF. The spec offers the reference instead of an end-to-end id.
  Either a reference or a message is required.
- **Transactions** (`EntryReferencePaging`): booked and pending are separate queries (`both` is refused:
  "Available values : booked, pending"). Booked ones come in blocks of 100; the response names
  `relevantEntryReference` (spelled `relevantEntryreference` in the documentation; both are read), which
  the next request sends as `entryReferenceFrom`, without dates. A date range needs both `dateFrom` and
  `dateTo`, so `dateTo` defaults to today. Pending ones come in one page without date filtering, so no dates
  are sent. The cursor is emitted only when a booked page has transactions.
- **Unsigned pending amounts:** pending payments come with a positive amount and no
  `creditDebitIndicator`, also when they leave the account. The adapter treats an unsigned transaction whose
  debtor account is the queried account (and whose creditor is not) as a debit.
- **`X-Request-ID` must be a lower-case UUID** ("must be a valid UUID" otherwise); `Config.NewID`'s
  default is.

## Limits

- 4 unattended account reads per consent and day; reads with `PSU-IP-Address` (the user present) are not
  counted, nor are follow-up pages with `entryReferenceFrom`.
- Transactions older than 90 days only in the first 5 minutes after approval (then up to 12 months back).
- Single payments cannot be cancelled (`DELETE` works only for periodic payments, which the SDK does not
  create).
- Card accounts (`/v2/card-accounts`) exist (the sandbox users have two cards each) but the adapter does
  not read them yet.
- Cross-border payments (`/v1/payments/cross-border-credit-transfers`) and periodic payments are not
  offered yet.

## Payments

`sepa` (EUR), optionally dated. Statuses: `RCVD` → `ACFC` (funds checked, being processed; SEPA Instant
in flight) → `ACSC` (done). `PDNG` is pending, `ACSP` is how a dated payment waits, `RJCT` rejected.

## Sandbox

Test users, picked from a list on the sandbox login page (no password):

| User | Bank | Accounts |
|---|---|---|
| SPSandbox Customer-01 | `saastopankki` | FI3745760010038400, FI3645760010038418 |
| SPSandbox Customer-02 | `saastopankki` | FI1445760010038426, FI8945760010038434 |
| OmaSpSandbox Customer-01 | `omasp` | FI1545370010011413, FI9045370010011421 |
| OmaSpSandbox Customer-02 | `omasp` | FI8945370010011439, FI6745370010011447 |

The login and approval pages are plain HTML forms (Spring OAuth), so they can be driven with curl:
`POST /samlink-api-sandbox/login` with `username=<user>&password=password`, then
`POST /samlink-api-sandbox/oauth/authorize` with `user_oauth_approval=true` and `scope.<scope>=true`
(`false` to refuse). The redirect's `Location` is the callback.

```sh
set -a; . banks/samlink/sandbox.env; set +a     # OBSDK_BANK=saastopankki or omasp
go run ./cmd/obdev connect
go run ./cmd/obdev pay -type sepa -amount 12.34 -currency EUR -from FI3745760010038400 \
  -to FI1445760010038426 -name 'Test User' -ref FI:1232
```

### Verified on 2026-10-19

- Säästöpankki: connect (2 accounts with balances), accounts, booked and pending transactions, refresh
  (consent status + refresh token), disconnect; SEPA payments with a message, with a Finnish reference,
  dated, and refused at the bank (`access_denied` → `ErrAuthFailed`); payment status `ACFC` → `ACSC`.
- Oma Säästöpankki: connect and a SEPA payment with an RF reference.
- A refused consent ends in `ErrAuthFailed`.

### What the sandbox does not show

- **Booked transactions:** the booked list stays empty, also after payments complete; `relevantEntryReference`
  then holds the last payment's id. Entry-reference paging is built from the documentation and checked
  against a fake server.
- **Dated payments:** `execute-future-dated-payments` rejected the dated payment made without a debtor
  account ("Accepted: 0, Rejected: 1"); not investigated.
- Business customers, card accounts.
- Everything production-only: the `apikey` header, request signing, the client assertion, TPP registration.
