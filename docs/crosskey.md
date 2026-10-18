# Crosskey integration notes

Crosskey (Ålandsbanken's IT company) hosts the PSD2 APIs of several Nordic banks on
[crosskey.io](https://crosskey.io). Every bank ("store") runs the same UK Open Banking (OBIE) APIs on
its own hosts, so the integration is one `internal/obie` profile per store, in `banks/crosskey`:

| Bank key | Store | Countries, segments | Payments (PIS version) |
|---|---|---|---|
| `spankki` | `s-pankki` | FI personal, business | `sepa`, `sepa_instant` (v3.1.7, international API) |
| `aktia` | `aktia` | FI personal, business | `sepa`, `sepa_instant` (v3.1.7, international API) |
| `poppankki` | `pop` | FI personal | `sepa`, `sepa_instant` (v3.1.7, international API) |
| `alandsbanken` | `alandsbanken-fi` | FI personal | `sepa`, `sepa_instant` (v3.1.7, international API) |
| `alandsbanken` | `alandsbanken-se` | SE personal | `domestic` (v3.1.6: Dataclearing, Bankgiro, Plusgiro) |
| `morrowbank` | `morrowbank` | FI, NO, SE personal | `domestic` (v3.1.6, single only) |
| `resursbank` | `resursbank` | DK, FI, NO, SE personal | none (credit cards, AIS only) |

Business segments are registered only where the bank's docs list business account types (S-Pankki,
Aktia). Account information is OBIE Account and Transaction API v3.1.6 at every store.

Built on 2026-10-18 from the public crosskey.io documentation: the store list
(`https://crosskey.io/api/stores`), each store's API list (`/api/stores/<store>/apis`), the OpenAPI
files behind the API pages (`/api/stores/<store>/apis/<api id>/docs`), the getting-started guide
(`/tutorialDocs`) and Crosskey's Postman collection. S-Pankki FI personal was run against the sandbox
on 2026-10-18 and is `sandbox_verified`, as are Aktia (personal and business), POP, Ålandsbanken FI
and SE, Morrow FI, NO and SE and Resurs DK, FI, NO and SE. S-Pankki business is `experimental`
(see Verified).

## Hosts

| | Sandbox | Production |
|---|---|---|
| API host (token, AIS, PIS) | `https://<store>-api-sandbox.crosskey.io` | per bank, e.g. `https://api.s-pankki.fi` |
| Authorisation page | `https://<store>-sandbox.crosskey.io/open-banking/v4.0/oidc/auth` | per bank, e.g. `https://openbanking.s-pankki.fi/...` |
| Token endpoint | `<API host>/open-banking/v2.0/oidc/token` | the same |
| AIS | `<API host>/open-banking/v3.1.6/aisp` | the same |
| PIS | `<API host>/open-banking/v3.1.7/pisp` (v3.1.6 at Ålandsbanken SE, Morrow) | the same |
| Response signing keys | `<API host>/open-banking/v1.0/oidc/jwks` | the same |

The production hosts are in `stores` in [banks/crosskey/crosskey.go](../banks/crosskey/crosskey.go).

## What the integration needs

- `client_id` and `api_key`: the **Client ID** and **X-API-Key** of an application on crosskey.io.
  The API key goes in `x-api-key` on every API call (not on the token endpoint).
- `redirect_url`: one of the application's redirect URLs; matched exactly.
- **TLS client certificate** for mutual TLS on every call, including the token endpoint, which
  authenticates the client by it (`tls_client_auth`: only `client_id` in the form). Build the client
  with `crosskey.HTTPClient`.
- **Signing key** (`Config.Seal`, RSA, PS256) **with its certificate**: the kid of every JWS is the
  certificate's serial number in decimal (`obie.SerialKeyID`; `Seal.KeyID` overrides it), and its
  subject DN goes into the request object and payment signatures.

In the sandbox, the team page on crosskey.io **generates** a self-signed TLS certificate and a
signing certificate with their keys; no eIDAS certificate is needed. Production needs a QWAC and a
QSealC of the same legal entity, uploaded to the team page; test certificates are refused there.
See [banks/crosskey/sandbox.env.example](../banks/crosskey/sandbox.env.example).

## Flows

**Connect** (redirect; OIDC hybrid flow, FAPI):

1. Client-credentials token, `scope=accounts`.
2. `POST /aisp/account-access-consents` with the permissions and an empty `Risk`.
3. Redirect with `response_type=code id_token`, `scope=openid accounts`, `state`, `nonce`, optional
   `ui_locales` (from `ConnectRequest.Language`; en, fi, sv, no, da) and a PS256 request object. Its
   `openbanking_intent_id` is **`urn:<store>:account:<consent id>`** (`payment` for payments), and
   `exp` must be at most 60 minutes after `nbf` (the SDK uses 30).
4. The callback comes back in the URL fragment. The code must be exchanged **within 30 seconds**
   (`grant_type=authorization_code` with `redirect_uri`).

**Refresh**: `grant_type=refresh_token`. Refresh tokens are single-use; each refresh returns a new
one, which replaces the old one in the session.

**Disconnect**: `DELETE /aisp/account-access-consents/{id}` with a client token.

## Behaviors worth knowing

- **Access tokens last 3 minutes** (`expires_in: 180`). Expect to refresh before most reads.
- **Two levels of access.** A token from the user's authorisation (SCA) reads every transaction the
  consent covers. A refreshed token is "customer authentication" only and reads the last 90 days;
  older ranges answer `403`, which the SDK reports as `ErrReauthRequired`
  (`Limits.HistoryWithoutStepUpDays` = 90). Authorising the same consent again restores full access.
- **Transactions** take `fromBookingDateTime` / `toBookingDateTime`; more pages come as `Links.Next`
  (with `paginationKey`), passed through as the cursor. Pages hold 100 transactions in the sandbox.
- **Resurs** serves four countries from one store: every API call carries
  `x-fapi-financial-id: resursbank/<country>` (`dk`, `fi`, `no`, `se`); without it the API answers
  `400 UK.OBIE.Header.Invalid`.
- **Account schemes**: IBAN for current and savings accounts; cards as `UK.OBIE.PAN`, `UK.OBIE.BBAN`
  (Aktia) or `FI.S-Pankki.CreditCard`; Morrow reports BBANs. Non-IBAN schemes keep their name without
  the `UK.OBIE.` prefix.
- **Balances**: `InterimAvailable` and `InterimBooked`; Resurs only `Expected` (mapped to `other`).
- **Rate limits**: the token endpoint answers `429` with `Retry-After` / `RateLimit-Reset`.
- Responses to payment calls are signed by the bank; the SDK does not verify them yet.

## Payments

OBIE payment consents, approved by redirect, then submitted with the user's token. Every POST is
signed with a detached JWS in `x-jws-signature`:

- header `alg` PS256, `kid` (certificate serial), `b64: false`, `crit` = `b64`,
  `http://openbanking.org.uk/iat`, `/iss` (subject DN), `/tan` (the API host name, e.g.
  `s-pankki-api-sandbox.crosskey.io`);
- the body is signed **unencoded** (RFC 7797), as OBIE did before v3.1.4.

Payment access tokens cannot be refreshed: the submission follows right after the code exchange.

**Finland** (S-Pankki, Aktia, POP, Ålandsbanken FI): SEPA goes through the **international** payment
API, not the domestic one:

- `sepa`: `LocalInstrument` `UK.OBIE.SEPACreditTransfer`, `CurrencyOfTransfer` EUR, payee BIC
  optional; `sepa_instant`: `UK.OBIE.SEPAInstantCreditTransfer`, no BIC.
- Payee name (on the account) is required, 70 characters; message 140; RF reference 35.
- Payee address: since the 3.1.7 change for the EPC rulebook (15 November 2026) it must be
  structured with **town and country**; unstructured lines are refused (the SDK refuses them first).
- `execution_date` uses `international-scheduled-payments` (`Permission: Create`); such payments
  can be deleted before they run (`CancelPayment`, client token, no user approval). The sandbox
  answers the `DELETE` with `204` but keeps reporting `InitiationCompleted`, so the SDK reports a
  successful `DELETE` as `cancelled` (with the bank's status in `Reason`).
- Status: SEPA starts `Pending`, then `AcceptedSettlementInProcess`, then
  `AcceptedSettlementCompleted` (settled on the payer's account, final). Instant usually answers its
  final status at once (`AcceptedCreditSettlementCompleted`). Scheduled payments say
  `InitiationCompleted` only.
- SWIFT (`UK.OBIE.SWIFT`) and standing orders are offered by the API but not implemented.

**Ålandsbanken SE**: domestic payments in SEK: account transfers (`SE.Dataclearing`, payee
`UK.OBIE.BBAN` = clearing + account number), Bankgiro (`SE.Bankgiro`, `SE.BGNR`) and Plusgiro
(`SE.Plusgiro`, `SE.PGNR`), with an OCR number or a message of at most 12 characters (the docs give
the limit for Dataclearing; the SDK applies it to all). Scheduled through
`domestic-scheduled-payments`, deletable. The debtor account is an IBAN.

**Morrow Bank**: domestic credit transfers only, single, by market: FI (EUR, IBAN), NO (NOK, BBAN),
SE (SEK, BBAN). No `LocalInstrument`; payee name 35 characters.

## The `internal/obie` adapter

The OBIE client (consents, request object, token handling, AIS mapping, payment consent/submit/status/
cancel) is generic in `internal/obie`, configured by an `obie.Profile`: hosts, API paths, client
authentication (`tls_client_auth` or `private_key_jwt`), request-object issuer (client id or
certificate DN), intent-id format, kid, signature shape (encoded or unencoded body, trust anchor),
extra headers and a payment builder. `revolut` and `hsbc` still carry their own copies of this code
and can move onto the adapter later.

## Verified

Run against the sandboxes on 2026-10-18 (`banks/crosskey/testdata/live-*`):

| Store | Test user | Connect + data | Payment |
|---|---|---|---|
| S-Pankki FI | `customera` | three accounts (two IBAN, one `FI.S-Pankki.CreditCard`); after a refresh, older than 90 days answers `403 UK.OBIE.Reauthenticate` → `ErrReauthRequired`; disconnect, then `400 UK.OBIE.Resource.InvalidConsentStatus` → `ErrReauthRequired` | SEPA `Pending` → `AcceptedSettlementCompleted`; scheduled SEPA (`InitiationCompleted`) created and deleted |
| Aktia FI personal | `95999991` | two IBAN accounts and a card (`UK.OBIE.BBAN`) | SEPA Instant: `AcceptedCreditSettlementCompleted` at once |
| Aktia FI business | `95999993` | two corporate IBAN accounts and a business card; **pagination**: 100 + 51 transactions, `Links.Next` with `paginationKey=1` passed through as the cursor | — |
| POP Pankki FI | `popsandbox01` | savings account (IBAN) and a card; 100-transaction pages | SEPA to another customer: `Pending` → `AcceptedSettlementCompleted` |
| Ålandsbanken FI | `aarodemo` | three IBAN accounts and a card | SEPA without a debtor (chosen on the bank's page) to an Aktia IBAN: settled |
| Ålandsbanken SE | `antondemo` | SEK and EUR accounts (IBAN) and a card | domestic `SE.Dataclearing`, 1 SEK: `AcceptedSettlementInProcess` (stays there) |
| Morrow FI, NO, SE | `fitest1`, `notest2`, `setest1` | cards, loans, a deposit account; FI with IBAN, NO and SE with BBAN | FI: EUR to an Aktia IBAN, `AcceptedSettlementCompleted` |
| Resurs DK, FI, NO, SE | `dktest1`, `fitest1`, `notest1`, `setest1` | credit cards in DKK, EUR, NOK, SEK, one or two per user (masked `UK.OBIE.PAN`; NO: `UK.OBIE.BBAN`); `Expected` balance; 84 transactions each; every call with `x-fapi-financial-id: resursbank/<country>` | — (no PIS) |

Not run: S-Pankki business (no business test user), SEPA Instant elsewhere than Aktia, Bankgiro and
Plusgiro, Morrow NO and SE payments, Ålandsbanken SE scheduled payments.

### Sandbox notes

- Test users are listed per bank on the application's **Sandboxes** page (S-Pankki: `customera`,
  `customerb`, password `12345678`). "Reset sandbox state" there undoes payments.
- Several test IBANs have wrong check digits, so the SDK refuses them as payees: S-Pankki Customer B
  (`FI8439390001387760`, `FI3839390001384718`), all of Ålandsbanken FI and SE and Morrow FI. Pay to a
  valid IBAN (e.g. Aktia's `FI6640509990999999`) and leave out the debtor, which the user then picks
  on the bank's page. A POP payment to the other POP test customer was accepted.
- Morrow answers `401` for an account id that is not in the consent (reported as
  `ErrAccessExpired`).
- Chrome autofills saved credentials into the bank's login form; clear them before logging in as the
  test user.
- The first token request right after creating the application failed with `401 invalid_client`;
  a few minutes later the same request worked.
- The authorisation code really must be exchanged quickly; 35 seconds after it was issued still
  worked.
- The sandbox certificates are self-signed by "CBS Self Signed Assurance Root CA"; the subject is
  `CN=<team id>`, which is what goes into `iss`.
