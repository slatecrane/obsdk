# SIBS API Market integration notes (Portugal)

SIBS API Market is the Portuguese PSD2 hub: one Berlin Group NextGenPSD2 interface (1.3.12, SIBS
"release 4") in front of 25 institutions, which SIBS puts at more than 95% of the payment accounts
in Portugal: Caixa Geral de Depósitos, Millennium bcp and ActivoBank, Novo Banco (and Novo Banco dos
Açores), Santander Totta, BPI, Crédito Agrícola (the central bank and several local Caixas), Montepio,
Bankinter, EuroBic, Banco BIG, Banco CTT/BPG, Cofidis, Unicre and others. It is the third bank on the
generic Berlin Group adapter ([berlin-group.md](berlin-group.md)): bank key `sibs`, PT, personal and
business. The bank is picked by its **ASPSP code** (`Config.Extra["aspsp"]`, e.g. `BST`).

| | Sandbox | Production |
|---|---|---|
| API | `https://site1.sibsapimarket.com:8445/sibs/apimarket-sb/{aspsp}/v1-0-4` (site2 too) | `https://site1.sibsapimarket.com/sibs/apimarket/{aspsp}/v1-0-4` (site2 too) |
| Test (QLY) | — | `https://site1.sibsapimarket.com:8444/sibs/apimarket/{aspsp}/v1-0-4` (`sibs.TestRoot`, via `base_url`) |
| mTLS | none | eIDAS QWAC |
| Signature | not checked | QSealC on every request |
| App id | `X-IBM-Client-Id` (portal app) | same |
| Approaches | redirect | redirect (every bank in SIBS's feature table) |
| Data | static, the same for every bank | real |

Built on 2026-10-19 from SIBS's TPP user guide *SIBS API Market – PSD2 APIs* v01.51 (2026-01-06,
attached to the Accounts product on the sandbox portal; classified "restricted", so it is not copied
into this repository) and the OpenAPI files of both portals: sandbox stubs 4.0.0/4.0.1, Test & Production
Accounts 4.0.14, Consents 4.0.16, Consent authorisation 4.0.13, Payments 4.0.11, Payment authorisation
4.0.8, List of Banks 2.0.2 (`/sandbox/product`, `/live/product`, "Open API" per API).

## Access

- **Sandbox:** free. Register on https://developer.sibsapimarket.com/sandbox (e-mail activation),
  create an app (Apps → Create New App) and subscribe it to the free sandbox plans of *Accounts*,
  *Payments* and *Information Product* (List of Banks). The app's client id goes in
  `X-IBM-Client-Id`; nothing else is needed. 200 calls per day per API.
- **Test & Production:** for registered TPPs with a valid eIDAS certificate, or ones that have formally
  applied to their NCA (test certificates are accepted then, "in test mode"). Certificates are
  registered through SIBS's TPP form (PKCS#10 of the QSealC and the QWAC). PSD2 APIs are free for TPPs.

## What the integration needs

- `client_id`: the portal app's client id, sent as `X-IBM-Client-Id` on every request.
- `aspsp` (`Config.Extra`): the bank's ASPSP code, its BIC or one of its Portuguese IBANs
  (`sibs.ASPSPCode`). The 25 banks of SIBS's List of Banks (`GET /v1/available-aspsp` on the sandbox root,
  `/sibs/v1-0-2/available-aspsp` in production; read 2026-10-19) are embedded
  ([directory.go](../banks/sibs/directory.go), `sibs.Institutions()` / `sibs.Lookup`); other codes of the
  right shape pass through, as banks join. It is kept in the session, flow state and payment reference.

  | Code | Bank | | Code | Bank |
  |---|---|---|---|---|
  | `CGDPT` | Caixa Geral de Depósitos | | `BIG` | Banco BIG |
  | `BCPPT` | Millennium bcp | | `BPG` | Banco Português de Gestão |
  | `ABPT` | ActivoBank | | `BIC` | EuroBic |
  | `NVB` | Novo Banco | | `ATLEU` | Banco Atlântico Europa |
  | `NVBA` | Novo Banco dos Açores | | `BCTT` | Banco CTT |
  | `BST` | Santander Totta | | `UNICR` | Unicre |
  | `BBPI` | BPI | | `COF` | Cofidis |
  | `GCA` | Crédito Agrícola (Caixa Central) | | `CEMAH` | CE Misericórdia de Angra do Heroísmo |
  | `CEMG` | Banco Montepio | | `CCAML`, `CATV`, `CABOM`, `CACHM`, `CAMAF` | Crédito Agrícola of Leiria, Torres Vedras, Bombarral, Chamusca, Mafra |
  | `BNKI` | Bankinter (PT branch) | | `CGDFR`, `BIGES` | CGD France, BIG España (French and Spanish accounts) |
- Production: **QWAC** (`sibs.HTTPClient`) and **QSealC** (`Config.Seal`, RSA).
- **TLS renegotiation:** SIBS's gateway renegotiates TLS after the handshake (sandbox too), which Go
  refuses by default (`tls: no renegotiation`). Use `sibs.HTTPClient(qwac)` or `sibs.SandboxHTTPClient()`,
  which allow it once per connection; for obdev set `OBSDK_TLS_RENEGOTIATE=1`.
- `PSU.IP`: `PSU-IP-Address` is mandatory on payments.

## How SIBS differs from the standard

All handled by profile knobs of the adapter:

- **Path version:** `/{aspsp}/v1-0-4/...` instead of `/v1/...` (`PathVersion`). Links come back as
  bare paths with the code (`BST/v1-0-4/consents/…`); the guide's own examples sometimes show `/v1/`.
  Both are accepted.
- **Global consent** is `"allPsd2": "all-accounts"` (hyphenated; `AllAccountsValue`). SIBS also offers
  `all-accounts-with-ownerName` and `availableAccounts`, which the SDK does not ask for.
- **`validUntil`** is a date-time; the SDK sends the guide's form `2027-04-17T10:00:00`
  (`ValidUntilLayout`) and reads the granted validity back as its date.
- **`Date`** is mandatory on every request, in ISO 8601 as in the guide (`2026-10-19T10:00:00.000Z`;
  `DateLayout`), and part of the signature.
- **Signature** (production): draft-cavage, `algorithm="rsa-sha256"`, `keyId` = the QSealC's serial number
  in lowercase hex (`sibs.KeyID`), signed headers `digest x-request-id date` plus `psu-id`,
  `psu-corporate-id` and `tpp-redirect-uri` when present, certificate in `TPP-Signature-Certificate`
  (release 3 called it `TPP-Certificate`). The sandbox's OpenAPI files still mark `Signature` and the
  certificate as required, so the SDK sends placeholders there when no seal is configured.
- **`Digest`** goes with every request that has a body, signed or not; the sandbox refuses a body without
  one and a GET with one (`400 "Invalid Digest Header."`; `BodyDigest`).
- **Redirect link:** `_links.redirect`, not the standard's `scaRedirect` (the guide's examples and the
  sandbox agree). The adapter treats both the same.
- **Character set:** only `A-Z a-z 0-9 / - ? : ( ) . , ' + < = > & % _ * #` and space; anything else
  (accented letters too) is declined. The payment specs carry this as a pattern on the payee name,
  description and end-to-end id, so `Validate` catches it before sending.

## Flows

Redirect only (every bank in the guide's feature table). The API also defines decoupled and embedded
steering links; the adapter follows whatever links come back.

1. `POST /{aspsp}/v1-0-4/consents` (`TPP-Redirect-Preferred: true`, `TPP-Redirect-URI`,
   `TPP-Nok-Redirect-URI`) → `_links.redirect`; the authorisation is created implicitly.
2. The user approves at the bank and comes back to the redirect URL (no parameters).
3. `GET …/consents/{id}/status` must be read and be `valid` before any account call ("account
   information requests will be denied" otherwise); the SDK always does this.

- A **long-lasting consent replaces** any earlier one of the same user (PSU-ID), TPP and bank.
- Consents last at most **180 days** (since 2023-07-25); the bank may shorten them. Abandoned consents
  and payments are deleted after 30 minutes, expired consents a month after expiry (then `404`).
- `frequencyPerDay` is capped at 4 per account and data set; above it `429`.
- **Disconnect:** `DELETE …/consents/{id}`.

## Data

- **Accounts:** `resourceId`, IBAN, currency, `name`, `product`, `cashAccountType`, `ownerName` (only
  with an `…-with-ownerName` consent), `_links`. No `withBalance` anywhere (`NoWithBalance`), no
  transaction details, no delta queries.
- **Balances:** `closingBooked`, `expected`, `openingBooked`, `interimAvailable`, `interimBooked`,
  `forwardAvailable`, `nonInvoiced`.
- **Transactions:** `bookingStatus` `booked`, `pending` or `both` (`information` = standing orders, not
  used). The spec has no `transactionId`; `entryReference` identifies a transaction. Pages are linked
  by `_links.next`, valid for 30 minutes, which must be called **unchanged** (SIBS: "must not add query
  parameters"); the cursor is that link as is.
- Transactions older than 90 days are only readable within 30 minutes of the consent's approval.
- Card accounts (`/card-accounts`) exist but are not used.

## Payments

| Type | Product | Notes |
|---|---|---|
| `sepa` | `sepa-credit-transfers` | `execution_date` for future-dated payments |
| `sepa_instant` | `instant-sepa-credit-transfers` | most, not all banks |

- JSON body with the address in the pre-1.3.8 shape (`street`, `city`, `postalCode`; `LegacyAddress`)
  and no structured remittance field. The debtor account is optional (the user can pick at the bank).
- A payment to an account at the same bank may be booked as an internal transfer; a
  `cross-border-credit-transfers` payment in EUR within SEPA may become a SEPA CT. `cross-border` and
  `target-2-payments` products, periodic, bulk, Multibanco and TSU payments exist but are not used.
- **Status:** `RCVD`, `PDNG`, `PATC` (other signatories needed), `ACTC` (final for future-dated),
  `ACSP`, `ACSC`, `ACCC`, `RJCT`, `CANC`. SIBS asks for at least 5 seconds between status polls.
- **Cancellation:** `DELETE …/payments/{product}/{id}`; banks allow it for future-dated payments, some
  with a cancellation authorisation (redirect).

## Verified

Sandbox, 2026-10-19 (portal app subscribed to the 4.0.x sandbox plans):

| Area | Result |
|---|---|
| List of Banks | 25 banks read; embedded as the directory |
| Payments | `sepa` and `sepa_instant` created (`PDNG`, empty `redirect` link), status read (`ACCP` → `accepted`): `live-pt-pay-sepa`, `live-pt-pay-instant`, `live-pt-payment-status` |
| Cancel | `DELETE` answers `CANC`, but the static stub keeps reporting `ACCP`, so the SDK's check reports the payment as not cancelled (`live-pt-cancel`). Correct against a real bank, which would report `CANC` |
| AIS | **not testable**: the sandbox's Accounts stub answers `404 RESOURCE_UNKNOWN "Invalid Aspsp-cde"` for every code (the 25 listed, BICs, bank codes) on consents, accounts, card accounts and funds confirmation (`live-pt-connect-sandbox-broken`). Covered by a fake server (`TestRequestShape`) |
| TLS | renegotiation needed (see above) |
| Not run | the redirect approval itself (the stub returns no URL; covered by `TestPaymentRedirect`), signing, mTLS, production |

The sandbox is static: every payment gets id `e741d60fac1763b84c3345d367140a39`, whatever was sent. The
List of Banks still names path versions `v1-0-2`/`v1-0-3`, but the current plans only answer on `v1-0-4`
(`v1-0-3`: `401 "Not registered to plan"`). Sandbox and AIS stay `experimental`.
