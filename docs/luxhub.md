# LUXHUB integration notes (Spuerkeess, POST Luxembourg, Banque Raiffeisen and other Luxembourg banks)

LUXHUB runs the PSD2 interface of most Luxembourg banks, a few of their Belgian and German sister entities, SEB's
Luxembourg and Oslo branches and Svea Bank. Each bank entity has its own hosts; the interface is the same. The banks
below are registered by [banks/luxhub](../banks/luxhub) on the generic Berlin Group adapter
([berlin-group.md](berlin-group.md)):

| Bank key | Bank | Countries and host code | Segments | Payments |
|---|---|---|---|---|
| `spuerkeess` | Spuerkeess (BCEE) | LU `openbank.bcee.lu` | personal and business | `sepa`, `sepa_instant` |
| `postluxembourg` | POST Luxembourg | LU `ccpllull` | personal and business | `sepa`, `sepa_instant` |
| `raiffeisenlu` | Banque Raiffeisen | LU `ccralull` | personal and business | `sepa`, `sepa_instant` |
| `banquedeluxembourg` | Banque de Luxembourg | LU `bluxlull`, BE `bluxbe41` | personal and business | `sepa`, `sepa_instant` |
| `banquetransatlantique` | Banque Transatlantique | LU `cmcilul1`, BE `cmcibeb1` | personal and business | `sepa`, `sepa_instant` |
| `dnbluxembourg` | DNB Luxembourg | LU `ubnllull` | business only | `sepa`, `sepa_instant` |
| `svea` | Svea Bank | SE `sveasess` | personal and business | none (AIS only) |
| `swissquotelu` | Swissquote Bank Europe | LU `swqblull` | personal and business | `sepa` |
| `seb` | SEB (Luxembourg and Oslo branches) | LU `tpp-api.sebgroup.lu`, NO `tpp-api.seb.no` | business only | `sepa` |
| `juliusbaerlu` | Julius Baer Luxembourg | LU `baerlulu` | business only | `sepa`, `sepa_instant` |
| `ubp` | Union Bancaire Privée (Europe) | LU `openapi.ubp.com` | business only | `sepa` |
| `andbanklu` | Andbank Luxembourg | LU `bacalull` | business only | `sepa`, `sepa_instant` |
| `bankinterlu` | Bankinter Luxembourg | LU `bkbklull` | business only | none (AIS only) |
| `safralu` | Banco Safra (Luxembourg branch) | LU `bsaflull` | business only | `sepa`, `sepa_instant` |
| `bpplu` | Banque de Patrimoines Privés | LU `bbpplull` | business only | none (AIS only) |
| `bnpwmde` | BNP Paribas Wealth Management Germany | DE `bnpadeff` | business only | `sepa` |
| `caixabankwmlu` | CaixaBank Wealth Management Luxembourg | LU `caixlull` | business only | none (AIS only) |
| `ccbeurope` | China Construction Bank (Europe) | LU `pcbclule` | business only | `sepa_instant` |
| `ccbbranches` | China Construction Bank (Luxembourg and Frankfurt branches) | LU `pcbclull`, DE `pcbcdeff` | business only | `sepa_instant` |
| `cmbeurope` | China Merchants Bank (Europe) | LU `cmbclulu` | business only | none (AIS only) |
| `cmbluxembourg` | China Merchants Bank (Luxembourg branch) | LU `cmbclull` | business only | none (AIS only) |
| `eurobanklu` | Eurobank Private Bank Luxembourg | LU `erbklull` | business only | none (AIS only) |
| `intesawmlu` | Intesa Sanpaolo Wealth Management | LU `cbpxlull` | business only | none (AIS only) |
| `threesmoney` | 3S Money | LU `molulu22` | business only | `sepa`, `sepa_instant` |
| `sogexia` | Sogexia | LU `soxalull` | personal and business | `sepa` |

"Business only" banks are private, wealth-management or corporate banks: they are registered for the business
segment. Payment types are the products each bank's OpenAPI file lists (`pain.001-*`, cross-border, TARGET2 and
proprietary products are not mapped).

Built on 2026-10-21 from LUXHUB's developer portal: the documentation tabs of each product and the OpenAPI file
embedded in it (both served by the portal's public JSON API, `developer.luxhub.com/api/api-details/<name>/...`).
**Nothing has run against a LUXHUB server**: the sandbox is closed to us (see [Access](#access)). Every variant is
`experimental` (sandbox) or `unverified` (production).

Not registered:

- **BGL BNP Paribas** (`bglllull`): STET 1.5 on LUXHUB, not Berlin Group. A STET profile on
  [internal/stet](stet.md) would cover it; the OAuth layer is the same as below.
- Banks on **Berlin Group v2** ("openFinance", `x-jws-signature` instead of draft-cavage): Bank of Communications
  (three entities), Northern Trust Global Services. The adapter doesn't sign JWS.
- The **CBPII extensions** (Banque Raiffeisen, Eurobank on `/bg/v2`), funds confirmation only.
- Banks with a **sandbox but no production** API in the catalogue: BPER, Chaabi Bank, IRACE, Mirabaud, Banque
  Calédonienne d'Investissement, the demo banks.
- **Fideuram Direct** (no authorisation endpoint published), **Banco Santander** (`bschbrsp`, Santander Brasil's
  Luxembourg branch, cross-border transfers only), **Intesa Sanpaolo WM "APP"** (a second API of the same entity).
- **BIL**: listed as a provider, but has no product in the catalogue.

## Access

- Anyone can register on https://developer.luxhub.com, but bank APIs (sandbox included) need an **organisation
  account**, which LUXHUB grants to authorised TPPs and PSPs that have applied for authorisation ("RTS article
  30(5)"): a form, a check, then a registration code. A personal account was created on 2026-10-21: its only
  allowed API is LUXHUB's own "One Core API" (`/api/applications/allowed-apis`), and its organisation stays
  `PENDING` / "Standalone".
- Portal bug: SIGN IN on developer.luxhub.com returns to `marketplace.luxhub.com/?loginFailed=true` (the login
  starts on one host and returns to the other). Starting at
  `https://marketplace.luxhub.com/api/login/oauth2/auth/luxhub-sso` works; that host's pages stay blank, but its
  `/api/...` calls answer with the session.
- With an organisation: an application per environment (PSD2, Sandbox or Production, redirect URLs), subscribed to
  the bank APIs; it gets a client id and secret. In the sandbox the portal generates **mock QWAC and QSealC**
  (Applications -> Authentication -> Generate new certificates; `QWAC-*.pem`, `QSealC-*.pem`), and real eIDAS
  certificates are accepted too. Production needs eIDAS certificates and a "promotion" of the organisation
  (signing a challenge with the QSealC), or dynamic registration with the QWAC (Third Party Management API).
- Every host requires **mTLS**: the sandbox refuses the handshake without a client certificate (checked
  2026-10-21).

## Hosts

| | Sandbox | Production |
|---|---|---|
| XS2A root | `https://<code>-psd2api-sbx.luxhub.com/bg/v1` | `https://<code>-psd2api.luxhub.com/bg/v1` |
| Token | `https://<code>-psd2api-sbx.luxhub.com/api/oauth/token` | `https://<code>-psd2api.luxhub.com/api/oauth/token` |
| Authorisation | `https://<code>-cb-sbx.luxhub.com/api/oauth/authorize` | `https://<code>-cb.luxhub.com/api/oauth/authorize` |

`<code>` is the entity's BIC8 in lower case. Spuerkeess (`openbank.bcee.lu`, `cbopenbank.bcee.lu`; sandbox
`sbopenbank`, `cbsbopenbank`), SEB (`tpp-api[-sbx].sebgroup.lu` / `.seb.no`, authorisation on `tpp-apicb[-sbx]`) and
UBP (`openapi[-sbx].ubp.com`, `openapicb[-sbx]`) use their own domains with the same paths. Catalogue oddities, not
followed: China Construction Bank Frankfurt's authorisation host is listed as `pcbcdeff-cb-tsx` (the pattern is
used instead); Svea's sandbox root is listed as `/bg/v2` while its version is 1.3 (`/bg/v1` is used).

## Flows

LUXHUB wraps Berlin Group 1.3 (2019-02-15) in OAuth2 ([adapter option `Profile.OAuth`](berlin-group.md)):

1. **Client-credentials token** at the token endpoint, HTTP Basic with the client id and secret: scope `AIS` for
   consents, `PIS:payment` for payments (the documentation's values). Consent and payment resources (create,
   status, read, delete) are called with it; the SDK asks for one per call and keeps none.
2. **Create** the consent (`allPsd2: allAccounts`, `frequencyPerDay` 4) or the payment, `TPP-Redirect-Preferred:
   true`.
3. **Approve**: if the response has a `scaRedirect` or `scaOAuth` link it is followed; otherwise (the documented
   case) the user goes to the bank's authorisation endpoint: `response_type=code`, `scope=AIS:<consentId>` or
   `PIS:<paymentId>`, `client_id`, `redirect_uri`, `state`, PKCE S256.
4. **Consents**: the code is exchanged (Basic auth, `scope` repeated, `code_verifier`) for an access and a refresh
   token (refresh valid 180 days). Account calls carry the access token and `Consent-ID`; `Refresh` checks the
   consent with a client token, then renews the access token.
5. **Payments**: the code is not exchanged; the payment's status (client token) decides.

Signing ([LUXHUB's "Security" tab](https://developer.luxhub.com)): every request is signed, draft-cavage-10,
`algorithm="rsa-sha256"`, signed headers `date digest x-request-id` (plus `psu-id`, `tpp-redirect-uri` when sent),
`keyId="SN=<serial, lower-case hex>,CA=<issuer DN, RFC 2253>"`, the QSealC in `TPP-Signature-Certificate`. The SDK
requires `Config.Seal`.

Assumed, not documented clearly:

- The payment authorisation: the PIS tab first creates an authorisation explicitly (`POST
  .../authorisations`) and then shows `scope=PIS:<consent_id>` with a `resource=payments/<authorisationId>`
  parameter. The SDK posts a `startAuthorisation` link when the bank returns one and sends `scope=PIS:<paymentId>`
  without `resource`.
- `client_id` is left out of token requests (Basic only), as in every example.

## Data

- Transactions: `booked`, `pending` and `both` where the bank's spec lists them (Raiffeisen: booked only; Banco
  Safra: booked and both). Pagination by `_links.next`, passed through.
- More than 90 days of history needs the extra scope `AIS_EXT` on the first token after the approval
  (LUXHUB's STET-style "extended transaction history"); not asked for, so older history may be refused with
  `403 insufficient_scope`.
- A `bic` query parameter exists on every endpoint for banks with several entities behind one API; no registered
  bank needs it (each entity has its own product).

## Payments

Single payments with redirect approval: `sepa` (`sepa-credit-transfers`) and `sepa_instant`
(`instant-sepa-credit-transfers`) per the table above. The debtor account is required (all examples send it);
creditor address accepted. No execution date and no cancellation are offered: the specs allow them, but nothing
says which banks support them. Not mapped: `cross-border-credit-transfers`, `target-2-payments`,
`swift-remittance`, Svea's domestic Swedish products, Eurobank's `standard-credit-transfers`, periodic and bulk
payments, signing baskets, multilevel SCA.

## Sandbox

Per the "Onboarding specifics" tab: static data (payments show up in transactions but don't change balances),
nightly reset, three generic users per bank (any password, OTP `123456`), `frequencyPerDay` fixed at 4, request
and response validation against each bank's spec, role checks on the certificate. To run it, see
`banks/luxhub/sandbox.env.example` (organisation account needed).

## Verified

Nothing against a server. Unit tests: the adapter's `Profile.OAuth` against a fake server (consent with client
token, fixed authorisation endpoint, code exchange with scope, accounts with the user token, payment approval
without exchange), and the LUXHUB profile against a fake hub (hosts, Basic auth, signature headers and keyId,
consent and payment flows).
