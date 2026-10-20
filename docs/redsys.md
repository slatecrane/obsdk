# Redsys PSD2 hub integration notes (Spain)

Redsys runs "HUB PSD2", the Berlin Group NextGenPSD2 interface (1.3.0, Redsys "v1.1") of most Spanish
banks: BBVA, CaixaBank (and imagin), Banco Santander (and Openbank, Santander CIB), Banco Sabadell,
Bankinter, Unicaja, Kutxabank, Ibercaja, Laboral Kutxa, Grupo Cajamar, the Caja Rural group (Banco
Cooperativo Español), Eurocaja Rural, Banca March, Banco Mediolanum, Renta 4, Self Bank, Triodos,
Colonya, Banco Pichincha, Inversis, Banco Alcalá, WiZink, Cetelem and more: 32 banking groups and 80+
entities, by Redsys's count. It is the fifth bank on the generic Berlin Group adapter
([berlin-group.md](berlin-group.md)): bank key `redsys`, ES, personal and business. The bank is picked
by its **code on the hub** (`Config.Extra["aspsp"]`, e.g. `BBVA`, `caixabank`, `BancSabadell`).

| | Sandbox | Production |
|---|---|---|
| API | `https://apis-i.redsys.es:20443/psd2/xs2a/api-entrada-xs2a/services/{aspsp}` | `https://psd2.redsys.es/api-entrada-xs2a/services/{aspsp}` |
| OAuth (authorize, token) | `https://apis-i.redsys.es:20443/psd2/xs2a/api-oauth-xs2a/services/rest/{aspsp}` | `https://hubpsd2.redsys.es/api-oauth-xs2a/services/rest/{aspsp}` |
| Signature | QSealC on every request (the portal's generic certificate, or the TPP's own) | QSealC on every request |
| mTLS | none (calls answer without a client certificate) | not stated in the guide; probably the QWAC |
| Paths | `{API}/v1.1/...` for everything (the guide's `/v1/` answers `SERVICE_INVALID`) | the same, assumed |
| Approaches | redirect (some banks also decoupled) | the same |

Built on 2026-10-19 from the hub's *PSD2-TPP Technical Design* v1.9.4 (September 2025, BBVA edition;
the other banks' editions differ in their notes only), its OpenAPI file `documentacionswagger_v1.1.yaml`,
the web guide (https://market.apis-i.redsys.es/psd2/xs2a/guia) and the per-bank pages
(`https://market.apis-i.redsys.es/psd2/xs2a/nodos/<bank>`): hosts, bank codes, SCA approaches, products,
sandbox users. Run against the sandbox (BBVA) on 2026-10-20; see [Verified](#verified).

## Access

- **Sandbox:** free. Create an account on https://market.apis-i.redsys.es/psd2/xs2a/user/register,
  create an application ("Applications" → "Create application", a title is enough), and subscribe to a
  plan (confirmed by e-mail, usually within a day; support: psd2.sandbox.soporte@redsys.es). The
  "Certificates" tab hands out a **sandbox certificate**: one PEM with the certificate and its RSA key,
  self-signed (`CN=<app>, O=HUB-PSD2`), organizationIdentifier `PSDES-BDE-<number>`, PSD2 roles PI, AI and
  IC, valid one year. Split it into `banks/redsys/cert/qseal.pem` and `qseal.key` (ignored). The
  organizationIdentifier is the OAuth client id. The application's own client id (a UUID) and secret are
  not used by the API: the gateway asked for neither.
- **Production:** a PSD2 licence and eIDAS certificates; onboarding with Redsys.
- Sandbox users, common to every simulated bank: `user1` / `1234` (SCA OK), `user2` / `1234` (SCA KO).
  Test IBANs are on each bank's page, e.g. BBVA `ES2501822200160201933547`, `ES4901822200110201933554`.
- The hub's sandbox pages name `ES0040000000000000000001` as the default creditor account. It fails the
  IBAN check, so the SDK's payment validation refuses it; use another valid Spanish IBAN.

## What the integration needs

| Config | |
|---|---|
| `Config.Extra["aspsp"]` | the bank's code on the hub, case as the hub spells it; `redsys.ASPSPs` lists the known ones and `redsys.ASPSPCode` maps any case of those (others pass as given). Needed to connect or pay, then kept in the session and payment reference |
| `Config.Seal` | RSA QSealC key and certificate: every request is signed (`Digest`, `Signature` over `digest x-request-id` and the present PSU-ID / TPP-Redirect-URI, `TPP-Signature-Certificate`) |
| `Credentials.ClientID` | the OAuth client id: the certificate's organizationIdentifier (`PSDES-BDE-3DFD21`). Read from `Config.Seal`'s certificate when empty |
| `Credentials.RedirectURL` | gets both callbacks: the OAuth code after the login, then the return from the consent or payment approval |

Known bank codes (2026-10-19): `BBVA`, `caixabank`, `imagin`, `bancosantander`, `bancosantanderglobal`,
`openbank`, `BancSabadell`, `bankinter`, `unicajabanco`, `kutxabank`, `ibercaja`, `laboralkutxa`,
`grupocajamar`, `BCE` (Caja Rural), `EUROCAJARURAL`, `bancamarch`, `BancoMediolanum`, `renta4`,
`selfbank`, `triodos`, `COLONYA`, `PICHINCHA`, `inversis`, `creandes` (Banco Alcalá), `wizink`,
`CETELEM`. The hub's ASPSP directory (`GET /v2/sva/aspsps`) lists all; not used yet.

## How Redsys differs from the standard

- **OAuth2 as a pre-step.** No XS2A call works without a bearer token (`401 TOKEN_INVALID`). The user
  first logs in at `{oauth}/authorize` (authorisation code, PKCE S256, scope `AIS` or `PIS`, client id =
  organizationIdentifier), the code is exchanged at `{oauth}/token`, and the token goes on every request.
  A token works only for the bank it was issued for (`TOKEN_UNKNOWN`). The adapter's `Profile.PreStep`.
- **Two redirects.** After the login the consent or payment still needs the user's approval, by the
  `scaRedirect` link (the sandbox: the same simulated bank). Both return to the redirect URL.
- **Every path is on `v1.1`.** The guide shows `/v1/` for everything but creation, but the sandbox
  answers `400 SERVICE_INVALID "[HUB007] Unavailable service for Asp."` there and serves consents,
  accounts, balances, transactions and payments on `/v1.1/` (`Profile.PathVersion`). Its links say
  `/v1.1/` too.
- **Some of the hub's links are wrong:** an account's `balances` link in the list points to
  `.../transactions/balances` (404), the account details' `transactions` link to `.../balances/transactions`.
  The adapter builds those paths itself and doesn't follow them.
- **Tokens last a year** (`expires_in` 31535990 in the sandbox); the refresh token works.
- **`TPP-Nok-Redirect-URI` is limited to 50 characters**, so it is not sent (`NoNokRedirect`): a
  refusal comes back to the redirect URL and the scaStatus or resource status tells.
- **Digest on every request**, also without a body (the adapter's signing does that).
- One long-lasting consent per TPP, user and bank: a new one replaces the previous.

## Flows

- **Connect:** login redirect (scope `AIS`) → callback with `code` → token → `POST /v1.1/consents`
  (global, `allPsd2: allAccounts`, up to 180 days) with the token → approval redirect, whose step
  already carries the session with the token → callback → `scaStatus` (when linked), consent status,
  granted `validUntil`, accounts with balances. The session holds the token, the refresh token, the
  token URL (`Meta`) and the consent.
- **Refresh:** renews the token with the refresh token first (every call needs one), then checks the
  consent status with the new token. Without a refresh token, an expired token means connecting again.
- **Disconnect:** `DELETE /v1/consents/{id}` with the token, when it is still valid.
- A failure after the login is a `FlowError` carrying the session.

## Data

Accounts (`withBalance=true`), balances, booked transactions (`bookingStatus=booked`; the sandbox
answers `PERIOD_INVALID` to `both` and `pending`) with the hub's `next` link (an opaque `?link=<JWT>`)
passed through as the cursor; every read carries the token and the `Consent-ID`.

Sandbox transactions (BBVA, 2026-10-20): debits come as positive amounts with the queried account as
debtor, which the adapter turns into signed debits; the purpose text is in
`remittanceInformationStructured` as a plain string (e.g. `"REGALO"`), which maps to `ReferenceNumber`
as the standard reads it; `ultimateCreditor` / `ultimateDebtor` stay in `Raw`.

## Payments

`sepa` (`sepa-credit-transfers`, incl. future-dated with `requestedExecutionDate`) and `sepa_instant`
(`instant-sepa-credit-transfers`), EUR, single payments. Following the hub's `SinglePayment`:
`debtorAccount` is required, the address uses the 1.3.8 names (`townName`, ...; BBVA requires the
town for instant transfers), remittance is one unstructured line of 140, and there is no
`endToEndIdentification` or structured reference.

A payment starts with its own login (scope `PIS`), unless `PaymentRequest.Session` holds a session
whose scope includes `PIS` and whose token is valid or can be renewed (an earlier payment's). Every
step after the login carries the session; **`PaymentStatus` and `CancelPayment` need it**
(`PaymentCallOptions.Session`), as the hub wants the token there too
(`PaymentSpec.StatusNeedsSession`). Cancellation is `DELETE` on future-dated payments; BBVA answers
`202` with an approval redirect.

Sandbox quirks (BBVA, 2026-10-20): a future-dated payment reports `ACSC` right after approval, and can
still be cancelled. After the cancellation is approved, the `scaStatus` link the hub gave for it answers
`404 RESOURCE_UNKNOWN` (later `403 HUB076`); the adapter then lets the payment status decide (`CANC`).

Not offered yet: `target-2-payments`, `cross-border-credit-transfers`, periodic and bulk payments, the
hub's "SVA" payments where the user picks the account at the bank, and funds confirmation.

## Verified

Sandbox, BBVA, personal user `user1`, 2026-10-20 (obdev, recorded as `testdata/live-es-*`):

- connect: login (pre-step, scope `AIS`), consent approval, 7 accounts with balances;
- accounts, balances, transactions over two pages (20 + 17), refresh (token renewed, consent `valid`);
- a SEPA payment with its own login (scope `PIS`), approved and `ACSC`; its status read with the session;
- a future-dated SEPA payment started with that session (no new login), approved, then cancelled with
  the cancellation's approval redirect (`CANC`). The cancel scenario's last exchange, the status, was
  read with a signed probe after the run, before the adapter fell back to it.

Not run: `sepa_instant`, a refused login or approval (`user2`), disconnect, business users, other banks
than BBVA (e.g. `caixabank`), production. Also covered offline by a fake hub
(`banks/redsys/redsys_test.go`) and synthetic scenarios (`testdata/es-hand-*`, generated by
`research/redsys/handwritten.py`) for those paths.

To run more: `set -a; . banks/redsys/sandbox.env; set +a`, then obdev as usual. Each login and approval
is a browser page on the simulated bank (`user1` / `1234`); paste the final `https://example.com/callback...`
URL into obdev. obdev stores a payment's session over the AIS session file; keep a copy.
