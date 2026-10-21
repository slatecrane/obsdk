# ABN AMRO integration notes (the Netherlands)

Package `banks/abnamro`, bank key `abnamro`, integration `abnamro-psd2`. ABN AMRO has its own PSD2 API (not Berlin
Group): OAuth2 authorization-code consent through its consent application, a per-account AIS API and a two-step
payment API (register, then execute with the user's token).

Sources: the developer portal's tutorials and OpenAPI files for Account Information (PSD2) 1.5.7 and Payment
Initiation (PSD2) 2.1 (developer.abnamro.com, read 2026-10-20; the product pages are only reachable through
`/api-products`, and the files need a browser: curl gets 406 from the portal).

## What the integration needs

| | Sandbox | Production |
|---|---|---|
| `client_id` | `TPP_test` (shared) | issued by ABN AMRO at onboarding (production access request on the portal) |
| `Extra["api_key"]` | the API key of an app on the developer portal (free account; Apps → Add app with the PSD2 products) | the production app's API key |
| `redirect_url` | `https://localhost/auth`, nothing else | the URLs given in the access request |
| mTLS (`HTTPClient`) | ABN AMRO's published sandbox certificate and key (`PSD2TPPCertificate.crt`, `PSD2TPPprivateKey.key`, linked from the tutorials) | a QWAC with the Client Authentication EKU (since 2025-10-01 CAs may leave it out: ask for it) |
| Licence | none | PSD2 licence (DNB in NL), or FCA for UK accounts |

Only the token and revocation endpoints are mTLS. API calls carry `API-Key` and the bearer token; nothing is
signed. Hosts:

| | Sandbox | Production |
|---|---|---|
| API | `api-sandbox.abnamro.com` | `api.abnamro.com` |
| Authorize | `auth-sandbox.abnamro.com/as/authorization.oauth2` | `www.abnamro.nl/consent/v2/authorize` |
| Token | `auth-mtls-sandbox.abnamro.com/as/token.oauth2` | `auth-mtls.abnamro.com/as/token.oauth2` |
| Revoke | `auth-mtls-sandbox.abnamro.com/as/revoke_token.oauth2` | assumed `auth-mtls.abnamro.com/as/revoke_token.oauth2` (PingFederate; not in the docs) |

Related brands (Bethmann Bank, Neuflize OBC, Franx, ABN AMRO Private Banking Belgium) have their own portals and are
not covered.

## Flows

**Connect.** Redirect to the consent page with the scopes for the requested capabilities
(`psd2:account:details:read` always, plus `balance` and `transaction`). The user picks **one** account. The code
must be exchanged within 60 seconds. Then `GET /v1/consentinfo` (allowed at most twice per consent) gives the
account's IBAN, status and remaining validity (as text: "26 days, 23 hours, …", parsed into `ValidUntil`), and
`GET /v1/accounts/{iban}/details` the account. The IBAN is the session's only account: kept in
`Consents["ais"].Accounts` and used as the account id. To connect several accounts, run Connect once per account;
each gives its own session.

**Data.**

- Accounts: the details call (owner name, currency).
- Balances: three calls, `BOOKBALANCE` (`interim_booked`), `BOOKBALANCEINCLUDINGRESERVATION`
  (`interim_available`) and `VALUEBALANCE` (`other`). Accounts outside the Netherlands only have the first; a 400 on
  the others is skipped.
- Transactions: `/v1/accounts/{iban}/activities` (`/transactions` reached end of life on 2025-12-31). Booked items, or
  reservations (card holds and similar) for `pending`, asked with `status=ACTIVE` so cancelled holds are left out.
  50 per page. The cursor is the next request's query: `nextPageKey` plus the filters, which ABN AMRO wants
  repeated. When both statuses are asked for, booked pages come first and the last one's cursor switches to
  reservations. `dateFrom`/`dateTo` are dates; since 2025-10-05 they filter on the transaction date, not the book date.

**Refresh** rotates the refresh token. **Disconnect** revokes the refresh token (RFC 7009), which voids every access
token of the consent (verified: the old access tokens answer 401 afterwards).

## Behaviours worth knowing

- Amounts are JSON numbers. Activities send them unsigned with `creditDebitIndicator`; balances send them signed
  **and** with the indicator. The SDK takes the number's text as sent (no float conversion) and signs it by the
  indicator.
- `descriptionLines` hold the statement text (in Dutch: "Naam:", "Omschrijving:", "Kenmerk:", …), padded with commas.
  They go into `Remittance` without the padding; `Raw` keeps the original. `mutationCode` is `BankCode`.
- `counterPartyAccountNumber` is an IBAN or, for some foreign counterparties, another number (`BBAN`).
- Some booked items have an empty `id` (cash withdrawals in the sandbox).
- The consent page refuses URLs over 256 characters (production; the sandbox took 271). The SDK keeps `:` and `/`
  unescaped in the query, as ABN AMRO's examples do, and uses a 20-character state.
- Errors: `{"errors": [{code, message, category, status, traceId}]}`. `ERR_2002_001` (401) is an expired or revoked
  token (`ErrAccessExpired`), `MESSAGE_RST560_0016` (403) an account outside the consent (`ErrReauthRequired`),
  OAuth `invalid_grant` on refresh a dead refresh token.

## Payments

| Type | Product | Notes |
|---|---|---|
| `sepa` | `/payment/v2/sepa-credit-transfers` | EUR; description or structured reference (`RF` sent as issuer `ISO`, `CUR` = Dutch betalingskenmerk, `BBA` = Belgian structured communication) |
| `crossborder` | `/payment/v2/cross-border-credit-transfers` | any currency; payee IBAN or other number, BIC required, structured address, charge bearer `DEBT`/`CRED`/`SHAR` |

1. Client-credentials token (`psd2:payment:sepa:write` or `…:xborder:write`), then `POST` the payment (`RCVD`).
2. Redirect to the consent page with `transactionId=<paymentId>` and the product's `write` and `read` scopes. If the
   debtor account was given, the user cannot change it; otherwise they pick one.
3. Exchange the code, then `PUT` the payment (empty body; `Content-Length: 0` is required) to execute it (`PDNG`).
   StepDone carries the payment and a **session** with that token pair (consent kind `pis`, id = payment id).
4. Status (`GET …/status`) and cancellation (`DELETE`, future-dated payments only, 204, no user approval) need that
   session in `PaymentCallOptions.Session`: the client-credentials token gets `403 SUBJECT_NOT_ALLOWED`. Its access
   token lasts 2 hours; the SDK refreshes it (status works for 30 days) and returns the new session in
   `Result.Session` / `Step.Session`.

Statuses are ISO 20022 (`RCVD`, `PDNG`, `ACSP`, `ACWC`, `ACSC`, `ACCC`, `RJCT`, `CANC`, `RTRN`; `RTRN` is mapped to
rejected). A rejection's reason is `statusDetails.statusISORsn` (`Payment.Reason`). There is no end-to-end id and no
duplicate check. Not built: standing orders and bulk payments (PIS v1 only), confirmation of funds.

## Verified against the sandbox (2026-10-20/21)

The sandbox is static (data reset daily) and its consent page is a plain IBAN picker without login, so the whole
loop was scripted with curl. Scenarios in `banks/abnamro/testdata/live-nl-*`:

- `connect`: consent for the commercial test account, code exchange, consent info, details.
- `data`: account, the three balances, booked activities over two pages, then the reservations.
- `refresh`, `disconnect` (revocation; old tokens then answer 401).
- `pay-sepa` (`ACCC`), `pay-reference` (CUR betalingskenmerk), `pay-crossborder` (USD to a US account, `ACCC`),
  `pay-rejected` (negative-scenario account: `RJCT`, `AM03`), `pay-cancel` (dated payment executed, `DELETE` 204,
  then `CANC`).

Test accounts: `NL12ABNA9999876523` (commercial), `NL62ABNA9999841479` (corporate), `NL58ABNA9999142181` (retail;
the negative payment scenario), `NL91ABNA9999428707`.

Sandbox quirks:

- The consent page's **Cancel** button answers `500 MESSAGE_SBX005_9999`, in a real browser too, so the
  `access_denied` callback is covered by unit tests only.
- The consent POST also answers 500 without `Origin`/`Referer` headers (scripting only).
- A refresh token could be used twice, although the docs say refreshing invalidates it. The SDK always stores the
  new one.
- `consentExpiresIn` is a fixed "2 days, 2 hours, 2 minutes, and 2 seconds"; the docs say 7 days.
- All reservations share one `id` (`2026-10-20-12:00:00.000000`), and card holds come with `CRDT`.
- An authorize URL that reached the consent application broken (once, from a scripting race) made every later
  attempt for that payment return `error=access_denied` ("Authentication failed").

## Still assumed

- Production authorize endpoint parameters (the same as the sandbox's, per the tutorials) and the production
  revocation endpoint.
- Real `consentExpiresIn` texts and reservation ids.
- Business access through Access Online works the same way (the docs say the consent application serves Internet
  Banking, Access Online and the mobile app).
