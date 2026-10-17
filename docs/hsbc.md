# HSBC integration notes

HSBC runs the UK Open Banking (OBIE) standard for its retail brands. Every brand has its own hosts,
and they all share one consent page and one client registration. The integration registers three
bank keys:

| Bank key | Brand | Country, segment | OBIE version | Sandbox test user |
|---|---|---|---|---|
| `hsbc` | HSBC UK | GB personal | v4.0 | `customer01` |
| `hsbc` | HSBC UK Business | GB business | v4.0 | `customer04` |
| `hsbc` | HSBC Malta | MT personal | v3.1 | `customer35` |
| `firstdirect` | first direct | GB personal | v4.0 | `customer02` |
| `mandsbank` | M&S Bank | GB personal | v4.0 | `customer03` |

Every sandbox user's security code is `123456`. Account information is registered for all five brands.
Payments are registered for the UK brands only.

| | Sandbox | Production |
|---|---|---|
| API host | `https://secure.sandbox.ob.<domain>` | `https://api.ob.<domain>` |
| Authorisation page | `https://sandbox.ob.<domain>/obie/open-banking/v1.1/oauth2/authorize` | `https://ob.<domain>/...` (same path) |
| Token endpoint | `<API host>/obie/open-banking/v1.1/oauth2/token` | the same |
| Data APIs | `<API host>/obie/open-banking/{v4.0,v3.1}/{aisp,pisp}` | the same |
| Client authentication | `private_key_jwt` (PS256) over mutual TLS | the same |
| Certificates | issued by HSBC's test CA from your CSR | OBWAC or eIDAS QWAC/QSealC |

`<domain>` is `hsbc.co.uk`, `business.hsbc.co.uk`, `hsbc.com.mt`, `firstdirect.com` or
`mandsbank.com`. The issuer, the `aud` of request objects, is the API host.

Built from the HSBC UK Open Banking implementation guide (v4.0.1), HSBC's OpenAPI files for
Account Information and Payment Initiation v4.0, and the sandbox's discovery document
(`https://sandbox.ob.hsbc.co.uk/.well-known/openid-configuration`). The flow follows the Revolut
integration (same standard).

## What the integration needs

`Info.Requirements` lists these; `banks/hsbc/sandbox.env.example` shows where each comes from.

- `client_id` from the client registration. In the sandbox this is the project on
  developer.hsbc.com: the wizard takes your CSR, returns the certificates and registers the client.
- `redirect_url`: one of the redirect URIs in the software statement.
- **Transport certificate** (mutual TLS on every call). Build the client with `hsbc.HTTPClient`.
  HSBC's servers present public-CA certificates, so no extra roots are needed.
- **Signing key** (`Config.Seal`, RSA). `KeyID` is the kid HSBC registered: in the sandbox, the
  signing certificate's Subject Key Identifier in upper-case hex (`openssl x509 -noout -ext
  subjectKeyIdentifier`, without the colons). Payments also need `Seal.Certificate`, because its
  subject DN goes into the payment signature.

## Flows

**Connect** (redirect):

1. A client-credentials token (`scope=accounts`), authenticated with a client assertion: a PS256
   JWT with `iss` = `sub` = client id and `aud` = the token endpoint.
2. `POST .../aisp/account-access-consents` with the permissions and an empty `Risk`. The SDK always
   asks for `ReadAccountsBasic` and `ReadAccountsDetail`, and adds the balance and transaction
   clusters from the requested capabilities.
3. Redirect to the authorisation page with `response_type=code id_token`, `scope=openid accounts`,
   `nonce`, and a signed request object. The request object carries the consent id as an essential
   `openbanking_intent_id` claim (in `id_token` and `userinfo`), and `acr`
   `urn:openbanking:psd2:sca`. HSBC wants its `exp` no more than 30 minutes ahead; the SDK uses 10.
4. The callback comes back in the **URL fragment**: `#code=...&id_token=...&state=...`. The code is
   exchanged at the token endpoint (`grant_type=authorization_code`, with a client assertion). **The
   code is valid for one minute.**

**Refresh**: `grant_type=refresh_token`. The refresh token lives as long as the consent; with no
`ExpirationDateTime`, it never expires.

**Disconnect**: `DELETE .../aisp/account-access-consents/{id}` with a client token. Afterwards data
calls answer `403 U008`, which becomes `ErrReauthRequired`.

## Behaviors worth knowing

- **v4.0 vs v3.1.** The UK brands use the ISO codes of OBIE v4.0:
  - balances `ITBD`, `ITAV`, `CLBD`, `OPBD`;
  - entry status `BOOK`, `PDNG`;
  - `AccountCategory` plus `AccountTypeCode`.

  Malta uses the v3.1 names (`InterimBooked`, `Booked`, `AccountType` plus `AccountSubType`). The
  mapping takes both.
- **Account types**: `AccountTypeCode` (`CACC`, `SVGS`, `CARD`, ...) becomes `Account.Type` as is. The
  business sandbox also sends `WALT` (Global Wallet), which the spec's enum doesn't list.
  `Description` (for example `BMM ACCOUNT`) becomes `Product`.
- **Transactions**: most recent first, pending before booked. `RJCT` entries (the Global Money
  Account shows rejected ones) are skipped. `FUTR` and `INFO` count as pending. HSBC ignores the time
  in `fromBookingDateTime` and `toBookingDateTime`: a range covers whole days.
- **Pagination**: only `Links.Next`, passed through as the cursor. Page sizes vary (up to 400; 300
  for first direct and M&S credit cards), and HSBC says to rely on nothing but the next link. Next
  links for ranges older than 90 days live five minutes, extended by five on each use. The cursor
  must point at the API host, so the access token never goes anywhere else.
- **90 days (Article 10A)**: for the hour after the user's SCA, every permitted cluster is readable.
  After that, only accounts, balances and the last 90 days of transactions. A transactions request
  reaching further back answers `403` for the whole request, which becomes `ErrReauthRequired`.
  `Limits.HistoryWithoutStepUpDays` is 90.
- **Errors**: OBIE `{"Id", "Code", "Message", "Errors": [{"ErrorCode", "Message", "Path"}]}`. `Id` becomes
  `APIError.RequestID`. 401 on a data call → `ErrAccessExpired`; 403 → `ErrReauthRequired`; a failed
  refresh → `ErrReauthRequired`.
- No `x-fapi-financial-id` header is needed.

## Payments

UK brands, OBIE v4.0: single and future-dated **Faster Payments** in GBP, to a sort code and
account number.

1. A client-credentials token with `scope=payments`.
2. `POST .../pisp/domestic-payment-consents` (or `domestic-scheduled-payment-consents` when
   `execution_date` is set), signed with `x-jws-signature` and sent with an `x-idempotency-key`.
3. The redirect, as for Connect, with `scope=openid payments`.
4. Code exchange, then `POST .../pisp/domestic-payments` with the consent id and the **same**
   `Initiation`, signed again.
5. Status: `GET .../pisp/domestic-payments/{id}` with a client token. No session is needed.

The `x-jws-signature` is a detached JWS (PS256, `typ` `JOSE`, `cty` `application/json`). Its `crit`
lists three claims:

- `http://openbanking.org.uk/iat`;
- `http://openbanking.org.uk/iss`: the signing certificate's **full subject DN in RFC 2253 form, in
  the certificate's own attribute order** (what `openssl x509 -noout -subject -nameopt RFC2253`
  prints);
- `http://openbanking.org.uk/tan`: `openbanking.org.uk`. It can be overridden with `Extra["jws_tan"]`.

The SDK formats the DN from the raw subject. Go's `pkix.Name` reorders the attributes, and HSBC
rejects that order with `400 UK.OBIE.Signature.InvalidClaim`.

Field rules (implementation guide, section 18):

- The reference is required: `RemittanceInformation.Structured[0].CreditorReferenceInformation.Reference`,
  at most 18 characters from `A-Z a-z 0-9 & - . /`, **no spaces**. A credit-card payee needs
  at least 4 digits in it. The SDK takes it from `Transfers[0].Remittance[0]`.
- `LocalInstrument` is `UK.OBIE.FPS`; the debtor account, when given, is a sort code and account number.
- The end-to-end id is at most 31 characters (Faster Payments).
- `PaymentContext` maps to the v4.0 `Risk.PaymentContextCode` values (`TransferToThirdParty`, ...).

Statuses (v4.0 ISO codes, plus the v3.1 names):

- `PDNG` → accepted;
- `ACSP`, `ACWC` and similar → in progress;
- `ACSC`, `ACCC` → completed;
- `RJCT` → rejected;
- scheduled payments: `INCO` → in progress (final), `INFA` → rejected.

There is no cancel endpoint.

Not implemented:

- payments for Malta, whose PIS is v3.1;
- CHAPS, international payments, standing orders and VRP;
- business multi-authorisation flows.

## Verified against the real sandbox (2026-10-17)

All five sandbox variants are registered as `sandbox_verified`; production stays `unverified`.
One client registration, from the project on developer.hsbc.com, works on every brand's host.

Scenarios (`banks/hsbc/testdata/`):

- `live-gb-connect`, `live-gb-data`: HSBC UK personal (`customer01`). Connect (5 accounts: current,
  savings, Global Money, credit card), balances, transactions (100 on the first page, then 93 through
  the next link), refresh.
- `live-gb-disconnect`: the consent deleted; a later accounts call answered `403 U008`.
- `live-gb-pay-domestic`: a £10.50 Faster Payment, approved by the user, `ACSP`, then read by status.
- `live-fd-*`, `live-ms-*`, `live-biz-*`, `live-mt-*`: first direct, M&S Bank, HSBC UK Business (10
  business accounts) and HSBC Malta (v3.1). Each one: connect, accounts, balances and transactions.

Observed:

- The authorisation code expires one minute after login, so the callback has to be passed on at
  once. The brands share one consent-page session (`consent.sandbox.hsbc.com`), so log in to one
  brand at a time.
- M&S and Malta have no sandbox transactions in the last month; a range from 2020 returns some.
- Payment `Charges` in the response name `UK.OBIE.CHAPSOut` although the payment was FPS.

## Still assumed

- Production hosts (`api.ob.<domain>`, `ob.<domain>`) are taken from the guide and the sandbox naming.
  They have not been called.
- The 403 for transactions older than 90 days after the first hour: the sandbox sessions here never
  left that hour.
- Scheduled payments (`domestic-scheduled-*`) and their statuses: built from the spec, not run in
  the sandbox.
- Rate limits and their `Retry-After`.
