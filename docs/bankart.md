# Bankart integration notes (NLB, OTP banka, Sparkasse and other Slovenian banks)

Bankart runs the PSD2 interface of seven Slovenian banks on one IBM API Connect platform. Each bank has its own
developer portal and API path; the interface is the same:

| Bank key | Bank | Code | Portal |
|---|---|---|---|
| `nlb` | NLB | `nlb` | https://openbanking.bankart.si/nlb/ |
| `otpbanka` | OTP banka (former Nova KBM and SKB; `/nkbm` redirects here) | `otp` | https://openbanking.bankart.si/otp/ |
| `sparkassesi` | Banka Sparkasse | `sparkasse` | https://openbanking.bankart.si/sparkasse/ |
| `gorenjskabanka` | Gorenjska banka | `gbkr` | https://openbanking.bankart.si/gbkr/ |
| `dezelnabanka` | Deželna banka Slovenije | `dbs` | https://openbanking.bankart.si/dbs/ |
| `hranilnicalon` | Hranilnica LON | `lon` | https://openbanking.bankart.si/lon/ |
| `primorskahranilnica` | Primorska hranilnica Vipava | `phv` | https://openbanking.bankart.si/phv/ |

All are registered by [banks/bankart](../banks/bankart) on the generic Berlin Group adapter
([berlin-group.md](berlin-group.md)): SI, personal and business. Bankart also sells a HUB
(`openbanking.bankart.si/hub`, path `psd2/hub`) that reaches every Slovenian bank through one subscription. It
is not registered: its routing isn't documented, and the banks' own interfaces cover the same banks.

Built on 2026-10-20 from the portals' API specifications and the "Support and FAQ" page. The specifications are
embedded in each API page (`drupalSettings`). The production specs (1.3.6.5, OpenAPI 3) are identical for all
seven banks, except for small differences in NLB's AIS spec; the sandbox specs (1.3.6, Swagger 2.0) are identical.
Run against the NLB sandbox on the same day; what that covers is below.

| | Sandbox | Production |
|---|---|---|
| AIS root | `https://api.bankart.si/psd2/<code>/sandbox/v1` | `https://api.bankart.si/psd2/<code>/v1` |
| Payments root | `https://api.bankart.si/psd2/<code>/sandbox/pay/v1` | `https://api.bankart.si/psd2/<code>/pay/v1` |
| Login (OAuth2) | `https://api.bankart.si/psd2/<code>/sandbox/oauth2/{authorize,token}` | `https://api-oauth.bankart.si/psd2/<code>/oauth/{authorize,token}` |
| App id | `X-IBM-Client-Id` on every request | same, plus the QWAC (the gateway authenticates the app by TLS certificate) |
| Signature | optional (Digest, Signature, TPP-Signature-Certificate "might be mandated") | same |
| Data | static | real |

## Access

- **Sandbox:** free. Create an account on a bank's portal (e.g. `/nlb/user/register`) and activate it from the
  e-mail. Create an app (Apps → Create New App) with the OAuth redirect URL. The form asks for a certificate:
  a self-signed one is accepted (we used RSA 2048, `C=SI, O=…, organizationIdentifier=PSDSI-…, CN=…`, kept in
  `banks/bankart/cert/`, ignored). Subscribe the app to "Account Information (Sandbox)" and "Payment initiation
  (Sandbox)". Until both subscriptions exist, every call answers `403 Not registered to plan` and the login
  `401 unauthorized_client`. The login page wants a user name and password; the developer-portal login worked,
  followed by an "Allow Access" screen without an account choice.
- **Simulation / production:** the app needs a valid eIDAS certificate uploaded and the Simulation or
  production plan; a simulation payment account is requested from psd2admin@bankart.si. Not done: no QWAC.

## Flows

- **Login first** (`PreStep`): the user is sent to `/authorize` with scope `psd2:acc` (Connect) or `psd2:pay`
  (payments), optionally `iban=` to name the account. The FAQ says the user picks one IBAN there and that the
  access token is a JWT whose `sub` is that IBAN, valid 5 minutes. The code is exchanged at `/token`
  (`client_id`, `client_secret`, PKCE verifier).
- **Consent:** `POST /v1/consents` with the bearer token, dedicated to that one IBAN (accounts, balances,
  transactions). One IBAN per consent; `allPsd2` and `availableAccounts` are "not supported". Then the user
  approves at `scaRedirect`; the consent status decides. Every later AIS call needs only `Consent-ID` and
  `X-IBM-Client-Id`: no token.
- **Payments:** `POST /pay/v1/payments/{product}` with a `psd2:pay` token. `debtorAccount` is required; when the
  request has none, the login's IBAN is used. Products: `sepa-credit-transfers`, `instant-sepa-credit-transfers`
  (production also lists `target-2-payments` and `cross-border-credit-transfers`, periodic and bulk payments;
  not offered here). Then `scaRedirect`; status, reads and cancellation need no token.
- **Transactions:** `bookingStatus` `booked` or `pending` (separate queries), `dateFrom` required, `page` /
  `pageSize`, `_links.next`. Older than 90 days only within 5 minutes of creating the consent.
- **Disconnect:** `DELETE /v1/consents/{id}`.

## How Bankart differs from the standard

Handled by profile knobs of the adapter:

- **The login token is only for creating** (`PreStep.CreateOnly`): it goes on the request that creates the
  consent or payment and is then dropped, never stored in the flow state or a session. Payments are read and
  cancelled without a session; `Refresh` only checks the consent.
- **The account comes from the token** (`PreStep.TokenAccount`): the JWT's `sub`, checked for the shape of an
  IBAN only (the sandbox's static IBANs fail the check digits). A named account (`Values["iban"]`, the payment's
  debtor) is passed to the login as `iban` (`PreStep.AccountParam`) and must be the one the user picked.
- **Payments under their own root** (`PaymentRoot: "pay"`).
- **`Initialized-By-PSU`** is required on every request (`PSUInitiatedHeader`): `true` on flow requests or when
  a PSU-IP-Address is known.
- **Gateway errors** come as `{"httpCode", "httpMessage", "moreInformation"}`; the adapter reads
  `moreInformation`.
- **An empty scaStatus** (`{}`, seen in the sandbox) after the redirect: the resource's own status decides.

## Sandbox (verified 2026-10-20, NLB)

The sandbox answers with static data and contradicts itself, so the obdev loop can't be completed and the
variants stay `experimental`:

- **Run for real:** the login (portal user, "Allow Access"), the code exchange (`client_secret` in the form is
  accepted), `POST /consents` with the bearer token (answers a fixed consent `6dd7e042-…` with a
  `scaRedirect` to `oauth2.testbank.com`, a placeholder that never returns), the payments root
  (`/sandbox/pay/v1`), and `Initialized-By-PSU`.
- **Recorded scenarios** (`testdata/live-si-*`): accounts, balances and booked transactions read with the
  consent id `12345` the FAQ documents (session written by hand), parsed by the adapter as in production.
- **Not like the documentation:** the sandbox token is opaque (154 characters, no JWT) and lives 1 hour with a
  refresh token (31 days); no account is chosen at the login, so the consent went out as `allPsd2` (accepted).
  Production is implemented as documented (JWT `sub`, 5 minutes).
- **Can't finish Connect:** `GET /consents/{id}/status` always answers `received`, while `GET /consents/{id}`
  says `valid`; `/authorisations/{id}` answers `{}`. Accounts come only for the FAQ's consent ids (`12345`,
  `1234567`); balances and transactions only under the account id `8735076338630656`, not the `resourceId`
  the account list returns. Booleans and numbers come as strings (`"recurringIndicator": "true"`).
- **Payments:** the sandbox wants the body wrapped as `{"paymentInitiationJson": {…}}` (the Swagger 2.0 spec's
  stand-in for `oneOf`) and answers a standard flat body with `500 {"error":"Error occurred!"}`. Wrapped, it
  answers `{}` except for the spec's exact example values, and then wraps its reply too
  (`{"paymentInitationRequestResponse201": {…}}`). The production spec has the standard flat body and reply,
  which the SDK sends; the sandbox's shape is not worked around. Payment status works for the FAQ's fixed ids
  (`73bafcc1-…` → `ACTC`).
- **Not run:** a real approval, refusal, disconnect, cancellation, pending transactions, the other six banks'
  sandboxes (each portal needs its own app), business users.

## Payments

| | |
|---|---|
| Types | `sepa` (incl. `execution_date`), `sepa_instant` (EUR) |
| Login | first, scope `psd2:pay`; the user picks the account to pay from |
| Approval | redirect (`scaRedirect`) after the login |
| Cancel | `DELETE` (the bank may ask for an approval); not run |
| Status | client id (production: QWAC); no session needed |
| Verified | not in the sandbox (static stub refuses the standard body, see above); against a fake server |
