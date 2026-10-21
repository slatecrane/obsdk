# STET adapter

[internal/stet](../internal/stet) implements the STET PSD2 API (versions 1.4.x to 1.6.x) once. A STET bank is
a package that describes the bank with a `stet.Profile` and calls `stet.Register`. Banks on it:
[BNP Paribas Fortis, Hello bank!, Fintro](bnpparibasfortis.md).

Built from STET v1.6.3 and v1.4.2 (framework, functional model, interaction examples, OpenAPI files), then
adjusted where BNP Paribas Fortis's sandbox showed what real banks do.

## Model

- **No consent resource.** The user's OAuth2 authorization (authorization code, scope `aisp`) is the
  consent; the session holds the access and refresh tokens under consent kind `aisp`. With
  `ForwardConsent` the adapter runs STET's mixed model (A2): list the accounts, `PUT /consents` with every
  listed account, list again. Accounts without a `resourceId` are left out of `Accounts`.
- **History:** STET narrows the scope on refresh; more than 90 days needs the extra scope
  `extended_transaction_history` (`Scopes.History`, `-` for none).
- **Transactions:** `dateFrom`/`dateTo` (`dateTo` exclusive, so the day after `To` is sent), formatted by
  `DateQuery` (RFC 3339 by default). The cursor is the resolved `_links.next`; links to another host are
  refused. Entries with status `INFO` are dropped.
- **Payments:** a payment request created with a client-credentials token (scope `pisp`), approved by the
  user on the `consentApproval` link, then confirmed as `Confirmation` says: `client_token` (POST
  `/confirmation` with a client token), `authorization_code` (STET's enforced redirect: the approval link is
  an authorize URL and the code's token confirms) or `none` (the bank executes it). Report URLs are the
  redirect URL plus `state` (plus `error=payment_not_approved` on the failure URL). The payment id is the
  last segment of `Location`. SEPA, SEPA Instant and cross-border (no service level, no default charge bearer; the payee bank's BIC,
  name and address go in `creditorAgent`) (`initiatingParty` from Extra `initiating_party`).
- **Cancellation:** the payment request sent back with `CancelStatus` (default `CANC`) and reason `DS02`;
  the bank may answer with an approval link. `RJCT` with reason `DS02` or `CUST` reads as cancelled. The
  state of a cancellation callback is not checked (some banks reuse the payment's report URLs).
- **Disconnect:** revokes the refresh token where `RevokeURL` is set; otherwise reports `Failed` and drops
  the tokens.

## Profile options for banks' deviations

| Option | What it does | Used by |
|---|---|---|
| `ClientAuth` | `tls_client_auth` (default), `client_secret_post`, `client_secret_basic` | Fortis: post |
| `TokenScope` | send the AIS scope with the code exchange and the refresh | Fortis (500 without it) |
| `Query` | query parameters on every resource request, links included | Fortis sandbox: `brand` |
| `AuthParams` | extra authorize parameters | Fortis sandbox: `brand` |
| `Headers`, `PaymentHeaders` | headers on every resource request / on payment creation and cancellation | Fortis: `businessLineName` |
| `PaymentLevel` | beneficiary and `requestedExecutionDate` at payment level (always sent; now when no date) | Fortis |
| `AmountString` | amounts as JSON strings | Fortis |
| `CancelStatus` | status that asks for a cancellation | Fortis: `RJCT` |
| `AdjustPayment` | last changes to the body | Fortis: no `categoryPurpose`; cross-border addresses as `townName` only |
| `Signing.Headers`, `Signing.Expires` | the signed header list, with `(created)`/`(expires)` parameters | Fortis |
| `Signing.SandboxValue` | a placeholder `Signature` in the sandbox when no Seal is set; `Required` then holds for production only | Fortis |

Read side, always on: account currency next to `accountId` (STET 1.6), numeric `resourceId`/`entryReference`,
`additionalTransactionInformation` as a string or an object (its `endToEndReference` fills `EndToEndID`),
amounts as numbers or strings. Date-times are written without fractional seconds.

## Signing

Default (STET framework §3.5.1): `Digest` of the body and a draft-cavage `Signature` over `(request-target)`,
`Date`, `Content-Type` and `Content-Length` when there is a body, `Digest`, `X-Request-ID` and every `PSU-*`
header; `keyId` from `Seal.KeyID`. Token requests are not signed.

## Assumptions not yet checked against a production bank

- A `Digest` on GET requests (of the empty body).
- The signed header defaults.
- `requestedExecutionDate` as `YYYY-MM-DDT00:00:00+00:00`.
