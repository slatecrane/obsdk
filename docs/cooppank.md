# Coop Pank integration notes (Estonia)

Coop Pank's PSD2 interface was built and is run for the bank by Tietoevry ("Tietoevry Open Banking"); the
portal footer still says TietoEvry. It is registered by [banks/cooppank](../banks/cooppank) on the generic
Berlin Group adapter ([berlin-group.md](berlin-group.md)) as bank `cooppank`, EE, personal and business.

Tietoevry's old shared host, `openbanking.api.tietoevry.com`, no longer resolves (checked 2026-10-20). The
platform now runs per bank, on the bank's own domain. Coop Pank is the only live instance we found; any
other Tietoevry bank would be a new profile with its own host and API key, built the same way.

Built and run against the sandbox on 2026-10-20 from the portal's specifications
(`/documentation/coop-xs2a-{accounts,payments,funds}.v1_3.yaml`) and its how-to page
(`/documentation/how-to/how-to.json`).

| | Sandbox | Production |
|---|---|---|
| API | `https://openbanking.cooppank.ee/sandbox/xs2a/v1.3` | `https://openbanking.cooppank.ee/live/xs2a/v1.3` |
| App key | `X-API-Key` (the application's key on the portal) | same, from the production application |
| mTLS | none | eIDAS QWAC, uploaded to the production application |
| Signature | none | none in the specification |
| Approach | redirect (`scaRedirect`) | same |
| Data | dynamic: payments become booked transactions on both test accounts | real |

## Access

- **Sandbox:** free. Register on https://openbanking.cooppank.ee. The form asks for an organisation name and
  registration number, a contact, and the PSD2 roles. Then add a sandbox application under My Apps with the
  redirect URI `https://example.com/callback`. The certificate step can be skipped on the sandbox. The
  application's API key goes into `OBSDK_EXTRA=api_key=…`.
- **Test users:** listed under My Sandbox: PSU 1 (`obcoop1`) and PSU 2 (`obcoop2`), each with its password
  shown there. "Reset the sandbox to initial state" restores the test data.
- **Production:** needs a PSD2 licence and an eIDAS certificate uploaded to the production application.
  Not done: we have no QWAC.

## Flows

- **Consent:** `POST /consents` with empty `accounts`, `balances` and `transactions` lists; the user picks
  the accounts at the bank (`ConsentBankOffered`). `validUntil` up to 180 days. The answer has an
  `scaRedirect` link to the bank's login page. After approval the bank returns to the bare
  `TPP-Redirect-URI`, without parameters; `Resume` reads the consent status.
- **Accounts:** `GET /accounts?withBalance=true` returns booked and expected balances.
- **Transactions:** `bookingStatus` is required (`booked`, `pending`, `both`); `dateFrom` at most 180 days
  back for a recurring consent (7 years for a one-off consent).
- **Payments:** `POST /payments/sepa-credit-transfers`, then the same redirect. The debtor account and the
  payee's address (at least `townName` and `country`) are required. `requestedExecutionDate` makes a dated
  payment; it cannot be today.
- **Cancellation:** `DELETE /payments/sepa-credit-transfers/{id}` answers `204`. The status is then `CNCL`.
- **Disconnect:** `DELETE /consents/{id}` (status `terminatedByTpp`; later calls get `401 CONSENT_INVALID`).

## How Coop Pank differs from the standard

- **`CNCL` for a cancelled payment.** ISO 20022 has `CANC`. `internal/bgstatus` maps both to cancelled.
- **No SEPA Instant.** The how-to lists `instant-sepa-credit-transfers`, `target-2-payments` and
  `cross-border-credit-transfers`, but the specification has only `sepa-credit-transfers` and
  `cross-border-credit-transfers`, and the sandbox answers `404 PRODUCT_UNKNOWN` for instant. Only `sepa` is
  registered. Cross-border payments are not built yet.
- **Links are host-relative and repeat the base path** (`/sandbox/xs2a/v1.3/consents/…`); the adapter's
  `PathVersion: "v1.3"` maps them back.
- **Remittance:** only one of unstructured and structured, except for payments within Estonia, where both
  are allowed.

## Sandbox notes

- The test data includes a multi-currency account: `EE634204278608993923` is listed twice, in EUR and SEK,
  with different resource ids. `StableID` includes the currency, so the two get different stable ids.
- The account `EE634204278608972555` ("Current / Card Account") has wrong IBAN check digits; the SDK refuses
  it as a payee.
- The sandbox writes "PSU 1" as the payee name of a transfer between its accounts, whatever was sent.
- A dated payment stays `PDNG` after approval.

## Verified against the sandbox (2026-10-20)

Recorded in `banks/cooppank/testdata/`:

| Scenario | What |
|---|---|
| `live-ee-connect` | consent, redirect approval as PSU 1, five accounts with balances |
| `live-ee-balances` | balances of one account |
| `live-ee-transactions` | a booked debit created by the sandbox payment |
| `live-ee-pay-sepa` | SEPA payment approved and `ACSC` |
| `live-ee-payment-status` | status read (`ACSC`) |
| `live-ee-pay-future` | dated SEPA payment approved, `PDNG` |
| `live-ee-cancel` | that payment cancelled (`204`, then `CNCL`) |
| `live-ee-refresh` | consent status read |
| `live-ee-disconnect` | consent deleted |

Assumed, not run: the business segment (the sandbox users are personal customers), production (QWAC), card
accounts, funds confirmation, cross-border payments, and the multilevel SCA flow for payments that several
users sign (`TPP-Explicit-Authorisation-Preferred`, status `PATC`).

## Payments

`sepa` (EUR), dated payments, cancellable while not executed. The debtor account and the payee's town and
country are required. See [payments.md](payments.md).
