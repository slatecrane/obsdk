# Payments

One request shape for every bank. The steps that authorise a payment work like `Connect`. Each bank
publishes which fields it needs, so an app can build its payment form from data instead of writing
per-bank code.

## The model

```go
step, err := c.InitiatePayment(ctx, obsdk.PaymentRequest{
    Type: obsdk.PaymentSEPA,
    PSU:  obsdk.PSUContext{IP: ip, UserAgent: ua},
    Transfers: []obsdk.Transfer{{
        Amount:     obsdk.Money{Amount: "10.50", Currency: "EUR"},
        Creditor:   obsdk.Creditor{Name: "Jane Doe", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: iban}},
        Remittance: []string{"Invoice 42"},
    }},
})
for step.Kind != obsdk.StepDone { /* same loop as Connect: redirect, input, wait */ }
pay := step.Payment // pay.Ref identifies it later: c.PaymentStatus(ctx, pay.Ref, ...)
```

- **Type** names the scheme:
  - `sepa`, `sepa_instant` and `domestic` (in Sweden also to Bankgiro/Plusgiro numbers).
  - `crossborder` (SWIFT) and `internal` (between accounts of the same bank).
  - The type says nothing about how many transfers a payment has.
- **Transfers** is always a list. A bulk payment is just more than one transfer. `PaymentSpec.MaxTransfers`
  says how many a bank accepts (1 at most banks; Handelsbanken Sweden takes up to 30, or 100 for business, with one approval).
- **Accounts** are `Identifier{Scheme, Value}`: `IBAN`, `BBAN`, `SORT_CODE_ACCOUNT`, `BANKGIRO`, `PLUSGIRO`.
  Accounts returned by AIS use the same schemes, so they can be used as the payer account directly.
- **Debtor** is optional wherever the user can pick the account on the bank's page.
- **Session** is optional. Passing an AIS session reuses its login where the bank allows it. At banks
  that allow one token per user (Swedbank), a new login otherwise invalidates the user's AIS session.

## What a bank needs: `PaymentSpec`

`Info.PaymentTypes(country, segment)` lists the payment types a bank offers.
`Info.PaymentSpec(country, segment, type)` describes one type:

| Field | Meaning |
|---|---|
| `Fields[]` | Every request field the bank takes, by path (`transfers.creditor.name`, `debtor.account`, `execution_date`, ...), with `Use` (required / optional), `Schemes`, `MaxLength`, `MaxItems`, `Pattern`, `Options`, `Label` and `Note`. A field that is not listed is not supported. |
| `Ask` | The field may be left empty because it is collected later, either by an input step or on the bank's page. |
| `SchemeRules` | Extra limits for one scheme of the field, e.g. a pattern for `BBAN` only, plus a scheme-specific `Label` and `Note` for forms. |
| `OnlyWith` | The field is accepted only when another field uses one of the given schemes, e.g. an OCR reference only for `BANKGIRO`/`PLUSGIRO` payees. |
| `Currencies`, `MaxTransfers`, `ExecutionDateMaxDays` | Request limits. |
| `AuthApproaches` | `redirect`, `decoupled`. |
| `FinalStatuses` | The statuses the bank treats as final success. |
| `Cancellable` | Whether a payment can be cancelled before it is executed. |
| `StatusNeedsSession` | Whether `PaymentStatus` and `CancelPayment` need the user's session. |

`obsdk.ValidatePayment(spec, req)` checks a request without calling the bank and returns a
`*PaymentValidationError` that lists every problem by path and transfer index, so a form can mark every
field at once. `InitiatePayment` runs the same check first. Setting a field the bank does not support
is an error, so nothing is dropped silently.

Account numbers and references are also checked against their scheme, the same way at every bank:
IBAN and RF check digits (mod 97), Bankgiro, Plusgiro and OCR check digits (mod 10), the Finnish reference
(`FI`, weights 7-3-1), the Belgian structured communication (`BE`: 12 digits, the last two the first ten mod
97, written without `+++` and slashes), the Czech variable symbol (`CZ`: 1 to 10 digits, no check digit), and 14 digits for `SORT_CODE_ACCOUNT`. `obsdk.ValidateIdentifier` and `obsdk.ValidateReference` run these checks on their own.
The payment type stays generic: a Swedish payment to a Bankgiro number is a `domestic` payment whose
payee account has the scheme `BANKGIRO`.

Try it: `go run ./cmd/obdev payment-spec` lists the types for the configured bank, and
`obdev payment-spec sepa` prints one spec.

## Standing orders

A standing order is a payment request with a `Schedule`: the bank repeats the transfer instead of paying once.

```go
req.Schedule = &obsdk.Schedule{
    Frequency: obsdk.FrequencyMonthly, // daily, weekly, every_two_weeks, monthly, every_two_months, quarterly, semiannual, annual
    StartDate: "2026-11-05",           // first execution; its weekday or day of month is kept
    EndDate:   "2027-10-05",           // or Count (number of executions); neither: until cancelled
}
```

- `EndOfMonth` runs on the last day of each month (monthly or longer). `NonBusinessDay` (`following` /
  `preceding`) moves an execution that falls on a non-business day.
- A bank that offers standing orders for a type has a second spec for it, with `Schedule` set:
  `Info.StandingOrderSpec(country, segment, type)` (`Info.StandingOrderTypes` lists them, `Info.SpecFor(..., req)`
  picks the right one for a request). Its `ScheduleSpec` has the earliest start (`StartDateMinDays`) and the
  latest day of the month (`MaxDayOfMonth`). The schedule's options are ordinary fields (`schedule.frequency`
  with the offered frequencies as `Options`, `schedule.start_date`, `schedule.end_date`, `schedule.count`,
  `schedule.end_of_month`, `schedule.non_business_day`).
- `execution_date` is not used: the start date replaces it. A schedule sent to a one-off spec, or a request
  without one to a standing-order spec, fails validation.
- `StepDone` carries the `Payment` with its `Schedule`. Status and cancellation depend on the bank (see its spec).
- The model fits Berlin Group `periodic-payments` (`startDate`, `endDate`, `frequency`, `dayOfExecution` 31 for
  the month's end, `executionRule`) and UK OBIE standing orders (`Count` as `NumberOfPayments`). Česká spořitelna
  and Komerční banka implement it, and the Berlin Group adapter has periodic payments (`berlingroup.PeriodicSpec`;
  Samlink and the local ModelBank offer them so far).

Try it: `obdev payment-spec -standing domestic`, `obdev pay ... -every monthly -start 2026-11-05 -end 2027-10-05`.

## Flow and status

`InitiatePayment` returns steps, just like `Connect`. Some steps need the user: a login, an approval
on the bank's page, an app approval with polling, or a question only the bank can settle (for example
which account to pay from). Every step carries `Step.Payment` once the bank has created the payment, so
its id can be recorded even if the user abandons the approval. A failure after that point is a
`*FlowError` that carries the payment.

Authorisation and payment status are separate:

- `StepDone` means the user approved the payment and the bank accepted it. It does not mean the money
  arrived.
- `Payment.Status` is one of:
  - `received`, `accepted`, `in_progress`
  - `completed`, `partially_accepted` (more signers needed, or only some transfers accepted)
  - `rejected`, `cancelled`

  `BankStatus` keeps the bank's own code.
- `Payment.Final` means no further changes are expected. Poll `PaymentStatus(ref)` until it is set.

Errors:
- A bank refusal (daily limit, rejected at initiation) is `errors.Is(err, obsdk.ErrPaymentRejected)`,
  with a `*PaymentRejectedError` giving the reason.
- An approval the user cancelled or failed is `ErrAuthFailed`.

## Per bank

| | Swedbank | Revolut | ING | Nordea | HSBC (UK brands) | Rabobank | bunq | Handelsbanken | OP | KBC Group (KBC, CBC, KBC Brussels) | Sparkassen | Crosskey banks (S-Pankki, Aktia, POP, Ålandsbanken, Morrow) | Atruvia banks (Volksbanken Raiffeisenbanken, Sparda, PSD, DZ BANK, …) | SIBS banks (CGD, Millennium bcp, Novo Banco, Santander, BPI, …) | Samlink (Säästöpankki, Oma Säästöpankki) | Redsys banks (BBVA, CaixaBank, Santander, Sabadell, Bankinter, …) | Bankart banks (NLB, OTP banka, Sparkasse, …) | Coop Pank | ABN AMRO | BNP Paribas Fortis (Hello bank!, Fintro) | LUXHUB banks (Spuerkeess, POST, Raiffeisen, Banque de Luxembourg, …) | Komerční banka | Česká spořitelna |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Types | SE: `domestic` (incl. Bankgiro/Plusgiro), `crossborder`. EE/LV/LT: `sepa`, `sepa_instant`, `crossborder` | GB: `domestic` (GBP, sort code). EEA: `sepa` (EUR). All: `crossborder` | `sepa` (all 7 countries), `sepa_instant` (not RO), `domestic` (RO, RON), `crossborder` (not IT) | Personal only. FI: `sepa`, `sepa_instant`. SE: `domestic` (incl. Bankgiro/Plusgiro + OCR). DK, NO: `domestic` (NO with KID) | GB: `domestic` (Faster Payments, GBP, sort code; the reference is required: 18 characters, no spaces) | NL: `sepa` (EUR; sent instant when the payee bank can take it), `crossborder` | `sepa` (EUR; a draft payment, sent as SEPA or within bunq) | SE: `domestic` (SEK, incl. Bankgiro/Plusgiro + OCR; a signing basket of up to 30 transfers, business 100), `internal` (any currency), `sepa` (business). NL, LU: `sepa`. GB: `domestic` (Faster Payments) | `sepa` (EUR; OP sends it as SEPA Instant when it can; bundles of up to 20 transfers), `crossborder` (foreign payments, any currency) | `sepa` (EUR; KBC sends it instant where possible), `sepa_instant`, `crossborder` (non-SEPA, EUR, to an IBAN) | `sepa`, `sepa_instant` (EUR; one interface for about 345 Sparkassen, Landesbanken and Weberbank, picked by bank code) | FI (S-Pankki, Aktia, POP, Ålandsbanken): `sepa`, `sepa_instant` (EUR, through OBIE's international payment API). Ålandsbanken SE: `domestic` (SEK: Dataclearing, Bankgiro, Plusgiro + OCR). Morrow: `domestic` in FI (EUR), NO (NOK), SE (SEK). Resurs: none | `sepa`, `sepa_instant` (EUR, sent as pain.001.001.09; instant only at some banks; none at DZ BANK). One interface for about 670 banks, picked by bank code | `sepa`, `sepa_instant` (EUR; instant at most banks). One interface for 25 banks, picked by ASPSP code, BIC or IBAN. Names and descriptions in SIBS's restricted character set (no accented letters) | `sepa` (EUR, incl. dated up to 5 years ahead; the reference, Finnish or RF, travels as the end-to-end id; a reference or a message is required); standing orders (weekly to yearly, end date, month end, business-day rule) | `sepa`, `sepa_instant` (EUR; the account to pay from is required; no end-to-end id or structured reference). One interface for most Spanish banks, picked by the hub's bank code | `sepa` (EUR, incl. dated), `sepa_instant`. The account to pay from is picked at the login; one given here must be that one. Seven Slovenian banks, each on its own path | `sepa` (EUR, incl. dated; the account to pay from and the payee's town and country are required; no SEPA Instant) | `sepa` (EUR; description or `RF`/`CUR`/`BE` reference), `crossborder` (any currency, BIC required) | `sepa` (EUR, incl. dated up to a year ahead; description or `BE`/`RF` reference), `sepa_instant` (EUR, today only; `BE` reference only), `crossborder` (any currency; IBAN or BBAN; payee and payee bank town + country required). One bank key per brand | `sepa` at 15 banks, `sepa_instant` at 12 (EUR), as each bank's spec lists them (see [luxhub.md](luxhub.md)); the account to pay from is required. One bank key per bank, each on its own hosts | CZ: `domestic` (CZK to a Czech IBAN; variable symbol as an `obsdk.ReferenceCZ` reference), `sepa` (EUR, payee name required). The account to pay from is required; domestic standing orders (daily to yearly, end date or count) | CZ: `domestic` (CZK to a Czech IBAN; variable symbol as an `obsdk.ReferenceCZ` reference), `sepa` (EUR; payee name and country required, charges `SHA`). The account to pay from is required; domestic standing orders (monthly to yearly) |
| Login | Needs a user login first: a new one, or the one in `PaymentRequest.Session` | None: the approval itself is the login | None: the approval itself is the login | None: the signature itself is the login | None: the approval itself is the login | None: the approval itself is the login | Needs the session of an earlier Connect (`PaymentRequest.Session`) | None: the approval itself is the login | None: the approval itself is the login | None: the approval itself is the login | None: the approval itself is the login (embedded asks for the online banking login and PIN) | None: the approval itself is the login | None: the approval itself is the login (embedded asks for the online banking login (PSU-ID) and PIN) | None: the approval itself is the login | None: the approval itself is the login | A login first (OAuth2 pre-step, scope `PIS`), or the session of an earlier payment (`PaymentRequest.Session`) | A login first (OAuth2, scope `psd2:pay`); its token only creates the payment | None: the approval itself is the login | None: the approval itself is the login | None: the approval itself is the login | None: the approval itself is the login | Needs a payment login (scope `pisp`) first: a new one, or the payment login in `PaymentRequest.Session`; an AIS session can't pay | Needs a payment login (scope `PISP`) first: a new one, or the payment login in `PaymentRequest.Session` |
| Approval | Redirect, or app (BankID / Smart-ID / Mobile-ID) with polling | Redirect | Redirect | Redirect | Redirect | Redirect | In the bunq app, with polling (decoupled) | Redirect everywhere; Mobile BankID with polling (decoupled) in Sweden | Redirect | Redirect | Redirect (the OAuth SCA approach: authorisation code with PKCE), or embedded: login, TAN method (pushTAN, smsTAN, chipTAN manual/optical/QR) and TAN; pushTAN 2.0 users approve in the S-pushTAN app with polling | Redirect | Embedded: login, TAN method (Smart-TAN plus manual/optical, Smart-TAN photo) and TAN; SecureGo plus users approve in the app with polling (decoupled) | Redirect | Redirect (OAuth: `scaOAuth`, scope `PIS:<id>`) | Redirect (a second one, after the login) | Redirect (a second one, after the login) | Redirect | Redirect (consent application; the user may pick the debtor account) | Redirect (the user may pick the account to pay from; `businessLineName` RPB/CPB picks the app on mobile) | Redirect (OAuth2 authorisation code with PKCE, scope `PIS:<paymentId>`, at the bank's fixed authorisation endpoint) | Redirect to KB's signing page (a second redirect, after the login) | Redirect to ČS's federated signing page (a second redirect, after the login), then a poll of the signing (a `wait` step while it is processing) |
| Future-dated | `execution_date` | `execution_date`, through Revolut's scheduled-payment API (beta) | `execution_date` | `execution_date` | `execution_date`, through the scheduled-payment API | `execution_date` | No (bunq's scheduled drafts not implemented) | `execution_date` (not NL) | `execution_date`, through OP's scheduled SEPA payments | `execution_date` (not `sepa_instant`); KBC requires a date, so empty sends today | `execution_date` (not `sepa_instant`) | `execution_date` (scheduled payments; not Morrow) | `execution_date` (not `sepa_instant`) | `execution_date` (not `sepa_instant`) | `execution_date` (1 day to 5 years ahead) | `execution_date` (not `sepa_instant`) | `execution_date` (not `sepa_instant`) | `execution_date` (not today) | `execution_date` | `execution_date` (not `sepa_instant`); empty sends today | No | No: executed the same business day | `execution_date` (the payment must be signed by that date) |
| Cancel | Yes, while not executed | No (no endpoint) | Yes, while not executed; no user approval | Yes, while not executed, with the session the approval returned | No (no endpoint) | Yes, while not executed; Rabobank may ask the user to sign the cancellation (redirect step) | Yes, while the user hasn't answered: the draft is withdrawn (bunq then shows `REJECTED`) | Sweden: yes, while not executed, for a payment with one transfer; the user approves the cancellation (redirect or BankID) | Yes: an unapproved payment is revoked without the user; an approved one not yet executed needs the user's approval (redirect), one payment at a time | No (no endpoint) | Only before approval (`DELETE`); approved JSON single payments can't be cancelled (Finanz Informatik allows it only for pain.001) | Scheduled payments only, while not executed, with a client token (`DELETE`); no user approval | Before approval without the user (`DELETE`, 204); after approval only a future-dated `sepa` payment, with a TAN (cancellation authorisation). Needs `PSU.ID` | Future-dated payments, while not executed (`DELETE`); some banks ask the user to approve the cancellation (redirect) | No (only periodic payments can be cancelled); standing orders: `DELETE` (the sandbox answers 200 but keeps `ACSP`, so unverified) | Future-dated payments, while not executed (`DELETE`), with the payment's session; the bank may ask the user to approve | `DELETE`; the bank may ask the user to approve. Not run | Future-dated payments, while not executed (`DELETE`, 204; status `CNCL`); no user approval | Future-dated payments, while not executed (`DELETE`, 204), with the session the approval returned; no user approval | Future-dated payments, while not executed: the payment request sent back with `RJCT`/`DS02`, approved by the user (redirect); ends as `RJCT` reason `CUST` | No (not offered: which banks allow it is undocumented) | No: signed payments are irrevocable | No (no endpoint); an unsigned payment expires after 30 days |
| Status | With the user's session | With an app token; no session needed | With an app token; no session needed | No session needed | With an app token; no session needed | Client id and signature only; no session needed | With the user's session | With a client token; no session needed | With a client token; no session needed | QWAC only; no session needed | QWAC only; no session needed | With a client token; no session needed. SEPA reports `AcceptedSettlementCompleted` once settled on the payer's account | QSealC signature (production also QWAC); no session needed. Reported as pain.002 XML | Client id only in the sandbox; production QSealC signature and QWAC. No session needed | With the subscription key (sandbox) or API key and signature; no session needed | With the session the payment's steps returned (its token); QSealC signature | Client id (`X-IBM-Client-Id`; production also QWAC); no session needed | With the API key (production also QWAC); no session needed | With the session the approval returned (its token; refreshed for up to 30 days) | With a client token; no session needed | With a client token (client credentials, Basic auth); no session needed. QWAC and QSealC signature | Certificate only; no session needed | With the payment login's session (`PaymentCallOptions.Session`) |
| Verified | SE sandbox, 2026-10-14: domestic, Bankgiro + OCR and international with app approval, and a future-dated payment cancelled. Redirect approval and the Baltics are not run yet. | Fake bank only. The sandbox app still needs the `payments` scope. | NL sandbox, 2026-10-16: status reads (completed, rejected). Creation, approval and cancel against a fake server only: the sandbox stub accepts only bodies the SDK cannot produce. | FI and SE sandbox, 2026-10-16: SEPA, Bankgiro + OCR and a future-dated payment cancelled; FI instant, DK and NO also `Paid` (not recorded). | GB personal sandbox, 2026-10-17: a Faster Payment approved and executed (`ACSP`), status read. Scheduled payments and first direct / M&S not run. | NL sandbox, 2026-10-17: creation (SEPA, cross-border), every documented status, cancel (cancelled, already cancelled, needs signing). Signing a created payment can't be done in the sandbox (its redirect goes to the real online bank). | NL sandbox, 2026-10-17: draft created, approved (`completed`), withdrawn and read. Approval done as the account owner through the API, not in the app. | SE, NL, LU, GB sandbox, 2026-10-17: Bankgiro + OCR with BankID, internal, SEPA (SE business, NL, LU) and GB Faster Payments approved and executed; a future-dated payment cancelled. Business cancellation fails in the sandbox (`500`); bulk baskets against a fake server only. | FI sandbox, 2026-10-17: SEPA approved and executed (`Credited`), a dated payment (the sandbox executes it at once), status read, an unapproved payment revoked. Cancelling an approved payment, bundles and foreign payments against a fake server only. | Fake server and synthetic scenarios only: waiting for KBC's sandbox QWAC. | Synthetic scenarios only (embedded chipTAN, rejection for missing funds), built from Finanz Informatik's documentation: no test QWAC yet. | Sandboxes, 2026-10-18: SEPA settled at S-Pankki, POP and Ålandsbanken FI; SEPA Instant at Aktia (final at once); a scheduled S-Pankki payment created and cancelled (the sandbox keeps reporting `InitiationCompleted` after the `DELETE`); an Ålandsbanken SE account transfer (`AcceptedSettlementInProcess`); a Morrow FI payment settled. Bankgiro/Plusgiro and Morrow NO/SE payments against a fake server only. | Synthetic scenarios only (decoupled SecureGo plus, exempted instant, rejection after SCA, cancel before approval), built from Atruvia's documentation: the sandbox refuses self-signed certificates. | Sandbox, 2026-10-19 (static stub): `sepa` and `sepa_instant` created and status read (`ACCP`); `DELETE` answers `CANC` but the stub's status stays `ACCP`. The redirect approval against a fake server only (the stub sends no URL). | FI sandbox, 2026-10-19: Säästöpankki payments with a message, a Finnish reference and a date, approved (`ACFC` → `ACSC`) and refused; Oma Säästöpankki with an RF reference. 2026-10-26: Säästöpankki standing orders (monthly with an end date, quarterly at month end, refused), status read | BBVA sandbox, 2026-10-20: SEPA with its own login, approved and `ACSC`, status read with the session; a future-dated payment on that session (no login), approved, then cancelled with an approval redirect (`CANC`). `sepa_instant` not run | Fake server only: the NLB sandbox stub (2026-10-20) wants a non-standard wrapped body and answers only the spec's example values | EE sandbox, 2026-10-20: SEPA approved and `ACSC`, status read; a dated payment approved (`PDNG`) and cancelled | NL sandbox, 2026-10-21: SEPA (`ACCC`), CUR reference, USD cross-border (`ACCC`), rejected (`RJCT` AM03), dated payment cancelled. | Fortis sandbox, 2026-10-21: SEPA approved and `ACSC` (account picked at the bank), a dated payment approved (`ACCP`) and cancelled with approval (`RJCT` CUST), status read; `sepa_instant` approved and `ACSC`; SEPA and `sepa_instant` with a `BE` reference `ACSC`; `crossborder` in USD to a BBAN and to a GB IBAN, `ACSC` (the sandbox takes only EUR and USD). Payments through the `hellobank` and `fintro` keys not run. | Fake server only: the sandbox needs a LUXHUB organisation account (authorised or applying TPP). | CZ sandbox, 2026-10-23: domestic with a message and variable symbol signed (`ACTC` → `ACSP`), a second payment on the same payment login, status read. SEPA is created but the sandbox can't sign it (`500`). 2026-10-26: domestic standing orders (end date, count, saved login) signed (`ACSP`), status read | CZ sandbox, 2026-10-24: domestic (with a new login and on a saved payment login) and SEPA created, signing URL, poll and status run; every payment answer is a static stub (`ACTC`, `INSUFFICIENT_FUNDS`). 2026-10-25: domestic standing orders created, signed and polled (static stub) |

Details: [swedbank.md](swedbank.md#payments), [handelsbanken.md](handelsbanken.md#payments), [revolut.md](revolut.md#payments), [ing.md](ing.md#payments), [nordea.md](nordea.md#payments), [hsbc.md](hsbc.md#payments), [rabobank.md](rabobank.md#payments), [bunq.md](bunq.md#payments), [op.md](op.md#payments), [kbc.md](kbc.md#payments), [sparkassen.md](sparkassen.md#payments), [crosskey.md](crosskey.md#payments), [atruvia.md](atruvia.md#payments), [sibs.md](sibs.md#payments), [samlink.md](samlink.md#payments), [redsys.md](redsys.md#payments), [bankart.md](bankart.md#payments), [cooppank.md](cooppank.md#payments), [abnamro.md](abnamro.md#payments), [bnpparibasfortis.md](bnpparibasfortis.md#payments), [luxhub.md](luxhub.md#payments), [komercnibanka.md](komercnibanka.md#payments), [ceskasporitelna.md](ceskasporitelna.md#payments).

## Not yet

Bulk payments fit the model but are not implemented, and standing orders exist only at Česká spořitelna and Komerční banka so far:

- **Bulk:** more transfers in a request. Handelsbanken's Swedish signing basket and OP's authorisation bundles take them.
- **Standing orders:** `Schedule` on the request (above). The Berlin Group adapter supports them (periodic payments),
  offered by Samlink so far; not in OBIE or the other banks. Reading the user's existing
  standing orders: `obsdk.StandingOrderLister` (Česká spořitelna so far).

Swedbank has `bulk-payments`, `periodic-payments` and `signing-baskets`. Revolut has file payments and
standing orders. ING has periodic and bulk payments. Nordea has recurring payments, a 2SCA API and separate business payment APIs. HSBC has standing orders, international payments and VRP. Rabobank has periodic and bulk (pain.001) payments. bunq has multi-entry and scheduled draft payments. KBC has periodic and bulk (pain.001) payments. The Sparkassen have periodic, bulk (also instant) and pain.001 payments, and Target2 and cross-border single payments. Atruvia has periodic payments (pain.001 + JSON multipart), bulk SEPA payments and cross-border single payments (pain.001.001.09_AXZ_GBIC5). BNP Paribas Fortis has standing orders (Belgian payees only, fixed or variable amount) and pain.001 files (business). Multi-signer business payments surface as `partially_accepted`.
