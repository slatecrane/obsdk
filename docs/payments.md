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
  says how many a bank accepts (1 everywhere so far).
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
IBAN and RF check digits (mod 97), Bankgiro, Plusgiro and OCR check digits (mod 10), and 14 digits for
`SORT_CODE_ACCOUNT`. `obsdk.ValidateIdentifier` and `obsdk.ValidateReference` run these checks on their own.
The payment type stays generic: a Swedish payment to a Bankgiro number is a `domestic` payment whose
payee account has the scheme `BANKGIRO`.

Try it: `go run ./cmd/obdev payment-spec` lists the types for the configured bank, and
`obdev payment-spec sepa` prints one spec.

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

| | Swedbank | Revolut | ING | Nordea | HSBC (UK brands) | Rabobank | bunq |
|---|---|---|---|---|---|---|---|
| Types | SE: `domestic` (incl. Bankgiro/Plusgiro), `crossborder`. EE/LV/LT: `sepa`, `sepa_instant`, `crossborder` | GB: `domestic` (GBP, sort code). EEA: `sepa` (EUR). All: `crossborder` | `sepa` (all 7 countries), `sepa_instant` (not RO), `domestic` (RO, RON), `crossborder` (not IT) | Personal only. FI: `sepa`, `sepa_instant`. SE: `domestic` (incl. Bankgiro/Plusgiro + OCR). DK, NO: `domestic` (NO with KID) | GB: `domestic` (Faster Payments, GBP, sort code; the reference is required: 18 characters, no spaces) | NL: `sepa` (EUR; sent instant when the payee bank can take it), `crossborder` | `sepa` (EUR; a draft payment, sent as SEPA or within bunq) |
| Login | Needs a user login first: a new one, or the one in `PaymentRequest.Session` | None: the approval itself is the login | None: the approval itself is the login | None: the signature itself is the login | None: the approval itself is the login | None: the approval itself is the login | Needs the session of an earlier Connect (`PaymentRequest.Session`) |
| Approval | Redirect, or app (BankID / Smart-ID / Mobile-ID) with polling | Redirect | Redirect | Redirect | Redirect | Redirect | In the bunq app, with polling (decoupled) |
| Future-dated | `execution_date` | `execution_date`, through Revolut's scheduled-payment API (beta) | `execution_date` | `execution_date` | `execution_date`, through the scheduled-payment API | `execution_date` | No (bunq's scheduled drafts not implemented) |
| Cancel | Yes, while not executed | No (no endpoint) | Yes, while not executed; no user approval | Yes, while not executed, with the session the approval returned | No (no endpoint) | Yes, while not executed; Rabobank may ask the user to sign the cancellation (redirect step) | Yes, while the user hasn't answered: the draft is withdrawn (bunq then shows `REJECTED`) |
| Status | With the user's session | With an app token; no session needed | With an app token; no session needed | No session needed | With an app token; no session needed | Client id and signature only; no session needed | With the user's session |
| Verified | SE sandbox, 2026-10-14: domestic, Bankgiro + OCR and international with app approval, and a future-dated payment cancelled. Redirect approval and the Baltics are not run yet. | Fake bank only. The sandbox app still needs the `payments` scope. | NL sandbox, 2026-10-16: status reads (completed, rejected). Creation, approval and cancel against a fake server only: the sandbox stub accepts only bodies the SDK cannot produce. | FI and SE sandbox, 2026-10-16: SEPA, Bankgiro + OCR and a future-dated payment cancelled; FI instant, DK and NO also `Paid` (not recorded). | GB personal sandbox, 2026-10-17: a Faster Payment approved and executed (`ACSP`), status read. Scheduled payments and first direct / M&S not run. | NL sandbox, 2026-10-17: creation (SEPA, cross-border), every documented status, cancel (cancelled, already cancelled, needs signing). Signing a created payment can't be done in the sandbox (its redirect goes to the real online bank). | NL sandbox, 2026-10-17: draft created, approved (`completed`), withdrawn and read. Approval done as the account owner through the API, not in the app. |

Details: [swedbank.md](swedbank.md#payments), [revolut.md](revolut.md#payments), [ing.md](ing.md#payments), [nordea.md](nordea.md#payments), [hsbc.md](hsbc.md#payments), [rabobank.md](rabobank.md#payments), [bunq.md](bunq.md#payments).

## Not yet

Bulk payments, standing orders and periodic payments all fit the model but are not implemented:

- **Bulk:** more transfers in a request.
- **Standing orders:** a schedule on the request.

Swedbank has `bulk-payments`, `periodic-payments` and `signing-baskets`. Revolut has file payments and
standing orders. ING has periodic and bulk payments. Nordea has recurring payments, a 2SCA API and separate business payment APIs. HSBC has standing orders, international payments and VRP. Rabobank has periodic and bulk (pain.001) payments. bunq has multi-entry and scheduled draft payments. Multi-signer business payments surface as `partially_accepted`.
