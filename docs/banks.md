# Banks

Integrated banks and how far each is verified. The registry is the source of truth at runtime:
`obsdk.List` / `obsdk.Lookup`, or `go run ./cmd/obdev list`. A test in `banks/all` fails when a
registered bank is missing from this page.

Maturity levels are explained in [new-integration.md](new-integration.md#2-create-the-package).
Production is `unverified` for every bank: it needs real QWAC/QSealC certificates.

| Bank | Countries | Spec | Sandbox | Payments | Notes |
|---|---|---|---|---|---|
| `revolut` | GB, EEA (30) | UK OBIE | GB personal `sandbox_verified` (2026-10-14); others `experimental` | domestic, SEPA, cross-border; not run in the sandbox yet | [revolut.md](revolut.md) |
| `swedbank` | SE, EE, LV, LT | custom | SE `sandbox_verified` (2026-10-14); Baltics `experimental` | SE domestic, Bankgiro, international and cancel run in the sandbox; Baltic SEPA unverified | [swedbank.md](swedbank.md) |

Maturity is recorded per variant, not per capability. The Payments column says how far payments
have been checked; [payments.md](payments.md) has the details.

What each row leaves unverified is listed at the end of the bank's notes.

## Running a bank's sandbox

Each bank folder has `sandbox.env.example`, listing what that bank's sandbox needs (app credentials,
certificates, test user) and where to get it. Copy it to `sandbox.env` (gitignored), fill it in, then:

```sh
set -a; . banks/<bank>/sandbox.env; set +a
go run ./cmd/obdev connect
```

Details: [new-integration.md](new-integration.md#sandbox-credentials).
