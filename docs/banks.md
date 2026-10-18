# Banks

Integrated banks and how far each is verified. The registry is the source of truth at runtime:
`obsdk.List` / `obsdk.Lookup`, or `go run ./cmd/obdev list`. A test in `banks/all` fails when a
registered bank is missing from this page.

Maturity levels are explained in [new-integration.md](new-integration.md#2-create-the-package).
Production is `unverified` for every bank: it needs real QWAC/QSealC certificates.

| Bank | Countries | Spec | Sandbox | Payments | Notes |
|---|---|---|---|---|---|
| `bunq` | EEA (30) | custom (bunq API, OAuth) | NL personal and business `sandbox_verified` (2026-10-17, method `api_key`; OAuth consent needs the sandbox app, not run); others `experimental` | `sepa` as draft payments approved in the bunq app; created, approved, withdrawn and read in the sandbox | [bunq.md](bunq.md) |
| `cbc` | BE | Berlin Group (KBC Group, OAuth2 + PKCE for AIS) | personal and business `experimental` (shared sandbox needs KBC's test QWAC, requested 2026-10-17) | `sepa` (instant where possible), `sepa_instant`, `crossborder` (EUR); fake server and synthetic scenarios only | [kbc.md](kbc.md) (CBC Banque) |
| `firstdirect` | GB | UK OBIE v4.0 (HSBC) | personal `sandbox_verified` (2026-10-17) | `domestic` (Faster Payments); built like `hsbc`, not run for this brand | [hsbc.md](hsbc.md) |
| `handelsbanken` | SE, GB, NL, LU | custom (Berlin Group-like, OAuth per consent) | SE, GB, NL personal and business, LU personal `sandbox_verified` (2026-10-17) | SE: `domestic` (signing basket, up to 30/100 transfers, incl. Bankgiro/Plusgiro + OCR), `internal`, `sepa` (business); NL, LU: `sepa`; GB: `domestic` (Faster Payments); all created, approved and executed in the sandbox, SE cancel too | [handelsbanken.md](handelsbanken.md) |
| `hsbc` | GB, MT | UK OBIE (v4.0 UK, v3.1 Malta) | GB personal, GB business, MT personal `sandbox_verified` (2026-10-17) | UK: `domestic` (Faster Payments); approved and executed in the sandbox for GB personal | [hsbc.md](hsbc.md) |
| `ing` | BE, DE, ES, IT, LU, NL, RO | custom (Berlin Group-like, JWS-signed) | NL personal `sandbox_verified` (2026-10-16); others `experimental` | `sepa`, `sepa_instant`, `domestic` (RO), `crossborder`; status read in the sandbox, creation tested against a fake server | [ing.md](ing.md) |
| `kbc` | BE | Berlin Group (KBC Group, OAuth2 + PKCE for AIS) | personal and business `experimental` (shared sandbox needs KBC's test QWAC, requested 2026-10-17) | `sepa` (instant where possible), `sepa_instant`, `crossborder` (EUR); fake server and synthetic scenarios only | [kbc.md](kbc.md) |
| `kbcbrussels` | BE | Berlin Group (KBC Group, OAuth2 + PKCE for AIS) | personal and business `experimental` (shared sandbox needs KBC's test QWAC, requested 2026-10-17) | `sepa` (instant where possible), `sepa_instant`, `crossborder` (EUR); fake server and synthetic scenarios only | [kbc.md](kbc.md) (KBC Brussels) |
| `mandsbank` | GB | UK OBIE v4.0 (HSBC) | personal `sandbox_verified` (2026-10-17) | `domestic` (Faster Payments); built like `hsbc`, not run for this brand | [hsbc.md](hsbc.md) |
| `nordea` | DK, FI, NO, SE | custom | FI personal and business `sandbox_verified` (2026-10-16); others `experimental` | personal: `sepa`, `sepa_instant` (FI), `domestic` (SE incl. Bankgiro/Plusgiro, DK, NO); created, signed and cancelled in the sandbox | [nordea.md](nordea.md) |
| `op` | FI | custom (OIDC request object, JWS-signed payments) | personal `sandbox_verified` (2026-10-17); business `experimental` | `sepa` (incl. dated; bundles of up to 20), `crossborder`; SEPA immediate and dated approved and executed in the sandbox, unapproved bundle revoked | [op.md](op.md) |
| `rabobank` | NL | custom (Berlin Group-like, draft-cavage signatures) | NL personal `sandbox_verified` (2026-10-17); business `experimental` | `sepa` (instant when reachable), `crossborder`; created, status and cancel run in the sandbox, signing not possible there | [rabobank.md](rabobank.md) |
| `revolut` | GB, EEA (30) | UK OBIE | GB personal `sandbox_verified` (2026-10-14); others `experimental` | domestic, SEPA, cross-border; not run in the sandbox yet | [revolut.md](revolut.md) |
| `sparkassen` | DE | Berlin Group (generic adapter; OAuth SCA redirect with PKCE, embedded incl. pushTAN 2.0 decoupled; camt.052 transactions) | personal and business `experimental` (sandbox needs a PSD2 test QWAC); one interface for about 345 Sparkassen, Landesbanken and Weberbank, picked by bank code | `sepa`, `sepa_instant`; synthetic scenarios only | [sparkassen.md](sparkassen.md) |
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
