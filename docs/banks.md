# Banks

Integrated banks and how far each is verified. The registry is the source of truth at runtime:
`obsdk.List` / `obsdk.Lookup`, or `go run ./cmd/obdev list`. A test in `banks/all` fails when a
registered bank is missing from this page.

Maturity levels are explained in [new-integration.md](new-integration.md#2-create-the-package).
Production is `unverified` for every bank: it needs real QWAC/QSealC certificates.

| Bank | Countries | Spec | Sandbox | Payments | Notes |
|---|---|---|---|---|---|
| `aktia` | FI | UK OBIE v3.1.6 (Crosskey platform, generic `internal/obie` adapter) | personal and business `sandbox_verified` (2026-10-18; open sandbox: crosskey.io signup, generated certificates) | `sepa`, `sepa_instant` (incl. scheduled, cancellable); a SEPA Instant payment settled in the sandbox | [crosskey.md](crosskey.md) |
| `alandsbanken` | FI, SE | UK OBIE v3.1.6 (Crosskey platform, generic `internal/obie` adapter) | FI and SE personal `sandbox_verified` (2026-10-18) | FI: `sepa`, `sepa_instant` (incl. scheduled); SE: `domestic` (Dataclearing, Bankgiro, Plusgiro + OCR, incl. scheduled); a FI SEPA payment settled and a SE account transfer accepted in the sandbox | [crosskey.md](crosskey.md) |
| `atruvia` | DE | Berlin Group 1.3 (generic adapter; embedded, incl. SecureGo plus decoupled; pain.001 payments; signed requests) | personal and business `experimental` (the sandbox needs a PSD2 test QSealC; self-signed ones are refused); one interface for about 670 Volksbanken Raiffeisenbanken, Sparda-Banken, PSD Banken, DZ BANK and private banks, each on its own host, picked by bank code | `sepa`, `sepa_instant` (pain.001.001.09); synthetic scenarios only | [atruvia.md](atruvia.md) |
| `bunq` | EEA (30) | custom (bunq API, OAuth) | NL personal and business `sandbox_verified` (2026-10-17, method `api_key`; OAuth consent needs the sandbox app, not run); others `experimental` | `sepa` as draft payments approved in the bunq app; created, approved, withdrawn and read in the sandbox | [bunq.md](bunq.md) |
| `cbc` | BE | Berlin Group (KBC Group, OAuth2 + PKCE for AIS) | personal and business `experimental` (shared sandbox needs KBC's test QWAC, requested 2026-10-17) | `sepa` (instant where possible), `sepa_instant`, `crossborder` (EUR); fake server and synthetic scenarios only | [kbc.md](kbc.md) (CBC Banque) |
| `firstdirect` | GB | UK OBIE v4.0 (HSBC) | personal `sandbox_verified` (2026-10-17) | `domestic` (Faster Payments); built like `hsbc`, not run for this brand | [hsbc.md](hsbc.md) |
| `handelsbanken` | SE, GB, NL, LU | custom (Berlin Group-like, OAuth per consent) | SE, GB, NL personal and business, LU personal `sandbox_verified` (2026-10-17) | SE: `domestic` (signing basket, up to 30/100 transfers, incl. Bankgiro/Plusgiro + OCR), `internal`, `sepa` (business); NL, LU: `sepa`; GB: `domestic` (Faster Payments); all created, approved and executed in the sandbox, SE cancel too | [handelsbanken.md](handelsbanken.md) |
| `hsbc` | GB, MT | UK OBIE (v4.0 UK, v3.1 Malta) | GB personal, GB business, MT personal `sandbox_verified` (2026-10-17) | UK: `domestic` (Faster Payments); approved and executed in the sandbox for GB personal | [hsbc.md](hsbc.md) |
| `ing` | BE, DE, ES, IT, LU, NL, RO | custom (Berlin Group-like, JWS-signed) | NL personal `sandbox_verified` (2026-10-16); others `experimental` | `sepa`, `sepa_instant`, `domestic` (RO), `crossborder`; status read in the sandbox, creation tested against a fake server | [ing.md](ing.md) |
| `kbc` | BE | Berlin Group (KBC Group, OAuth2 + PKCE for AIS) | personal and business `experimental` (shared sandbox needs KBC's test QWAC, requested 2026-10-17) | `sepa` (instant where possible), `sepa_instant`, `crossborder` (EUR); fake server and synthetic scenarios only | [kbc.md](kbc.md) |
| `kbcbrussels` | BE | Berlin Group (KBC Group, OAuth2 + PKCE for AIS) | personal and business `experimental` (shared sandbox needs KBC's test QWAC, requested 2026-10-17) | `sepa` (instant where possible), `sepa_instant`, `crossborder` (EUR); fake server and synthetic scenarios only | [kbc.md](kbc.md) (KBC Brussels) |
| `mandsbank` | GB | UK OBIE v4.0 (HSBC) | personal `sandbox_verified` (2026-10-17) | `domestic` (Faster Payments); built like `hsbc`, not run for this brand | [hsbc.md](hsbc.md) |
| `morrowbank` | FI, NO, SE | UK OBIE v3.1.6 (Crosskey platform, generic `internal/obie` adapter) | FI, NO and SE personal `sandbox_verified` (2026-10-18) | `domestic` (FI EUR, NO NOK, SE SEK); a FI payment settled in the sandbox | [crosskey.md](crosskey.md) |
| `nordea` | DK, FI, NO, SE | custom | FI personal and business `sandbox_verified` (2026-10-16); others `experimental` | personal: `sepa`, `sepa_instant` (FI), `domestic` (SE incl. Bankgiro/Plusgiro, DK, NO); created, signed and cancelled in the sandbox | [nordea.md](nordea.md) |
| `op` | FI | custom (OIDC request object, JWS-signed payments) | personal `sandbox_verified` (2026-10-17); business `experimental` | `sepa` (incl. dated; bundles of up to 20), `crossborder`; SEPA immediate and dated approved and executed in the sandbox, unapproved bundle revoked | [op.md](op.md) |
| `poppankki` | FI | UK OBIE v3.1.6 (Crosskey platform, generic `internal/obie` adapter) | personal `sandbox_verified` (2026-10-18) | `sepa`, `sepa_instant` (incl. scheduled, cancellable); a SEPA payment settled in the sandbox | [crosskey.md](crosskey.md) (POP Pankki) |
| `rabobank` | NL | custom (Berlin Group-like, draft-cavage signatures) | NL personal `sandbox_verified` (2026-10-17); business `experimental` | `sepa` (instant when reachable), `crossborder`; created, status and cancel run in the sandbox, signing not possible there | [rabobank.md](rabobank.md) |
| `resursbank` | DK, FI, NO, SE | UK OBIE v3.1.6 (Crosskey platform, generic `internal/obie` adapter) | personal `sandbox_verified` 2026-10-18 (DK, FI, NO, SE: cards, balances, transactions); credit cards only | none (AIS only) | [crosskey.md](crosskey.md) |
| `revolut` | GB, EEA (30) | UK OBIE | GB personal `sandbox_verified` (2026-10-14); others `experimental` | domestic, SEPA, cross-border; not run in the sandbox yet | [revolut.md](revolut.md) |
| `sibs` | PT | Berlin Group 1.3.12 (SIBS API Market, generic adapter; redirect; `v1-0-4` paths) | personal and business `experimental` (free sandbox 2026-10-19: payments run; its AIS stub refuses every bank code); one interface for 25 banks (CGD, Millennium bcp, Novo Banco, Santander, BPI, Crédito Agrícola, Montepio, Bankinter, ...), picked by ASPSP code, BIC or IBAN | `sepa`, `sepa_instant`; created and status read in the static sandbox | [sibs.md](sibs.md) |
| `spankki` | FI | UK OBIE v3.1.6 (Crosskey platform, generic `internal/obie` adapter) | personal `sandbox_verified` (2026-10-18); business `experimental` | `sepa`, `sepa_instant` (incl. scheduled, cancellable); a SEPA payment settled and a scheduled one cancelled in the sandbox | [crosskey.md](crosskey.md) (S-Pankki) |
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
