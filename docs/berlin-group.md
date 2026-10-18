# Berlin Group adapter

[internal/berlingroup](../internal/berlingroup) implements the Berlin Group NextGenPSD2 XS2A interface
(1.3.x) once. A bank that runs the standard becomes a small package with a `berlingroup.Profile`. The
adapter is not a bank: users only ever see the banks built on it, under their own keys.

Built and verified on 2026-10-18 against adorsys' open-source ModelBank (XS2A-Sandbox 5.14), run
locally in Docker. Banks on it: `sparkassen` ([sparkassen.md](sparkassen.md)).

## What it covers

| Area | Covered |
|---|---|
| AIS consent | global (`allPsd2: allAccounts`), bank-offered (empty lists, the user picks at the bank), or dedicated to the IBANs in `ConnectRequest.Values["iban"]` (comma separated); `validUntil` clamped per profile, the granted one read back |
| SCA | redirect, decoupled and embedded, following the steering links the bank returns (`scaRedirect`, `startAuthorisation*`, `updatePsuIdentification`, `updatePsuAuthentication`, `selectAuthenticationMethod`, `authoriseTransaction`, `scaStatus`) for consents, payments and cancellations alike. Explicit and implicit authorisation start both work. The bank's choice wins over the preference sent, including an embedded flow that turns decoupled after the method choice (Sparkassen' pushTAN 2.0) |
| OAuth SCA | a `scaOAuth` (or `scaOAuth2`) link: RFC 8414 metadata, then an authorisation-code redirect with PKCE, scope `AIS:<consentId>` / `PIS:<paymentId>`. For consents the code is exchanged for tokens: account calls carry the bearer token, `Refresh` uses the refresh token, the token endpoint is kept in `Session.Meta`. For payments the status decides (no exchange) |
| Hubs | `Profile.Institution`: a `Config.Extra` parameter (e.g. the BLZ) picks one bank of a hub; it is stored in the session, the flow state and the payment reference, so later calls reach the same bank |
| Not yet | OAuth as a pre-step (Deutsche Bank-style), encrypted PSU authentication, signing baskets, multilevel SCA, periodic and bulk payments, card accounts |
| Data | accounts (`withBalance`), balances, transactions (booked, pending or both per profile) as JSON or camt.052/053/054 XML (`Profile.XMLTransactions`; parsed by content); `next` links passed through as the cursor; signed amounts, `creditDebitIndicator` on unsigned ones; 1.3.8 and older field shapes |
| Payments | single payments per payment product, status, cancellation (immediate 204, or approved through cancellation authorisations) |
| Refresh | there is no token: `Refresh` checks the consent status and asks for re-authorisation when it is not `valid` |
| Signing | Digest + draft-cavage `Signature` + `TPP-Signature-Certificate` with `Config.Seal` (RSA), SHA-256 or SHA-512, configurable `keyId` and `algorithm` |
| Errors | `CONSENT_EXPIRED` / `CONSENT_INVALID` / `CONSENT_UNKNOWN` → re-authorise; `ACCESS_EXCEEDED` and 429 → rate limited with `Retry-After`; `TOKEN_EXPIRED` → access expired; wrong login, TAN or method during authorisation → `ErrAuthFailed`; `PAYMENT_FAILED` or `RJCT` → payment rejected |

Steps use the shared field keys: `psu_id`, `password` (secret), `sca_method` (select) and `otp`. Passwords
and TANs are sent as soon as they arrive and are never put in `Step.State`. A redirect refusal arrives
as `error=access_denied`, because the adapter sends the redirect URL with that parameter added as
`TPP-Nok-Redirect-URI` (`Profile.NoNokRedirect` turns it off).

## Adding a Berlin Group bank

```go
package examplebank

func init() {
	berlingroup.Register(berlingroup.Profile{
		ID:   "examplebank-bg",
		Info: obsdk.Info{Bank: "examplebank", Name: "Example Bank", Variants: ..., Capabilities: ...,
			Payments: []obsdk.PaymentSpec{berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{...})}},
		BaseURL:    func(env obsdk.Env, t obsdk.Target, institution string) string { ... }, // without /v1
		Approaches: []string{berlingroup.Redirect, berlingroup.Decoupled},
		Products:   map[obsdk.PaymentType]string{obsdk.PaymentSEPA: "sepa-credit-transfers"},
	})
}
```

The profile carries everything that differs between banks: hosts, approaches, consent model, consent
limits, booking statuses, payment products and specs, whether PSU-ID is needed up front
(`PSUIDRequired`), field-shape versions (`LegacyAddress`, `StructuredRemittanceString`, which banks mix),
`NoWithBalance`, XML transactions, OAuth details (`OAuthNoRedirectURI`), hubs (`Institution`), signing,
and extra headers. If a bank needs more than a profile can say, add a field
or hook to the profile instead of copying the adapter. Then follow [new-integration.md](new-integration.md)
as for any bank: own docs page, row in [banks.md](banks.md), scenarios recorded against its sandbox.

## The local ModelBank

[internal/berlingroup/modelbank](../internal/berlingroup/modelbank) registers the ModelBank as bank
`modelbank` (DE, sandbox only). `banks/all` does not import it; only `cmd/obdev` and the tests do, so it
never shows up for users of the SDK.

### Running it

The current XS2A-Sandbox images are in a private registry. Release 5.14 is the last one on Docker Hub
(amd64 only; runs under emulation on Apple silicon, about five minutes to start):

```sh
git clone --depth 1 --branch 5.14 https://github.com/adorsys/xs2a-sandbox.git && cd xs2a-sandbox
# Optional: move ports that clash with local services, e.g. Keycloak off 8080:
cat > docker-compose.override.yml <<'EOF'
services:
  ledgers-keycloak:
    ports: !override
      - "18080:8080"
  xs2a-consent-management-db:
    ports: !override
      - "15432:5432"
EOF
docker compose -p xs2a up -d     # XS2A on :8089, online banking on :4400, TPP API on :8093
```

The connector runs with a mocked QWAC (profile `mock-qwac`), so no certificate is needed.

### Test users

Register a TPP and let the sandbox generate users, accounts and payments:

```sh
curl -X POST localhost:8093/tpp/register -H 'Content-Type: application/json' \
  -d '{"id":"DE_36686519","email":"tpp@example.com","login":"obsdk-tpp","pin":"12345"}'
TOKEN=$(curl -si -X POST localhost:8093/tpp/login -H 'login: obsdk-tpp' -H 'pin: 12345' | awk -F': ' 'tolower($1)=="access_token"{print $2}' | tr -d '\r')
curl -H "Authorization: Bearer $TOKEN" 'localhost:8093/tpp/data/generate/EUR?generatePayments=true' > users.yml
```

Logins look like `DE_36686519_EmbeddedSca-1a`, all with PIN `12345`. The generated users all have one
e-mail TAN method:

- **Embedded:** the sandbox prints the TAN in `challengeData.additionalInformation` ("tan is …"), so
  embedded flows can be scripted end to end.
- **Redirect:** the online banking page (localhost:4400) asks for the e-mailed TAN, but nothing ends up
  in the fake mail server. Give the user a static TAN first (`PUT /tpp/users` with
  `usesStaticTan: true, staticTan: "123456"` on its method).
- **Two methods:** add a second method with `PUT /tpp/users` to see the method-selection step. Only
  e-mail methods can be completed (others give `SCA_METHOD_UNKNOWN`).
- **Decoupled:** nothing on the sandbox confirms a decoupled approval: generated users have no
  decoupled method, and confirming one means answering the online banking backend's websocket
  message. Decoupled is covered by hand-written scenarios.

The ASPSP profile can be changed at runtime (`PUT localhost:48080/api/v1/aspsp-profile/for-debug/aspsp-settings`),
e.g. to require signatures or offer pending transactions.

### obdev

```sh
export OBSDK_BANK=modelbank OBSDK_COUNTRY=DE OBSDK_ENV=sandbox OBSDK_CLIENT_ID=none \
       OBSDK_REDIRECT_URL=https://app.example/callback OBSDK_PSU_IP=203.0.113.7 \
       OBSDK_SESSION_FILE=/tmp/modelbank.session.json
go run ./cmd/obdev connect -method embedded        # asks login, PIN, TAN
go run ./cmd/obdev pay -method embedded -type sepa -amount 1.00 -currency EUR \
  -from DE66366865190000000016 -to DE72366865190000000005 -name 'Default Creditor' -e2e e2e-1
go run ./cmd/obdev cancel-payment REF -method embedded
```

After a redirect approval the sandbox sends the user to the bare redirect URL; paste that URL as the
callback.

## ModelBank quirks

Each one is handled in the ModelBank profile, not in the adapter:

- Without `TPP-Redirect-Preferred` it picks EMBEDDED, the first approach in its profile.
- A payment without `endToEndIdentification` is accepted, then fails at the password step with
  `PSU_CREDENTIALS_INVALID`. The ModelBank spec makes the end-to-end id required.
- `remittanceInformationStructured` must be a string (pre-1.3.8), while addresses use the 1.3.8 names.
  Even as a string, a structured reference makes the authorisation fail with `FORMAT_ERROR`, so the
  ModelBank spec has no reference field.
- `bookingStatus=both` and `pending` are refused (`PARAMETER_NOT_SUPPORTED`), and transactions are not
  paginated. The two-page case is a hand-written scenario.
- Responses always carry a mocked `scaMethods` entry and a WARNING `tppMessage`; the adapter ignores
  warnings.

## Verified (2026-10-18, ModelBank 5.14)

Recorded in `internal/berlingroup/modelbank/testdata`:

| Scenario | What ran |
|---|---|
| `de-embedded-data` | embedded connect with method selection, accounts, balances, transactions, refresh, disconnect |
| `de-embedded-history` | embedded connect of a four-account user, transactions of two accounts |
| `de-embedded-wrong-tan` | wrong TAN → `ErrAuthFailed` |
| `de-embedded-pay-cancel` | future-dated SEPA payment (ACSP), status, cancellation with its own embedded authorisation (CANC) |
| `de-embedded-pay-instant` | SEPA Instant payment, completed (ACCC) |
| `de-redirect-connect` | redirect connect approved on the online banking page |
| `de-pay-validation` | a request the spec refuses before any call |

Hand-written (the sandbox can't produce them): `de-hand-transactions-pages` (next link, unsigned debit,
structured reference object, foreign cursor refused), `de-hand-consent-expired`, `de-hand-rate-limited`,
`de-hand-decoupled-connect`, `de-hand-decoupled-rejected`, `de-hand-redirect-refused`.

Not verified anywhere: decoupled against a real server, request signing against a server that checks it
(unit-tested only), bank-offered and dedicated consents, the OAuth SCA approach and camt parsing (fake
bank, unit tests and Sparkassen's hand-written scenarios only). ModelBank 5.14 has an OAuth mode
(`scaRedirectFlow: OAUTH`), but it is not the standard one: the metadata link is called `scaRedirect`,
the callback has no `state` and there is no PKCE, so it was not used to verify the adapter.
