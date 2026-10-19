# Atruvia integration notes (Volksbanken Raiffeisenbanken, Sparda, PSD, DZ BANK)

Atruvia AG runs one Berlin Group NextGenPSD2 1.3 interface for the German cooperative banks and others:
about 600 Volksbanken and Raiffeisenbanken, 11 Sparda-Banken, 8 PSD Banken, DZ BANK and private banks
such as Airbus Bank, ABK, Warburg or UmweltBank (668 bank codes in the directory of 2026-10-19). It is
the second bank on the generic Berlin Group adapter ([berlin-group.md](berlin-group.md)): bank key
`atruvia`, DE, personal and business.

| | Sandbox | Production |
|---|---|---|
| API | `https://p1.xs2a-doc.atruvia.de/sandbox/psd2/v1` (fallback `p2.…`, `atruvia.SandboxFallbackRoot`), one host for all | per bank, from the Xs2aApiDirectory: `https://<bank's online banking host>/services_xs2a/bg13/v1` |
| mTLS | none | eIDAS QWAC |
| Signature | required on every call (QSealC); certificates checked with the EU DSS, so self-signed ones are refused | required; QSealC, DSS-checked since 2025-11-18 / 2026-01-22 |
| Approaches | embedded, decoupled (SecureGo plus) | same |

Built on 2026-10-19 from Atruvia's public documentation, linked from
https://atruvia.de/drittanbieter-schnittstelle-xs2a: the OpenAPI file ("1.3 + additional errata",
https://p1.xs2a-doc.atruvia.de/xs2a-openapi.yaml), the implementer options, the sandbox guide
(`TPP-Sandbox-Documentation.zip`, 2026-04-27), the release notes (2026-10-16) and the directory
(`Xs2aApiDirectory.json`).

## What the integration needs

- **QSealC** (`Config.Seal`, RSA): every request carries `Digest`, `Signature` and
  `TPP-Signature-Certificate`, also in the sandbox. The client refuses to start without it.
- **QWAC** for mTLS in production (`atruvia.HTTPClient(cert)`); the sandbox does not use mTLS.
- `bank_code` (`Config.Extra`): the bank's BLZ, one of its IBANs or its BIC (`atruvia.BankCode`). It
  picks the host from the embedded directory ([banks/atruvia/directory.json](../banks/atruvia/directory.json),
  `atruvia.Institutions()` / `atruvia.Lookup`), and is kept in the session, flow state and payment
  reference. A code not in the directory is refused. In the sandbox use `49999960`, the code of its test
  IBANs (`atruvia.SandboxBankCode`); every code reaches the same sandbox host.
- `PSU.ID`: the online banking login (VR-NetKey or alias). Atruvia wants `PSU-ID` on the consent, the
  payment and the cancellation. Connect and InitiatePayment ask for it (`psu_id`) when it's missing;
  CancelPayment refuses without `PaymentCallOptions.PSU.ID`.
- `PSU.IP`: `PSU-IP-Address` is mandatory on consents and payments.

No client id, no redirect URL: there is no redirect approach.

Refresh the directory after Atruvia's merger announcements (release notes, usually twice a year):

```sh
go run ./banks/atruvia/gendirectory     # downloads Xs2aApiDirectory.json, rewrites directory.json
```

Volksbank Mittelhessen lists its MEINE BANK brand (`www.meinebank.de`) under the same bank code
51390000; the directory keeps the first entry (`www.vb-mittelhessen.de`), and the other host is
reachable with `Config.Extra["base_url"]`. After a merger Atruvia accepts the old URLs for about a
month, then only the directory's.

## Signature

draft-cavage as in the Berlin Group guidelines, with Atruvia's details:

- `algorithm="rsa-sha256"`, SHA-256 `Digest` (also for empty bodies).
- `keyId="SN=<serial hex>,CA=<issuer DN>"` with the issuer **fully URL-encoded** (`atruvia.KeyID`;
  the OpenAPI example: `CA=CN%3DD-TRUST%20CA%202-1%202015%2CO%3DD-Trust%20GmbH%2CC%3DDE`).
- Signed headers: `digest x-request-id psu-id` (and `psu-corporate-id` when present). **Not `date`**:
  the OpenAPI example lists it, but the sandbox answers `FORMAT_ERROR "The header 'date' is not allowed
  for signature specification."` (seen 2026-10-19).

## Flows

Implementer options: redirect and OAuth are not offered; embedded and decoupled are, both through the
embedded authorisation (no `TPP-Redirect-Preferred` / `TPP-Decoupled-Preferred` headers are documented).
`ConnectRequest.Method` / `PaymentRequest.Method` is `embedded` (default) or `decoupled`; either way
the bank's steering links decide.

1. `POST /v1/consents` (or `/v1/payments/{product}`) with `PSU-ID`. Consents ask for all accounts
   (`allPsd2: allAccounts`, "global consent"); `Values["iban"]` gives a dedicated consent instead.
2. `startAuthorisationWithPsuAuthentication` with the PIN (`psuData.password`).
3. `selectAuthenticationMethod` when the user has several (the SDK shows them all):
   | Id | Type | Name | Notes |
   |---|---|---|---|
   | 946 | `PUSH_OTP` | SecureGo plus (Direktfreigabe) | approve in the app: decoupled, the SDK polls `scaStatus` |
   | 962 | `CHIP_OTP` 1.4 | Smart-TAN plus manuell | HHD start code in `challengeData`; until 2027-03-16 |
   | 972 | `CHIP_OTP` 1.4 | Smart-TAN plus optisch / USB | flicker code; until 2027-03-16 |
   | 982 | `PHOTO_OTP` | Smart-TAN photo | image in `challengeData.image`, as `Step.Challenge.ImageURL`; until at least 2030 |
4. `authoriseTransaction` with the TAN, or wait steps until `finalised` (decoupled).

SecureGo plus with TAN (944) was switched off on 2025-08-01. A payment within the SCA exemption
(amount limit, own account) can come back `exempted` right after the PIN.

**Disconnect:** `DELETE /v1/consents/{id}`.

## Data

- **Accounts** (`GET /v1/accounts`): IBAN only, `ownerName` with each account. `withBalance` is not
  supported (ignored in the sandbox), so the adapter leaves it out (`NoWithBalance`).
- **Balances:** `openingBooked`, `interimAvailable`, `closingBooked`.
- **Transactions:** JSON only, `bookingStatus=booked` (no `pending` or `both`); `information` would
  list standing orders and is not used. `dateFrom` is required without a `scrollRef`. Long lists are
  paged with a `next` link carrying `scrollRef`, passed through as the cursor.
  `remittanceInformationUnstructuredArray` carries the full purpose beyond 140 characters.
- Consent `frequencyPerDay` 4; a one-off consent stays usable for 5 minutes after its first use.

## Payments

| Type | Product | Notes |
|---|---|---|
| `sepa` | `pain.001-sepa-credit-transfers` | `execution_date` for future-dated payments |
| `sepa_instant` | `pain.001-instant-sepa-credit-transfers` | today only; offered by some banks only |

- **pain.001 only** ("pure JSON not supported"). The SDK builds pain.001.001.09 in the GBIC_5 profile
  (DFÜ-Abkommen Anlage 3 v3.9), supported since 2025-11-25 ([pain.go](../internal/berlingroup/pain.go)):
  one `PmtInf` with one transaction, `SvcLvl SEPA` (plus `LclInstrm INST` for instant: required since
  2025-10-09), `ChrgBr SLEV`, `DbtrAgt` and missing names/end-to-end ids as `NOTPROVIDED` (which Atruvia
  allows for `Dbtr/Nm`), `ReqdExctnDt` today in German time when no date is given. The sandbox
  validates against the XSD.
- pain.001.001.03 is still accepted: its end of life (2026-11-14) was postponed in October 2026.
- **Status** is a pain.002 report (`p1` sandbox: pain.002.001.03, `p2`: .001.10; production was to
  move to .001.10 in week 46/2026, then stays on .03 per the release notes of 2026-10-16). The SDK asks
  with `Accept: application/xml, application/json;q=0.9`, takes the most specific status (transaction,
  payment information, group) and puts the status reason (`AddtlInf`, else the reason code) in
  `Payment.Reason`.
- The debtor IBAN is required. Creditor BIC and a structured RF reference (`Strd/CdtrRefInf`, instead
  of the description) are optional.
- **Cancellation:** an unapproved payment is cancelled at once without SCA (`DELETE` → 204). After
  approval only a future-dated SEPA credit transfer can be cancelled, with a cancellation authorisation
  (embedded, TAN). `PSU-ID` is required.
- DZ BANK has no PIS ("This service is disabled for the DZ Bank AG"); its bank code still connects for
  AIS.
- Not implemented: `pain.001-cross-border-credit-transfers` (pain.001.001.09_AXZ_GBIC5; not
  cancellable), bulk payments, periodic payments (pain.001 + JSON multipart), confirmation of funds.

## Errors

The adapter's Berlin Group mapping applies: `CONSENT_EXPIRED`, `CONSENT_INVALID`, `CONSENT_UNKNOWN` →
`ReauthError`; 429 (the sandbox's answer to an exceeded frequency) → rate limited; wrong PIN or TAN
(`PSU_CREDENTIALS_INVALID`, `SCA_INVALID`) → `ErrAuthFailed`; `RJCT` → `PaymentRejectedError`;
`CERTIFICATE_INVALID` / `FORMAT_ERROR` stay `APIError`s.

## Sandbox

No registration; every call needs a valid signature with a test QSealC. The guide says "no validation
of the certificate path", but the DSS check is active: a self-signed certificate with PSD2 QC
statements was refused on 2026-10-19 with `401 CERTIFICATE_INVALID
"INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND"`. A PSD2 test certificate from a trust centre is needed
(the guide names Bundesdruckerei). Resources are deleted daily at 03:00.

| What | Values |
|---|---|
| PSU-IDs | `VRK1234567890SECPLUS` (946), `VRK1234567890SMART` (962, 972, 982), `VRK1234567890SMART2` (962, 982), `VRK1234567890ALL` (all four; the only one allowed payments without TAN); `…BLOCKED` variants of each; decoupled outcomes `VRK1234567890DECOUPLED{FIN,FAIL,PEN,BLOCKED}` and `…DECOUPLED2…` |
| PIN / TAN | `password` / `123456` |
| Payment IBANs | success with SCA `DE39499999600000005111`, SCA exemption `DE55…5114`, pending no funds `DE28…5115`, failed after SCA `DE98…5116`, invalid execution date `DE71…5117` |
| Consent IBAN | `DE87499999600000005120` |
| Account IBANs | `DE45499999600000005100` … `DE93499999600000005109`; standing orders and high volumes `DE60499999600000005121` |
| Mocked consents | `CONSENTVALID`, `CONSENTEXPIRED`, `CONSENTINVALIDACCOUNT`, `CONSENTINVALIDBALANCES`, `CONSENTINVALIDTRANSACTIONS`, `CONSENTTERMINATED`, `CONSENTFREQUENCYEXCEEDED`, `CONSENTREVOKEDBYPSU` |

Sandbox limits: a consent created there only runs the authorisation; account calls need a mocked
consent id. `GET /v1/consents/{id}/status` does not work (NISP AIS/Consent/G001b), so a sandbox
Connect probably ends in an error after the approval (the adapter reads it to finish): run the data calls with a session that carries
`CONSENTVALID` instead. Payments are not shown in transaction lists.

```sh
cp banks/atruvia/sandbox.env.example banks/atruvia/sandbox.env   # fill in the seal
set -a; . banks/atruvia/sandbox.env; set +a
go run ./cmd/obdev connect -method embedded     # PSU-ID VRK1234567890ALL, PIN password, TAN 123456
go run ./cmd/obdev pay -method decoupled        # PSU-ID VRK1234567890DECOUPLEDFIN
```

## Verified

Nothing against the real sandbox yet: no test QSealC. All variants are `experimental` (sandbox) or
`unverified` (production). Checked on 2026-10-19 with hand-made requests: the sandbox answers without
mTLS, wants `Digest` first, refuses a signed `date`, and refuses self-signed certificates.

Covered offline:

- Unit tests: pain.001 building and pain.002 reading (`internal/berlingroup/pain_test.go`), bank code
  / IBAN / BIC normalization, the directory, the URL-encoded keyId (Atruvia's example).
- Hand-written scenarios in `banks/atruvia/testdata` (generator: `research/atruvia/handwritten.py`,
  local): `de-hand-embedded-connect-phototan` (PSU-ID first, four methods, photo challenge),
  `de-hand-embedded-wrong-pin`, `de-hand-data` (mocked consent, accounts, balances, two pages via
  `scrollRef`, refresh), `de-hand-consent-expired`, `de-hand-decoupled-pay` (SecureGo plus polled,
  pain.002 ACSP), `de-hand-instant-exempted` (`exempted`, ACSC), `de-hand-pay-rejected` (Smart-TAN
  manual, RJCT with reason), `de-hand-cancel` (refused without PSU-ID, then 204 and CANC).

Assumed and to check on the first sandbox run: that a GBIC_5 pain.001 with `DbtrAgt NOTPROVIDED` and
`InitgPty/Nm NOTPROVIDED` passes the sandbox's XSD check; the authorisation response shapes (taken
from the standard, the OpenAPI file has no full examples); how a decoupled method is reported
(`chosenScaMethod` plus a `scaStatus` link only); whether production hosts need the QWAC's
organization registered first (release notes: certificates are checked by DSS since 2026-01-22, before
that they had to be sent in advance).
