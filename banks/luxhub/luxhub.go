// Package luxhub registers the banks whose PSD2 interface runs on LUXHUB's
// platform (Luxembourg): Spuerkeess, POST Luxembourg, Banque Raiffeisen,
// Banque de Luxembourg, DNB Luxembourg, Svea Bank, Swissquote and about
// twenty private and corporate banks. Each bank has its own hosts (mostly
// <code>-psd2api.luxhub.com, a few on their own domain); the interface is the
// same.
//
// It is Berlin Group NextGenPSD2 1.3 (2019-02-15) inside OAuth2: consents and
// payments are created and read with a client-credentials token (scope AIS,
// or PIS:payment), the user approves them in an authorisation-code flow with
// PKCE scoped to the resource (AIS:<consentId>, PIS:<paymentId>) at the
// bank's "-cb" host, and the code exchange gives the token the account calls
// carry, with a refresh token. Every request goes over mTLS (QWAC) and is
// signed (draft-cavage, QSealC). The client id and secret come from an
// application on LUXHUB's developer portal.
//
// The sandbox (static data, generic users, OTP 123456, mock QWAC/QSealC from
// the portal) is open only to organisations of authorised or applying TPPs;
// a personal portal account sees no bank API. Built from the portal's
// documentation and each bank's OpenAPI file on 2026-10-21, not run against
// any server. See docs/luxhub.md.
//
// Not covered: BGL BNP Paribas (STET on LUXHUB), the banks on Berlin Group
// v2 (JWS signatures: Bank of Communications, Northern Trust), the CBPII
// extensions and banks with a sandbox only.
package luxhub

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// hosts are a bank entity's API root (before "/v1"), token endpoint and
// authorisation endpoint in one environment.
type hosts struct{ api, token, authorize string }

// entity is one bank entity on the platform, in one country.
type entity struct {
	country obsdk.Country
	code    string // the entity's host prefix on luxhub.com (its BIC8, lower case)
	live    *hosts // own domain (production); nil: derived from code
	sandbox *hosts // own domain (sandbox); nil: derived from code
}

type bank struct {
	key, name, group string
	entities         []entity
	sepa, instant    bool     // sepa-credit-transfers / instant-sepa-credit-transfers offered
	booking          []string // bookingStatus values the bank accepts; nil: booked, pending and both
	business         bool     // private and corporate banking only: no personal variant
}

func (e entity) hosts(env obsdk.Env) hosts {
	if env == obsdk.Production && e.live != nil {
		return *e.live
	}
	if env != obsdk.Production && e.sandbox != nil {
		return *e.sandbox
	}
	sfx := "-sbx"
	if env == obsdk.Production {
		sfx = ""
	}
	api := "https://" + e.code + "-psd2api" + sfx + ".luxhub.com"
	return hosts{api: api + "/bg", token: api + "/api/oauth/token",
		authorize: "https://" + e.code + "-cb" + sfx + ".luxhub.com/api/oauth/authorize"}
}

func own(api, cb string) *hosts {
	return &hosts{api: "https://" + api + "/bg", token: "https://" + api + "/api/oauth/token",
		authorize: "https://" + cb + "/api/oauth/authorize"}
}

// banks are the Berlin Group v1 banks with a production API on the platform
// (LUXHUB's catalogue, 2026-10-21). Payment products are those each bank's
// OpenAPI file lists.
var banks = []bank{
	{key: "spuerkeess", name: "Spuerkeess (BCEE)", sepa: true, instant: true, entities: []entity{{country: "LU",
		live: own("openbank.bcee.lu", "cbopenbank.bcee.lu"), sandbox: own("sbopenbank.bcee.lu", "cbsbopenbank.bcee.lu")}}},
	{key: "postluxembourg", name: "POST Luxembourg", sepa: true, instant: true, entities: []entity{{country: "LU", code: "ccpllull"}}},
	{key: "raiffeisenlu", name: "Banque Raiffeisen", sepa: true, instant: true, booking: []string{"booked"}, entities: []entity{{country: "LU", code: "ccralull"}}},
	{key: "banquedeluxembourg", name: "Banque de Luxembourg", group: "Crédit Mutuel Alliance Fédérale", sepa: true, instant: true,
		entities: []entity{{country: "LU", code: "bluxlull"}, {country: "BE", code: "bluxbe41"}}},
	{key: "banquetransatlantique", name: "Banque Transatlantique", group: "CIC (Crédit Mutuel Alliance Fédérale)", sepa: true, instant: true,
		entities: []entity{{country: "LU", code: "cmcilul1"}, {country: "BE", code: "cmcibeb1"}}},
	{key: "dnbluxembourg", name: "DNB Luxembourg", group: "DNB", business: true, sepa: true, instant: true, entities: []entity{{country: "LU", code: "ubnllull"}}},
	{key: "svea", name: "Svea Bank", entities: []entity{{country: "SE", code: "sveasess"}}},
	{key: "swissquotelu", name: "Swissquote Bank Europe", group: "Swissquote", sepa: true, entities: []entity{{country: "LU", code: "swqblull"}}},
	{key: "seb", name: "SEB (Luxembourg and Oslo branches)", group: "SEB", business: true, sepa: true, entities: []entity{
		{country: "LU", live: own("tpp-api.sebgroup.lu", "tpp-apicb.sebgroup.lu"), sandbox: own("tpp-api-sbx.sebgroup.lu", "tpp-apicb-sbx.sebgroup.lu")},
		{country: "NO", live: own("tpp-api.seb.no", "tpp-apicb.seb.no"), sandbox: own("tpp-api-sbx.seb.no", "tpp-apicb-sbx.seb.no")}}},
	{key: "juliusbaerlu", name: "Julius Baer Luxembourg", group: "Julius Baer", business: true, sepa: true, instant: true, entities: []entity{{country: "LU", code: "baerlulu"}}},
	{key: "ubp", name: "Union Bancaire Privée (Europe)", group: "UBP", business: true, sepa: true, entities: []entity{{country: "LU",
		live: own("openapi.ubp.com", "openapicb.ubp.com"), sandbox: own("openapi-sbx.ubp.com", "openapicb-sbx.ubp.com")}}},
	{key: "andbanklu", name: "Andbank Luxembourg", group: "Andbank", business: true, sepa: true, instant: true, entities: []entity{{country: "LU", code: "bacalull"}}},
	{key: "bankinterlu", name: "Bankinter Luxembourg", group: "Bankinter", business: true, entities: []entity{{country: "LU", code: "bkbklull"}}},
	{key: "safralu", name: "Banco Safra (Luxembourg branch)", group: "Safra", business: true, sepa: true, instant: true, booking: []string{"booked", "both"}, entities: []entity{{country: "LU", code: "bsaflull"}}},
	{key: "bpplu", name: "Banque de Patrimoines Privés", group: "Crèdit Andorrà", business: true, entities: []entity{{country: "LU", code: "bbpplull"}}},
	{key: "bnpwmde", name: "BNP Paribas Wealth Management Germany", group: "BNP Paribas", business: true, sepa: true, entities: []entity{{country: "DE", code: "bnpadeff"}}},
	{key: "caixabankwmlu", name: "CaixaBank Wealth Management Luxembourg", group: "CaixaBank", business: true, entities: []entity{{country: "LU", code: "caixlull"}}},
	{key: "ccbeurope", name: "China Construction Bank (Europe)", group: "China Construction Bank", business: true, instant: true, entities: []entity{{country: "LU", code: "pcbclule"}}},
	{key: "ccbbranches", name: "China Construction Bank (Luxembourg and Frankfurt branches)", group: "China Construction Bank", business: true, instant: true,
		entities: []entity{{country: "LU", code: "pcbclull"}, {country: "DE", code: "pcbcdeff"}}},
	{key: "cmbeurope", name: "China Merchants Bank (Europe)", group: "China Merchants Bank", business: true, entities: []entity{{country: "LU", code: "cmbclulu"}}},
	{key: "cmbluxembourg", name: "China Merchants Bank (Luxembourg branch)", group: "China Merchants Bank", business: true, entities: []entity{{country: "LU", code: "cmbclull"}}},
	{key: "eurobanklu", name: "Eurobank Private Bank Luxembourg", group: "Eurobank", business: true, entities: []entity{{country: "LU", code: "erbklull"}}},
	{key: "intesawmlu", name: "Intesa Sanpaolo Wealth Management", group: "Intesa Sanpaolo", business: true, entities: []entity{{country: "LU", code: "cbpxlull"}}},
	{key: "threesmoney", name: "3S Money", business: true, sepa: true, instant: true, entities: []entity{{country: "LU", code: "molulu22"}}},
	{key: "sogexia", name: "Sogexia", sepa: true, entities: []entity{{country: "LU", code: "soxalull"}}},
}

func (b bank) bookingStatuses() []string {
	if b.booking != nil {
		return b.booking
	}
	return []string{"booked", "pending", "both"}
}

func (b bank) entity(country obsdk.Country) (entity, bool) {
	for _, e := range b.entities {
		if e.country == country {
			return e, true
		}
	}
	return entity{}, false
}

// endpoint returns one of a bank entity's endpoints for a target.
func (b bank) endpoint(pick func(hosts) string) func(obsdk.Env, obsdk.Target, string) string {
	return func(env obsdk.Env, t obsdk.Target, _ string) string {
		e, ok := b.entity(t.Country)
		if !ok {
			return ""
		}
		return pick(e.hosts(env))
	}
}

// keyID is LUXHUB's keyId: the serial number in lower-case hex and the
// issuer DN in RFC 2253 form, as its signing examples show.
func keyID(cert *x509.Certificate) string {
	return fmt.Sprintf("SN=%x,CA=%s", cert.SerialNumber, cert.Issuer.String())
}

// clientAuth authenticates at the token endpoint with HTTP Basic, as every
// example of the platform does; the client id is not repeated in the form.
func clientAuth(cfg obsdk.Config, _ string, form url.Values, h http.Header) error {
	if cfg.Credentials.ClientSecret == "" {
		return &obsdk.ConfigError{Env: cfg.Env, Missing: []string{"client_secret"}}
	}
	form.Del("client_id")
	r := &http.Request{Header: h}
	r.SetBasicAuth(url.QueryEscape(cfg.Credentials.ClientID), url.QueryEscape(cfg.Credentials.ClientSecret.Reveal()))
	return nil
}

var approaches = []string{berlingroup.Redirect}

func (b bank) specs() []obsdk.PaymentSpec {
	var out []obsdk.PaymentSpec
	if b.sepa {
		out = append(out, berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{Address: true, Approaches: approaches}))
	}
	if b.instant {
		out = append(out, berlingroup.CreditTransferSpec(obsdk.PaymentSEPAInstant, berlingroup.SpecOptions{Address: true, Approaches: approaches}))
	}
	return out
}

func profile(b bank) berlingroup.Profile {
	var variants []obsdk.Variant
	segments := []obsdk.Segment{obsdk.Personal, obsdk.Business}
	if b.business {
		segments = segments[1:]
	}
	for _, e := range b.entities {
		for _, s := range segments {
			variants = append(variants,
				obsdk.Variant{Country: e.country, Segment: s, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
				obsdk.Variant{Country: e.country, Segment: s, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified})
		}
	}
	caps := []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions}
	products := map[obsdk.PaymentType]string{}
	if b.sepa {
		products[obsdk.PaymentSEPA] = "sepa-credit-transfers"
	}
	if b.instant {
		products[obsdk.PaymentSEPAInstant] = "instant-sepa-credit-transfers"
	}
	if len(products) > 0 {
		caps = append(caps, obsdk.CapPayments)
	}
	return berlingroup.Profile{
		ID: b.key + "-luxhub",
		Info: obsdk.Info{
			Bank:         b.key,
			Name:         b.name,
			Group:        b.group,
			Variants:     variants,
			Capabilities: caps,
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "the client id of an application on developer.luxhub.com subscribed to the bank's XS2A API (an organisation account is needed)"},
				{Name: "client_secret", Required: true, Note: "the application's client secret (HTTP Basic at the token endpoint)"},
				{Name: "redirect_url", Required: true, Note: "one of the application's redirect URLs; receives the authorisation code"},
				{Name: "tls_client_cert", Required: true, Note: "QWAC for mTLS (Config.HTTPClient): the portal's mock QWAC in the sandbox, an eIDAS QWAC in production"},
				{Name: "seal", Required: true, Note: "QSealC for the request signature: the portal's mock QSealC in the sandbox, an eIDAS QSealC in production"},
			},
			Docs: []string{
				"https://developer.luxhub.com/products",
				"https://developer.luxhub.com/faq/",
			},
			Notes: []string{
				"The user approves the consent or payment on the bank's pages (OAuth2 authorisation code with PKCE); the account calls carry the token from that approval, which Refresh renews.",
				"Transactions older than 90 days need an extra scope (AIS_EXT) on the first token after the approval; not asked for.",
			},
			Payments: b.specs(),
		},
		BaseURL:            b.endpoint(func(h hosts) string { return h.api }),
		Approaches:         approaches,
		MaxConsentDays:     180,
		DefaultConsentDays: 180,
		FrequencyPerDay:    4,
		BookingStatuses:    b.bookingStatuses(),
		Products:           products,
		OAuth: &berlingroup.OAuthServer{
			Authorize:         b.endpoint(func(h hosts) string { return h.authorize }),
			Token:             b.endpoint(func(h hosts) string { return h.token }),
			ClientCredentials: true,
			PISScope:          "PIS:payment",
			ExchangeScope:     true,
		},
		OAuthClientAuth: clientAuth,
		Signing:         &berlingroup.Signing{Required: true, Algorithm: "rsa-sha256", KeyID: keyID, Date: true},
	}
}

// Profiles are the registered banks' profiles.
var Profiles = func() []berlingroup.Profile {
	var out []berlingroup.Profile
	for _, b := range banks {
		out = append(out, profile(b))
	}
	return out
}()

func init() {
	for _, p := range Profiles {
		berlingroup.Register(p)
	}
}
