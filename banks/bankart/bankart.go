// Package bankart registers the Slovenian banks whose PSD2 interface runs on
// Bankart's API platform (api.bankart.si): NLB, OTP banka, Banka Sparkasse,
// Gorenjska banka, Deželna banka Slovenije, Hranilnica LON and Primorska
// hranilnica Vipava. Each bank has its own developer portal and API root
// (openbanking.bankart.si/<code>, api.bankart.si/psd2/<code>); the interface
// is the same.
//
// It is Berlin Group NextGenPSD2 1.3.6 with Bankart's deviations: an OAuth2
// login comes first, in which the user picks one account (the token's sub is
// its IBAN); that token, valid 5 minutes, authorises only creating the
// consent or payment. A consent covers that one account. Payments are served
// under their own root (.../pay/v1). Every request names the application in
// X-IBM-Client-Id; production adds the QWAC (mTLS), and every request carries
// Initialized-By-PSU.
//
// The sandbox is free: an account on a bank's developer portal and an app
// subscribed to the sandbox products. It answers with static data. Built from
// the portals' specifications and FAQ on 2026-10-20. See docs/bankart.md.
package bankart

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Registry keys.
const (
	NLBBank        = "nlb"
	OTPBank        = "otpbanka"
	SparkasseBank  = "sparkassesi"
	GorenjskaBank  = "gorenjskabanka"
	DezelnaBank    = "dezelnabanka"
	LONBank        = "hranilnicalon"
	PrimorskaBank  = "primorskahranilnica"
	sandboxSegment = "sandbox"
)

type bank struct {
	key, name, code, group string
}

// banks are the banks with a portal on openbanking.bankart.si; code is
// their path segment there and on api.bankart.si.
var banks = []bank{
	{key: NLBBank, name: "NLB", code: "nlb"},
	{key: OTPBank, name: "OTP banka", code: "otp", group: "OTP Group (former Nova KBM and SKB banka; openbanking.bankart.si/nkbm redirects here)"},
	{key: SparkasseBank, name: "Banka Sparkasse", code: "sparkasse", group: "Erste Group / Steiermärkische Sparkasse"},
	{key: GorenjskaBank, name: "Gorenjska banka", code: "gbkr", group: "AIK Banka"},
	{key: DezelnaBank, name: "Deželna banka Slovenije", code: "dbs"},
	{key: LONBank, name: "Hranilnica LON", code: "lon"},
	{key: PrimorskaBank, name: "Primorska hranilnica Vipava", code: "phv"},
}

// baseURL is the API root before "/v1" (AIS) and "/pay/v1" (payments).
func (b bank) baseURL(env obsdk.Env, _ obsdk.Target, _ string) string {
	if env == obsdk.Production {
		return "https://api.bankart.si/psd2/" + b.code
	}
	return "https://api.bankart.si/psd2/" + b.code + "/" + sandboxSegment
}

// oauthURL is the root of the login's authorize and token endpoints.
func (b bank) oauthURL(env obsdk.Env, _ obsdk.Target, _ string) string {
	if env == obsdk.Production {
		return "https://api-oauth.bankart.si/psd2/" + b.code + "/oauth"
	}
	return "https://api.bankart.si/psd2/" + b.code + "/sandbox/oauth2"
}

// headers name the application on every request (IBM API Connect).
func headers(cfg obsdk.Config, h http.Header) {
	h.Set("X-IBM-Client-Id", cfg.Credentials.ClientID)
}

// clientAuth adds the application's secret at the token endpoint when there
// is one; the portal's example sends the client id alone.
func clientAuth(cfg obsdk.Config, _ string, form url.Values, h http.Header) error {
	h.Set("X-IBM-Client-Id", cfg.Credentials.ClientID)
	if s := string(cfg.Credentials.ClientSecret); s != "" {
		form.Set("client_secret", s)
	}
	return nil
}

var ibanShape = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)

// tokenAccount reads the IBAN the user picked at the login from the access
// token, a JWT whose sub claim is that IBAN. The signature is not checked:
// the token comes straight from the bank's token endpoint, and the bank
// checks it again on the request it authorises.
func tokenAccount(tok string) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", nil // not a JWT: the caller names the account
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", fmt.Errorf("unreadable access token payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return "", fmt.Errorf("unreadable access token claims: %w", err)
	}
	// Only the shape is checked: the sandbox's static IBANs fail the check digits.
	iban := strings.ToUpper(strings.ReplaceAll(claims.Sub, " ", ""))
	if !ibanShape.MatchString(iban) {
		return "", nil // a sub that is no IBAN names no account
	}
	return iban, nil
}

var approaches = []string{berlingroup.Redirect}

func specs() []obsdk.PaymentSpec {
	notes := []string{
		"The user logs in first and picks the account to pay from; a debtor account given here is passed to the login and must be the one picked.",
	}
	return []obsdk.PaymentSpec{
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{DebtorOptional: true, ExecutionDate: true,
			Address: true, NoReference: true, Approaches: approaches, Notes: notes}),
		berlingroup.CreditTransferSpec(obsdk.PaymentSEPAInstant, berlingroup.SpecOptions{DebtorOptional: true, Address: true,
			NoReference: true, Approaches: approaches, Notes: notes}),
	}
}

func profile(b bank) berlingroup.Profile {
	variants := []obsdk.Variant{
		{Country: "SI", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
		{Country: "SI", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
		{Country: "SI", Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		{Country: "SI", Segment: obsdk.Business, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
	}
	portal := "https://openbanking.bankart.si/" + b.code + "/"
	return berlingroup.Profile{
		ID: b.key + "-bankart",
		Info: obsdk.Info{
			Bank:         b.key,
			Name:         b.name,
			Group:        b.group,
			Variants:     variants,
			Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "the client id of an app on " + portal + " (Apps), subscribed to the Account Information and Payment Initiation products; sent as X-IBM-Client-Id and used for the login"},
				{Name: "client_secret", Note: "the app's secret, sent to the token endpoint when set"},
				{Name: "redirect_url", Required: true, Note: "the app's OAuth Redirect URL; receives the login's callback (code) and the return from the approval"},
				{Name: "qwac", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "eIDAS QWAC for mTLS (Config.HTTPClient), uploaded to the app on the portal"},
				{Name: "seal", Note: "QSealC: signs requests (Digest, Signature, TPP-Signature-Certificate) when set; the bank may mandate it"},
			},
			Docs: []string{
				portal + "support",
				portal + "product",
				"https://openbanking.bankart.si/hub/support",
			},
			Notes: []string{
				"The user is sent to the bank twice: first to log in and pick one account, then to approve the consent or payment.",
				"A consent covers one account, the one picked at the login; connect again for each further account.",
				"Transactions older than 90 days can be read only in the first 5 minutes after the consent is created.",
				"Booked and pending transactions are read separately.",
			},
			Payments: specs(),
		},
		BaseURL:            b.baseURL,
		Approaches:         approaches,
		MaxConsentDays:     180,
		DefaultConsentDays: 180,
		BookingStatuses:    []string{"booked", "pending"},
		Products: map[obsdk.PaymentType]string{
			obsdk.PaymentSEPA:        "sepa-credit-transfers",
			obsdk.PaymentSEPAInstant: "instant-sepa-credit-transfers",
		},
		PaymentRoot:        "pay",
		PSUInitiatedHeader: "Initialized-By-PSU",
		PreStep: &berlingroup.PreStep{URL: b.oauthURL, AISScope: "psd2:acc", PISScope: "psd2:pay",
			CreateOnly: true, TokenAccount: tokenAccount, AccountParam: "iban"},
		OAuthClientAuth: clientAuth,
		Signing:         &berlingroup.Signing{},
		Headers:         headers,
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
