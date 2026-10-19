// Package samlink registers the Finnish savings banks on Samlink's PSD2
// interface: Säästöpankki (the Savings Banks Group, bank "saastopankki") and
// Oma Säästöpankki (bank "omasp"). Each bank has its own production host;
// the interface is the same.
//
// It is Berlin Group NextGenPSD2 1.3 with Samlink's deviations: account
// information is served under "/v2", the user picks the accounts at the bank
// (no global consents), approval is an OAuth2 authorisation-code flow behind
// a scaOAuth link, transactions are paged by entry reference, and the creditor
// reference of a payment travels in endToEndIdentification. Production
// requests are signed with the QSealC and carry the API key from Samlink's
// TPP registration; the token endpoint takes a private_key_jwt client
// assertion signed with the same QSealC. No QWAC is needed.
//
// The sandbox is free: an account on developer.samlink.fi, a subscription
// key, and an application registered through the sandbox's management API.
// Connect, accounts, transactions, refresh, disconnect and payments were run
// against the sandbox on 2026-10-19 for both banks. See docs/samlink.md.
package samlink

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/berlingroup"
)

// Registry keys.
const (
	SaastopankkiBank = "saastopankki"
	OmaSPBank        = "omasp"
)

// Config.Extra keys.
const (
	// ParamSubscriptionKey is the developer portal's subscription key, sent
	// as Ocp-Apim-Subscription-Key on every sandbox request.
	ParamSubscriptionKey = "subscription_key"
	// ParamAPIKey is the API key returned by Samlink's TPP registration, sent
	// as apikey on every production request.
	ParamAPIKey = "api_key"
)

// verifiedOn is the date of the last obdev run against the sandbox.
const verifiedOn = "2026-10-19"

// sandboxRoot is the sandbox gateway; both banks share it, and the test user
// picked at login decides the bank.
const sandboxRoot = "https://sml-prod-psd2.azure-api.net/psd2"

type bank struct {
	key, name, host, authPath string
	group                     string
}

var banks = []bank{
	{key: SaastopankkiBank, name: "Säästöpankki", host: "sp-psdapi.samlink.fi", authPath: "sp",
		group: "Säästöpankkiryhmä (Savings Banks Group: Säästöpankki Optia, Myllykosken Säästöpankki and the other member savings banks)"},
	{key: OmaSPBank, name: "Oma Säästöpankki", host: "omasp-psdapi.samlink.fi", authPath: "omasp"},
}

func (b bank) baseURL(env obsdk.Env, _ obsdk.Target, _ string) string {
	if env == obsdk.Production {
		return "https://" + b.host + "/psd2"
	}
	return sandboxRoot
}

func headers(cfg obsdk.Config, h http.Header) {
	if cfg.Env == obsdk.Production {
		h.Set("apikey", cfg.Param(ParamAPIKey))
		return
	}
	h.Set("Ocp-Apim-Subscription-Key", cfg.Param(ParamSubscriptionKey))
}

// clientAuth authenticates at the token endpoint: in the sandbox with HTTP
// Basic (the client id and secret from the sandbox registration) and the
// subscription key; in production with a client assertion signed by the
// QSealC, whose organizationIdentifier is the client id.
func clientAuth(cfg obsdk.Config, tokenURL string, form url.Values, h http.Header) error {
	h.Set("X-Request-ID", cfg.ID(obsdk.IDRequest))
	if cfg.Env != obsdk.Production {
		h.Set("Ocp-Apim-Subscription-Key", cfg.Param(ParamSubscriptionKey))
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
			[]byte(cfg.Credentials.ClientID+":"+string(cfg.Credentials.ClientSecret))))
		return nil
	}
	h.Set("apikey", cfg.Param(ParamAPIKey))
	a, err := clientAssertion(cfg, tokenURL)
	if err != nil {
		return err
	}
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", a)
	return nil
}

// clientAssertion is the private_key_jwt of RFC 7523: the client id as
// issuer and subject, the token endpoint as audience, jti and exp, signed
// RS256 with the QSealC. Samlink refuses headers with repeated keys, so the
// header is kept minimal.
func clientAssertion(cfg obsdk.Config, tokenURL string) (string, error) {
	s := cfg.Seal
	if s == nil || s.Key == nil {
		return "", &obsdk.ConfigError{Env: cfg.Env, Missing: []string{"seal (QSealC key: it signs the token request's client assertion)"}}
	}
	if _, ok := s.Key.Public().(*rsa.PublicKey); !ok {
		return "", fmt.Errorf("%w: samlink: the client assertion needs an RSA QSealC key", obsdk.ErrInvalidConfig)
	}
	head := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.KeyID != "" {
		head["kid"] = s.KeyID
	}
	now := cfg.Clock()
	claims := map[string]any{"iss": cfg.Credentials.ClientID, "sub": cfg.Credentials.ClientID, "aud": tokenURL,
		"jti": cfg.ID(obsdk.IDRequest), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	hb, _ := json.Marshal(head)
	cb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(input))
	sig, err := s.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("samlink: sign client assertion: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

var approaches = []string{berlingroup.Redirect}

func specs() []obsdk.PaymentSpec {
	s := berlingroup.CreditTransferSpec(obsdk.PaymentSEPA, berlingroup.SpecOptions{DebtorOptional: true, ExecutionDate: true,
		ExecutionDateMaxDays: 5 * 365, Address: true, Approaches: approaches,
		Notes: []string{
			"Either a description or a reference is required. The reference is sent as the end-to-end id, which is how Samlink carries it.",
			"A payee address, when given, needs at least the town and the country.",
			"A future-dated payment must be at least one day ahead.",
			"Single payments cannot be cancelled through the API.",
		}})
	kept := s.Fields[:0]
	for _, f := range s.Fields {
		switch f.Path {
		case obsdk.FieldEndToEndID:
			continue // the reference takes its place
		case obsdk.FieldReference:
			f.Schemes = []string{obsdk.ReferenceFI, obsdk.ReferenceRF}
			f.Note = "Finnish reference (viitenumero) or RF creditor reference."
		}
		kept = append(kept, f)
	}
	s.Fields = kept
	return []obsdk.PaymentSpec{s}
}

func profile(b bank) berlingroup.Profile {
	// The sandbox's test users are personal customers; business accounts are
	// served by the same API but were not seen there.
	variants := []obsdk.Variant{
		{Country: "FI", Segment: obsdk.Personal, Env: obsdk.Sandbox, Maturity: obsdk.MaturitySandboxVerified, VerifiedOn: verifiedOn},
		{Country: "FI", Segment: obsdk.Business, Env: obsdk.Sandbox, Maturity: obsdk.MaturityExperimental},
		{Country: "FI", Segment: obsdk.Personal, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
		{Country: "FI", Segment: obsdk.Business, Env: obsdk.Production, Maturity: obsdk.MaturityUnverified},
	}
	return berlingroup.Profile{
		ID: b.key + "-samlink",
		Info: obsdk.Info{
			Bank:         b.key,
			Name:         b.name,
			Group:        b.group,
			Variants:     variants,
			Capabilities: []obsdk.Capability{obsdk.CapAccounts, obsdk.CapBalances, obsdk.CapTransactions, obsdk.CapPayments},
			Requirements: []obsdk.Requirement{
				{Name: "client_id", Required: true, Note: "sandbox: the client_id from the sandbox's /management/tpp-register-app; production: the organizationIdentifier of the QSealC (e.g. PSDFI-FINFSA-1234567-8)"},
				{Name: "client_secret", Required: true, Envs: []obsdk.Env{obsdk.Sandbox}, Note: "the client_secret from the sandbox registration (HTTP Basic at the token endpoint)"},
				{Name: ParamSubscriptionKey, Required: true, Envs: []obsdk.Env{obsdk.Sandbox}, Note: "subscription key from the developer.samlink.fi profile page (Ocp-Apim-Subscription-Key)"},
				{Name: ParamAPIKey, Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "API key returned by Samlink's TPP registration API (reg.samlink.fi), sent as apikey"},
				{Name: "seal", Required: true, Envs: []obsdk.Env{obsdk.Production}, Note: "QSealC (RSA): signs every request (Digest, Signature, TPP-Signature-Certificate) and the token endpoint's client assertion. No QWAC is needed"},
			},
			Docs: []string{
				"https://developer.samlink.fi/tech-doc",
				"https://developer.samlink.fi/sandbox-doc",
				"https://developer.samlink.fi/faq",
			},
			Notes: []string{
				"The user picks the accounts at the bank; consents last up to 180 days and allow 4 unattended reads per day.",
				"Transactions older than 90 days can be read only in the first 5 minutes after the consent is approved (up to 12 months back).",
				"Booked and pending transactions are reported separately; pending ones come in one page without date filtering.",
				"Card accounts are offered by the bank but not read by this integration yet.",
			},
			Payments: specs(),
		},
		BaseURL:              b.baseURL,
		Approaches:           approaches,
		Consent:              berlingroup.ConsentBankOffered,
		MaxConsentDays:       180,
		DefaultConsentDays:   180,
		BookingStatuses:      []string{"booked", "pending"},
		Products:             map[obsdk.PaymentType]string{obsdk.PaymentSEPA: "sepa-credit-transfers"},
		AISPathVersion:       "v2",
		EntryReferencePaging: true,
		ReferenceInEndToEnd:  true,
		LegacyAddress:        true,
		OAuthClientAuth:      clientAuth,
		Signing:              &berlingroup.Signing{Algorithm: "rsa-sha256"},
		Headers:              headers,
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
