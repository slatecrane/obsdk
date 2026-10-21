package bnpparibasfortis

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/stet"
	"github.com/slatecrane/obsdk/obsdktest"
)

// TestScenarios replays the scenarios recorded against the BNP Paribas Fortis sandbox.
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

func TestProductionHosts(t *testing.T) {
	for _, tc := range []struct {
		brand          brand
		segment        obsdk.Segment
		api, auth, tok string
	}{
		{brands[0], obsdk.Personal, "https://regulatory.api.bnpparibasfortis.be/psd2/v4",
			"https://services.bnpparibasfortis.be/SEPL/PSD2/IND/authorize", "https://regulatory.api.bnpparibasfortis.be/token"},
		{brands[0], obsdk.Business, "https://regulatory.api.bnpparibasfortis.be/psd2/v4",
			"https://services.bnpparibasfortis.be/SEPL/PSD2/ENT/authorize", "https://regulatory.api.bnpparibasfortis.be/token"},
		{brands[1], obsdk.Personal, "https://regulatory.api.hellobank.be/psd2/v4",
			"https://services.hellobank.be/SEPL/PSD2/IND/authorize", "https://regulatory.api.hellobank.be/token"},
		{brands[2], obsdk.Business, "https://regulatory.api.fintro.be/psd2/v4",
			"https://services.fintro.be/SEPL/PSD2/ENT/authorize", "https://regulatory.api.fintro.be/token"},
	} {
		p := profile(tc.brand)
		tg := obsdk.Target{Bank: tc.brand.bank, Country: "BE", Segment: tc.segment}
		if got := p.APIBase(obsdk.Production, tg); got != tc.api {
			t.Errorf("%s api: %s", tc.brand.bank, got)
		}
		if got := p.AuthURL(obsdk.Production, tg); got != tc.auth {
			t.Errorf("%s %s auth: %s", tc.brand.bank, tc.segment, got)
		}
		if got := p.TokenURL(obsdk.Production, tg); got != tc.tok {
			t.Errorf("%s token: %s", tc.brand.bank, got)
		}
	}
}

func TestSandboxBrandAndSegment(t *testing.T) {
	p := profile(brands[2])
	sandbox := obsdk.Config{Env: obsdk.Sandbox}
	if got := p.Query(sandbox, obsdk.Target{}); got.Get("brand") != "fintro" {
		t.Errorf("sandbox query %v", got)
	}
	if got := p.Query(obsdk.Config{Env: obsdk.Production}, obsdk.Target{}); len(got) != 0 {
		t.Errorf("production query %v", got)
	}
	q := url.Values{}
	p.AuthParams(sandbox, obsdk.Target{}, q)
	if q.Get("brand") != "fintro" {
		t.Errorf("authorize params %v", q)
	}
	h := http.Header{}
	p.PaymentHeaders(sandbox, obsdk.Target{Segment: obsdk.Business}, h)
	if h.Get("businessLineName") != "CPB" {
		t.Errorf("business line %q", h.Get("businessLineName"))
	}
}

func TestProductionNeedsSeal(t *testing.T) {
	cfg := obsdk.Config{Env: obsdk.Production, Credentials: obsdk.Credentials{ClientID: "id", ClientSecret: "secret", RedirectURL: "https://tpp.example/cb"}}
	_, err := obsdk.New(obsdk.Target{Bank: BankFortis, Country: "BE"}, cfg)
	if !errors.Is(err, obsdk.ErrInvalidConfig) || !strings.Contains(err.Error(), "seal") {
		t.Errorf("production without a seal: %v", err)
	}
	cfg.Env = obsdk.Sandbox
	if _, err := obsdk.New(obsdk.Target{Bank: BankFortis, Country: "BE"}, cfg); err != nil {
		t.Errorf("sandbox without a seal: %v", err)
	}
}

func TestHelloBankHasNoBusiness(t *testing.T) {
	if _, err := obsdk.New(obsdk.Target{Bank: BankHello, Country: "BE", Segment: obsdk.Business},
		obsdk.Config{Env: obsdk.Sandbox, Credentials: obsdk.Credentials{ClientID: "id", ClientSecret: "secret"}}); err == nil {
		t.Error("Hello bank! business should not resolve")
	}
}

func TestReferenceSchemes(t *testing.T) {
	info, _ := obsdk.Lookup(BankFortis)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	pay := func(typ obsdk.PaymentType, scheme, value string) obsdk.PaymentRequest {
		return obsdk.PaymentRequest{Type: typ, Transfers: []obsdk.Transfer{{
			Amount:    obsdk.Money{Amount: "1.00", Currency: "EUR"},
			Creditor:  obsdk.Creditor{Name: "Jan Peeters", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "BE63380242772874"}},
			Reference: &obsdk.Reference{Scheme: scheme, Value: value},
		}}}
	}
	for _, tt := range []struct {
		typ           obsdk.PaymentType
		scheme, value string
		ok            bool
	}{
		{obsdk.PaymentSEPA, obsdk.ReferenceBE, "123456789002", true},
		{obsdk.PaymentSEPA, obsdk.ReferenceRF, "RF18539007547034", true},
		{obsdk.PaymentSEPA, obsdk.ReferenceBE, "123456789003", false},
		{obsdk.PaymentSEPAInstant, obsdk.ReferenceBE, "123456789002", true},
		{obsdk.PaymentSEPAInstant, obsdk.ReferenceRF, "RF18539007547034", false}, // instant takes Belgian references only
	} {
		ps, _ := info.PaymentSpec("BE", obsdk.Personal, tt.typ)
		if err := ps.Validate(pay(tt.typ, tt.scheme, tt.value), now); (err == nil) != tt.ok {
			t.Errorf("%s %s %s: err = %v, want ok=%v", tt.typ, tt.scheme, tt.value, err, tt.ok)
		}
	}
}

func crossBorder() obsdk.PaymentRequest {
	return obsdk.PaymentRequest{Type: obsdk.PaymentCrossBorder, Transfers: []obsdk.Transfer{{
		Amount: obsdk.Money{Amount: "1.00", Currency: "USD"},
		Creditor: obsdk.Creditor{Name: "John Smith", Account: obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "123456789"},
			Address: &obsdk.PostalAddress{Street: "Main St", BuildingNumber: "1", Town: "New York", Country: "US"},
			Agent:   &obsdk.Agent{BIC: "CHASUS33", Address: &obsdk.PostalAddress{Town: "New York", Country: "US"}}},
	}}}
}

func TestCrossBorderSpec(t *testing.T) {
	info, _ := obsdk.Lookup(BankFortis)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	personal, _ := info.PaymentSpec("BE", obsdk.Personal, obsdk.PaymentCrossBorder)
	business, ok := info.PaymentSpec("BE", obsdk.Business, obsdk.PaymentCrossBorder)
	if !ok {
		t.Fatal("no business cross-border spec")
	}
	r := crossBorder()
	if err := personal.Validate(r, now); err != nil {
		t.Fatal(err)
	}
	r.ExecutionDate = "2026-10-28"
	if err := personal.Validate(r, now); err == nil {
		t.Error("personal customers can only pay international today")
	}
	if err := business.Validate(r, now); err != nil {
		t.Errorf("business: %v", err)
	}
	r = crossBorder()
	r.Transfers[0].Creditor.Agent.Address = nil
	if err := personal.Validate(r, now); err == nil {
		t.Error("the payee bank's address is required")
	}
}

func TestAdjustCrossBorder(t *testing.T) {
	body := func(r obsdk.PaymentRequest) *stet.PaymentRequestBody {
		return &stet.PaymentRequestBody{
			DebtorAccount: &stet.AccountID{IBAN: "BE68539007547034"},
			Beneficiary: &stet.Beneficiary{Creditor: stet.Party{Name: "John Smith", PostalAddress: &stet.PostalAddress{Country: "US", AddressLine: []string{"Main St 1", "New York"}}},
				CreditorAgent: &stet.Agent{BICFI: "CHASUS33"}},
		}
	}
	r := crossBorder()
	b := body(r)
	if err := adjustPayment(r, obsdk.Target{}, b); err != nil {
		t.Fatal(err)
	}
	if b.DebtorAccount.Currency != "EUR" {
		t.Errorf("debtor currency %q, want EUR by default", b.DebtorAccount.Currency)
	}
	if a := b.Beneficiary.Creditor.PostalAddress; a.TownName != "New York" || a.Country != "US" || a.AddressLine != nil {
		t.Errorf("creditor address %+v", a)
	}
	if a := b.Beneficiary.CreditorAgent.PostalAddress; a == nil || a.TownName != "New York" || a.Country != "US" {
		t.Errorf("agent address %+v", a)
	}

	r.Transfers[0].Creditor.Address.Town = ""
	if err := adjustPayment(r, obsdk.Target{}, body(r)); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("a payee without town: %v", err)
	}
	r = crossBorder()
	r.Transfers[0].Creditor.Agent.BIC = ""
	if err := adjustPayment(r, obsdk.Target{}, body(r)); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Errorf("a payee bank without BIC or name: %v", err)
	}
}
