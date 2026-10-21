package bnpparibasfortis

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	obsdk "github.com/slatecrane/obsdk"
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
