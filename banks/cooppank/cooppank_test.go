package cooppank

import (
	"net/http"
	"testing"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/obsdktest"
)

// TestScenarios replays the scenarios recorded against the Coop Pank sandbox.
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

func TestBaseURL(t *testing.T) {
	if got := baseURL(obsdk.Sandbox, obsdk.Target{}, ""); got != "https://openbanking.cooppank.ee/sandbox/xs2a" {
		t.Errorf("sandbox: %s", got)
	}
	if got := baseURL(obsdk.Production, obsdk.Target{}, ""); got != "https://openbanking.cooppank.ee/live/xs2a" {
		t.Errorf("production: %s", got)
	}
}

func TestHeaders(t *testing.T) {
	h := http.Header{}
	headers(obsdk.Config{Extra: map[string]string{ParamAPIKey: "key-1"}}, h)
	if got := h.Get("X-API-Key"); got != "key-1" {
		t.Errorf("X-API-Key = %q", got)
	}
}

func TestPaymentSpec(t *testing.T) {
	spec, ok := Profile.Info.PaymentSpec("EE", obsdk.Personal, obsdk.PaymentSEPA)
	if !ok {
		t.Fatal("no SEPA spec")
	}
	use := map[string]obsdk.FieldUse{}
	for _, f := range spec.Fields {
		use[f.Path] = f.Use
	}
	for _, path := range []string{obsdk.FieldDebtorAccount, obsdk.FieldCreditorAddress, obsdk.FieldCreditorCountry} {
		if use[path] != obsdk.FieldRequired {
			t.Errorf("%s: %q, want required", path, use[path])
		}
	}
	if !spec.Cancellable {
		t.Error("SEPA payments should be cancellable")
	}
	if _, ok := Profile.Info.PaymentSpec("EE", obsdk.Personal, obsdk.PaymentSEPAInstant); ok {
		t.Error("SEPA Instant is not offered")
	}
}
