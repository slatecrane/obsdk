package atruvia

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/obsdktest"
)

// TestScenarios replays the hand-written scenarios built from Atruvia's
// documentation.
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

func TestBankCode(t *testing.T) {
	for in, want := range map[string]string{
		"50060400":                    "50060400", // DZ BANK
		"500 604 00":                  "50060400",
		"GENODEFFXXX":                 "50060400",
		"GENODEFF":                    "50060400",
		"DE06 5006 0400 0000 0123 45": "50060400",
		SandboxBankCode:               SandboxBankCode,
		"DE45499999600000005100":      SandboxBankCode,
	} {
		if got, err := BankCode(in); err != nil || got != want {
			t.Errorf("BankCode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1234567", "5006040X", "37050198", "COBADEFFXXX", "DE00500604000000012345"} {
		if got, err := BankCode(in); err == nil {
			t.Errorf("BankCode(%q) = %q, want an error", in, got)
		}
	}
}

func TestDirectory(t *testing.T) {
	list := Institutions()
	if len(list) < 600 {
		t.Fatalf("directory has %d banks, want about 670", len(list))
	}
	for _, in := range list {
		if in.URL == "" || in.URL[len(in.URL)-1] == '/' || len(in.Code) != 8 {
			t.Errorf("bad directory entry %+v", in)
		}
	}
	if got := baseURL(obsdk.Production, obsdk.Target{}, "50060400"); got != "https://dzbanking.com/services_xs2a/bg13" {
		t.Errorf("DZ BANK production root = %q", got)
	}
	if got := baseURL(obsdk.Sandbox, obsdk.Target{}, "50060400"); got != sandboxRoot {
		t.Errorf("sandbox root = %q", got)
	}
	if got := baseURL(obsdk.Production, obsdk.Target{}, SandboxBankCode); got != "" {
		t.Errorf("the sandbox bank code has a production root %q", got)
	}
}

func TestKeyID(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(0x9FA1),
		Issuer: pkix.Name{CommonName: "D-TRUST CA 2-1 2015", Organization: []string{"D-Trust GmbH"}, Country: []string{"DE"}}}
	// The example of Atruvia's OpenAPI file.
	if got, want := KeyID(cert), "SN=9FA1,CA=CN%3DD-TRUST%20CA%202-1%202015%2CO%3DD-Trust%20GmbH%2CC%3DDE"; got != want {
		t.Errorf("KeyID = %s, want %s", got, want)
	}
}
