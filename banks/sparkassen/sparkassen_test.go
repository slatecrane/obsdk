package sparkassen

import (
	"testing"

	"github.com/slatecrane/obsdk/obsdktest"
)

// TestScenarios replays the hand-written scenarios built from Finanz
// Informatik's documentation.
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }

func TestBankCode(t *testing.T) {
	for in, want := range map[string]string{
		"37050198":                    "37050198",
		"370 501 98":                  "37050198",
		"DE89 3704 0044 0532 0130 00": "37040044",
	} {
		if got, err := BankCode(in); err != nil || got != want {
			t.Errorf("BankCode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1234567", "3705019X", "DE00370400440532013000", "AT611904300234573201"} {
		if got, err := BankCode(in); err == nil {
			t.Errorf("BankCode(%q) = %q, want an error", in, got)
		}
	}
}
