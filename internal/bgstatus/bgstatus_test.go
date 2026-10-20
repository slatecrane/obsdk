package bgstatus

import (
	"testing"

	obsdk "github.com/slatecrane/obsdk"
)

func TestPayment(t *testing.T) {
	for code, want := range map[string]obsdk.PaymentStatus{
		"RCVD": obsdk.PaymentReceived, "ACTC": obsdk.PaymentAccepted, "ACSP": obsdk.PaymentInProgress,
		"ACSC": obsdk.PaymentCompleted, "PATC": obsdk.PaymentPartiallyAccepted, "RJCT": obsdk.PaymentRejected,
		"CANC": obsdk.PaymentCancelled, "CNCL": obsdk.PaymentCancelled, "???": obsdk.PaymentReceived,
	} {
		got, final := Payment(code)
		if got != want {
			t.Errorf("%s: %s, want %s", code, got, want)
		}
		if wantFinal := code == "ACSC" || code == "RJCT" || code == "CANC" || code == "CNCL"; final != wantFinal {
			t.Errorf("%s: final %t", code, final)
		}
	}
}
