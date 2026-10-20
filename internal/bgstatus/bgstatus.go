// Package bgstatus maps Berlin Group (ISO 20022) transaction status codes to
// the SDK's payment statuses, for banks that report them.
package bgstatus

import obsdk "github.com/slatecrane/obsdk"

// Payment returns the normalized status of a Berlin Group transactionStatus
// and whether no further changes are expected.
func Payment(code string) (status obsdk.PaymentStatus, final bool) {
	switch code {
	case "RCVD":
		return obsdk.PaymentReceived, false
	case "ACTC", "ACCP", "ACFC", "ACTV":
		return obsdk.PaymentAccepted, false
	case "ACSP", "ACWC", "ACWP", "PDNG":
		return obsdk.PaymentInProgress, false
	case "ACSC", "ACCC":
		return obsdk.PaymentCompleted, true
	case "PATC", "PART":
		return obsdk.PaymentPartiallyAccepted, false
	case "RJCT":
		return obsdk.PaymentRejected, true
	case "CANC", "CNCL": // CNCL is not ISO 20022; Coop Pank reports cancelled payments with it
		return obsdk.PaymentCancelled, true
	}
	return obsdk.PaymentReceived, false
}
