package hsbc_test

import (
	"testing"

	"github.com/slatecrane/obsdk/obsdktest"
)

// TestScenarios replays every recorded scenario under testdata and compares
// the SDK's outcomes with the golden files. No network, no credentials.
//
// After an intended behaviour change: go test ./banks/hsbc -obsdktest.update
func TestScenarios(t *testing.T) {
	obsdktest.PlayAll(t, "testdata")
}
