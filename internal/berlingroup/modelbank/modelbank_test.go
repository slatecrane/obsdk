package modelbank

import (
	"testing"

	"github.com/slatecrane/obsdk/obsdktest"
)

// TestScenarios replays conversations recorded against a local ModelBank
// (and hand-written ones for what it cannot produce).
func TestScenarios(t *testing.T) { obsdktest.PlayAll(t, "testdata") }
