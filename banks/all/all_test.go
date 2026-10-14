package all_test

import (
	"os"
	"strings"
	"testing"

	obsdk "github.com/slatecrane/obsdk"
	_ "github.com/slatecrane/obsdk/banks/all"
)

// TestBanksDocListsEveryBank keeps docs/banks.md in step with the registry.
func TestBanksDocListsEveryBank(t *testing.T) {
	doc, err := os.ReadFile("../../docs/banks.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range obsdk.List(obsdk.Filter{}) {
		if !strings.Contains(string(doc), "| `"+info.Bank+"` |") {
			t.Errorf("docs/banks.md has no row for %q", info.Bank)
		}
	}
}
