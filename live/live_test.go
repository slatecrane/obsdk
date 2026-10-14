//go:build live

// Package live holds development-only tests that talk to real bank APIs.
// They are excluded from normal builds by the "live" tag and need credentials:
//
//	export OBSDK_BANK=swedbank OBSDK_COUNTRY=SE OBSDK_ENV=sandbox
//	export OBSDK_CLIENT_ID=... OBSDK_CLIENT_SECRET=... OBSDK_REDIRECT_URL=...
//	export OBSDK_SESSION_FILE=$HOME/.obsdk/swedbank-se.json
//	go run ./cmd/obdev connect        # once, interactive; saves the session
//	go test -tags live ./live -v
package live

import (
	"testing"

	_ "github.com/slatecrane/obsdk/banks/all"
	"github.com/slatecrane/obsdk/obsdktest"
)

func TestLive(t *testing.T) { obsdktest.RunLive(t) }
