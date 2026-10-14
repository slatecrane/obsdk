// Package obsdktest is the development and testing kit for ob-sdk.
//
// It supports two ways of testing a bank integration without writing a mock
// by hand:
//
//   - Live: run the real flow against a bank's sandbox (cmd/obdev, or the
//     opt-in live tests). Nothing automated depends on this.
//   - Replay: serve recorded request/response examples from a directory. The
//     recorder captures a real session once, redacts secrets and personal data,
//     and the replayer plays it back so `go test` needs no network.
//
// A scenario is a directory:
//
//	scenario.json     target, config placeholders, frozen clock, recorded ids, and the SDK calls made
//	exchanges/*.json  the HTTP exchanges, in order, one file each
//	golden.json       expected outcome of every call (written with -obsdktest.update)
//
// Everything is injected through obsdk.Config (HTTP client, clock, id source),
// so integrations need no special test hooks.
package obsdktest
