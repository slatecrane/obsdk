// Package obsdk is a stateless client library for European open banking APIs.
//
// It hides per-bank differences (Berlin Group, STET, UK, Polish API and
// bank-specific variants) behind one small surface:
//
//	c, err := obsdk.New(obsdk.Target{Bank: "swedbank", Country: "SE"}, cfg)
//	step, err := c.Connect(ctx, obsdk.ConnectRequest{...})
//	for step.Kind != obsdk.StepDone {
//	    // act on the step (redirect the user, ask for input, wait), then:
//	    step, err = c.Resume(ctx, step.State, obsdk.StepInput{...})
//	}
//	accounts, err := c.Accounts(ctx, step.Session, obsdk.CallOptions{})
//
// Design rules:
//
//   - The client holds configuration only. Everything mutable lives in
//     serializable values (Session, Step.State) that the caller persists,
//     so calls may run on different instances.
//   - Credentials, certificates and keys are configuration and never end up
//     in a Session.
//   - The SDK does not run servers, schedulers or storage. Waiting, polling
//     and persistence are the caller's job.
//   - Banks register themselves (like database/sql drivers); import the
//     banks you need, or banks/all for every bank.
package obsdk
