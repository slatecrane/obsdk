// Command obdev is a development tool for integrations. It talks to a real
// bank (usually its sandbox) with the same client your application would use,
// and can record the conversation as a replayable test scenario.
//
//	export OBSDK_BANK=swedbank OBSDK_COUNTRY=SE OBSDK_ENV=sandbox
//	export OBSDK_CLIENT_ID=... OBSDK_CLIENT_SECRET=... OBSDK_REDIRECT_URL=https://localhost/cb
//	export OBSDK_SESSION_FILE=$HOME/.obsdk/swedbank-se.json
//
//	obdev -record banks/swedbank/testdata/se-redirect connect
//	obdev -record banks/swedbank/testdata/se-redirect accounts
//	obdev -record banks/swedbank/testdata/se-redirect transactions ACCOUNT_ID -from 2026-01-01
//	obdev replay banks/swedbank/testdata/se-redirect
//
// Recording redacts secrets and personal data, but no redaction is perfect:
// read the files in <scenario>/exchanges before committing them. The session
// file holds tokens and is never written into a scenario.
//
// See the OBSDK_* variables in package obsdktest (mTLS certificates and
// signing keys included). Each bank's banks/<bank>/sandbox.env.example lists
// what that bank needs; copy it to sandbox.env and load it with
//
//	set -a; . banks/<bank>/sandbox.env; set +a
package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	_ "github.com/slatecrane/obsdk/banks/all"
	"github.com/slatecrane/obsdk/obsdktest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "obdev:", err)
		os.Exit(1)
	}
}

const usage = `usage: obdev [-record DIR] <command> [args]

commands:
  connect                          log in (redirect/decoupled) and save the session
  accounts
  balances ACCOUNT_ID
  transactions ACCOUNT_ID [-from D] [-to D] [-status booked,pending] [-size N] [-cursor C]
  refresh
  disconnect
  auth-methods
  payment-spec [TYPE]              show the payment types offered here, or one type's field rules
  pay -type T -amount A -currency C -to ACCOUNT -name NAME [flags]
                                   initiate a payment and drive its approval (see obdev pay -h)
  payment-status REF               read a payment's status (REF from pay's output)
  cancel-payment REF
  replay DIR                       run a recorded scenario offline and print the outcomes
  list                             show registered integrations
  jwks                             print a JWKS for the signing key (OBSDK_SEAL_CERT or OBSDK_TLS_CERT, OBSDK_SEAL_KID)
`

func run() error {
	record := flag.String("record", "", "record the conversation as a scenario in this directory")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage); flag.PrintDefaults() }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		return fmt.Errorf("missing command")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch args[0] {
	case "replay":
		if len(args) != 2 {
			return fmt.Errorf("usage: obdev replay DIR")
		}
		return replay(ctx, args[1])
	case "jwks":
		return printJWKS()
	case "list":
		for _, i := range obsdk.List(obsdk.Filter{}) {
			fmt.Printf("%-14s %-24s %s\n", i.Bank, i.Name, i.Spec)
		}
		return nil
	}

	live, err := obsdktest.LiveFromEnv()
	if err != nil {
		return err
	}
	if live.SessionFile == "" {
		fmt.Fprintln(os.Stderr, "note: OBSDK_SESSION_FILE is not set; the session will be lost when this command ends")
	}
	cfg := live.Config
	var rec *obsdktest.ScenarioRecorder
	if *record != "" {
		red := obsdktest.DefaultRedactor(map[string]string{
			cfg.Credentials.ClientID:              "client_id",
			cfg.Credentials.ClientSecret.Reveal(): "client_secret",
		})
		rec, err = obsdktest.NewScenarioRecorder(*record, obsdktest.ScenarioConfig{
			Bank: live.Target.Bank, Country: string(live.Target.Country), Segment: string(live.Target.Segment),
			Env: string(cfg.Env), RedirectURL: cfg.Credentials.RedirectURL, Extra: cfg.Extra,
		}, red)
		if err != nil {
			return err
		}
		base := http.DefaultTransport
		if hc, ok := cfg.HTTPClient.(*http.Client); ok && hc.Transport != nil {
			base = hc.Transport
		}
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second, Transport: rec.Transport(base)}
		cfg.NewID = rec.NewID(cfg.NewID)
	}
	live.Config = cfg

	client, session, err := live.Client()
	if err != nil {
		return err
	}
	if rec != nil {
		// Commands that work without a login (connect, pay, payment-status at
		// banks that read payments with an app token) record without one.
		noLogin := map[string]bool{"connect": true, "pay": true, "payment-status": true, "payment-spec": true, "auth-methods": true}
		switch {
		case args[0] == "connect":
		case session != nil:
			if err := rec.SetStartSession(session); err != nil {
				return err
			}
		case !noLogin[args[0]]:
			return fmt.Errorf("no session: run `obdev connect` first")
		}
		client = rec.Wrap(client)
	}

	cmdErr := dispatch(ctx, live, client, session, args)
	if rec != nil {
		if err := rec.Save(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "recorded into %s: review exchanges/, then run `go test ./... -obsdktest.update` to create golden.json\n", *record)
	}
	return cmdErr
}

func dispatch(ctx context.Context, l *obsdktest.Live, c obsdk.Client, s *obsdk.Session, args []string) error {
	opts := obsdk.CallOptions{}
	if l.PSU.IP != "" || l.PSU.UserAgent != "" {
		opts.PSU = &l.PSU
	}
	needSession := func() error {
		if s == nil {
			return fmt.Errorf("no session: run `obdev connect` first (and set OBSDK_SESSION_FILE)")
		}
		return nil
	}
	keep := func(ns *obsdk.Session) {
		if ns != nil {
			s = ns
			if err := l.SaveSession(s); err != nil {
				fmt.Fprintln(os.Stderr, "warning: saving session:", err)
			}
		}
	}

	switch args[0] {
	case "connect":
		fs := flag.NewFlagSet("connect", flag.ExitOnError)
		method := fs.String("method", "", "login method, e.g. redirect or decoupled")
		days := fs.Int("days", 0, "consent validity in days")
		_ = fs.Parse(args[1:])
		step, err := c.Connect(ctx, obsdk.ConnectRequest{Method: *method, ConsentValidityDays: *days, PSU: l.PSU})
		if err != nil {
			return err
		}
		done, err := drive(ctx, c, step, keep)
		if err != nil {
			return err
		}
		fmt.Printf("connected: %d accounts discovered\n", len(done.Accounts))
		return printJSON(done.Accounts)
	case "accounts":
		if err := needSession(); err != nil {
			return err
		}
		r, err := c.Accounts(ctx, s, opts)
		if err != nil {
			return err
		}
		keep(r.Session)
		return printJSON(r.Data)
	case "balances":
		if err := needSession(); err != nil || len(args) < 2 {
			return orUsage(err, "obdev balances ACCOUNT_ID")
		}
		r, err := c.Balances(ctx, s, args[1], opts)
		if err != nil {
			return err
		}
		keep(r.Session)
		return printJSON(r.Data)
	case "transactions":
		if err := needSession(); err != nil || len(args) < 2 {
			return orUsage(err, "obdev transactions ACCOUNT_ID [-from D] [-to D] [-size N] [-cursor C]")
		}
		fs := flag.NewFlagSet("transactions", flag.ExitOnError)
		from := fs.String("from", "", "start date (YYYY-MM-DD or RFC 3339); default 30 days ago")
		to := fs.String("to", "", "end date; default now")
		status := fs.String("status", "", "comma separated: booked,pending")
		size := fs.Int("size", 0, "page size; 0 lets the integration choose")
		cursor := fs.String("cursor", "", "next_cursor from the previous page")
		_ = fs.Parse(args[2:])
		q := obsdk.TxQuery{AccountID: args[1], Options: opts, From: time.Now().AddDate(0, 0, -30), To: time.Now(), PageSize: *size, Cursor: *cursor}
		var err error
		if *from != "" {
			if q.From, err = parseDate(*from); err != nil {
				return err
			}
		}
		if *to != "" {
			if q.To, err = parseDate(*to); err != nil {
				return err
			}
		}
		for _, st := range strings.Split(*status, ",") {
			if st != "" {
				q.Status = append(q.Status, obsdk.TxStatus(st))
			}
		}
		res, err := c.Transactions(ctx, s, q)
		if err != nil {
			return err
		}
		keep(res.Session)
		if res.Step != nil {
			done, err := drive(ctx, c, res.Step, keep)
			if err != nil {
				return err
			}
			if done.Transactions == nil {
				return fmt.Errorf("flow finished without transactions")
			}
			return printJSON(done.Transactions)
		}
		return printJSON(res.TxPage)
	case "refresh":
		if err := needSession(); err != nil {
			return err
		}
		ns, err := c.Refresh(ctx, s)
		if err != nil {
			return err
		}
		keep(ns)
		fmt.Println("refreshed")
		return nil
	case "disconnect":
		if err := needSession(); err != nil {
			return err
		}
		r, err := c.Disconnect(ctx, s)
		if err != nil {
			return err
		}
		keep(r.Session)
		return printJSON(map[string]any{"closed": r.Closed, "failed": r.Failed})
	case "payment-spec":
		info := c.Info()
		if len(args) < 2 {
			return printJSON(info.PaymentTypes(l.Target.Country, l.Target.Segment))
		}
		spec, ok := info.PaymentSpec(l.Target.Country, l.Target.Segment, obsdk.PaymentType(args[1]))
		if !ok {
			return fmt.Errorf("%w: no %s payments here", obsdk.ErrUnsupported, args[1])
		}
		return printJSON(spec)
	case "pay":
		r, useSession, err := paymentFlags(args[1:])
		if err != nil {
			return err
		}
		r.PSU = l.PSU
		if useSession {
			if err := needSession(); err != nil {
				return err
			}
			r.Session = s
		}
		step, err := c.InitiatePayment(ctx, r)
		if err != nil {
			return err
		}
		done, err := drive(ctx, c, step, keep)
		if err != nil {
			return err
		}
		return printJSON(done.Payment)
	case "payment-status", "cancel-payment":
		if len(args) < 2 {
			return fmt.Errorf("usage: obdev %s REF", args[0])
		}
		po := obsdk.PaymentCallOptions{Session: s, PSU: opts.PSU}
		if args[0] == "payment-status" {
			res, err := c.PaymentStatus(ctx, args[1], po)
			if err != nil {
				return err
			}
			keep(res.Session)
			return printJSON(res.Data)
		}
		step, err := c.CancelPayment(ctx, args[1], po)
		if err != nil {
			return err
		}
		done, err := drive(ctx, c, step, keep)
		if err != nil {
			return err
		}
		return printJSON(done.Payment)
	case "auth-methods":
		lister, ok := c.(obsdk.AuthMethodLister)
		if !ok {
			return fmt.Errorf("%w: this integration does not list login methods", obsdk.ErrUnsupported)
		}
		ms, err := lister.AuthMethods(ctx)
		if err != nil {
			return err
		}
		return printJSON(ms)
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

// paymentFlags builds a single-transfer PaymentRequest from command-line flags.
func paymentFlags(args []string) (obsdk.PaymentRequest, bool, error) {
	fs := flag.NewFlagSet("pay", flag.ExitOnError)
	typ := fs.String("type", "", "payment type: sepa, sepa_instant, domestic, crossborder, internal")
	amount := fs.String("amount", "", "amount, e.g. 1.00")
	currency := fs.String("currency", "", "ISO 4217 currency")
	to := fs.String("to", "", "payee account")
	scheme := fs.String("scheme", "", "payee account scheme (IBAN, BBAN, SORT_CODE_ACCOUNT, BANKGIRO, PLUSGIRO); default: IBAN if it starts with two letters, else BBAN")
	name := fs.String("name", "", "payee name")
	msg := fs.String("message", "", "remittance line / payment reference")
	ref := fs.String("ref", "", "structured reference, as SCHEME:VALUE (e.g. OCR:1234567890 or RF:RF18539007547034)")
	from := fs.String("from", "", "debtor account (IBAN if it starts with two letters, else BBAN)")
	date := fs.String("date", "", "execution date YYYY-MM-DD")
	e2e := fs.String("e2e", "", "end-to-end id")
	bic := fs.String("bic", "", "payee bank BIC")
	street := fs.String("street", "", "payee street")
	town := fs.String("town", "", "payee town")
	postcode := fs.String("postcode", "", "payee post code")
	country := fs.String("country", "", "payee country")
	charge := fs.String("charge", "", "charge bearer: DEBT, CRED, SHAR, SLEV")
	pctx := fs.String("context", "", "payment context, e.g. party_to_party")
	method := fs.String("method", "", "approval method: redirect or decoupled")
	withSession := fs.Bool("session", false, "reuse the saved session's login")
	_ = fs.Parse(args)
	if *typ == "" || *amount == "" || *currency == "" || *to == "" {
		fs.Usage()
		return obsdk.PaymentRequest{}, false, fmt.Errorf("-type, -amount, -currency and -to are required")
	}
	ident := func(v, sc string) obsdk.Identifier {
		if sc == "" {
			sc = obsdk.SchemeBBAN
			if len(v) > 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z' {
				sc = obsdk.SchemeIBAN
			}
		}
		return obsdk.Identifier{Scheme: sc, Value: v}
	}
	t := obsdk.Transfer{Amount: obsdk.Money{Amount: obsdk.Decimal(*amount), Currency: *currency},
		Creditor: obsdk.Creditor{Name: *name, Account: ident(*to, *scheme)}, EndToEndID: *e2e}
	if *msg != "" {
		t.Remittance = []string{*msg}
	}
	if *ref != "" {
		sc, v, ok := strings.Cut(*ref, ":")
		if !ok {
			return obsdk.PaymentRequest{}, false, fmt.Errorf("-ref wants SCHEME:VALUE")
		}
		t.Reference = &obsdk.Reference{Scheme: sc, Value: v}
	}
	if *bic != "" {
		t.Creditor.Agent = &obsdk.Agent{BIC: *bic}
	}
	if *street+*town+*postcode+*country != "" {
		t.Creditor.Address = &obsdk.PostalAddress{Street: *street, Town: *town, PostCode: *postcode, Country: *country}
	}
	r := obsdk.PaymentRequest{Type: obsdk.PaymentType(*typ), Method: *method, Transfers: []obsdk.Transfer{t},
		ExecutionDate: *date, ChargeBearer: *charge, Context: *pctx}
	if *from != "" {
		id := ident(*from, "")
		r.Debtor = &obsdk.PaymentDebtor{Account: &id}
	}
	return r, *withSession, nil
}

func orUsage(err error, u string) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("usage: %s", u)
}

func parseDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// drive plays the application's part: it shows redirects, asks for input and
// waits, until the operation is done. Like an application, it saves the
// session from every step and from a failure that still carries one.
func drive(ctx context.Context, c obsdk.Client, step *obsdk.Step, keep func(*obsdk.Session)) (*obsdk.Step, error) {
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		line, err := in.ReadString('\n')
		return strings.TrimSpace(line), err
	}
	seenPayment := false
	for i := 0; i < 100; i++ {
		keep(step.Session)
		if p := step.Payment; p != nil && !seenPayment && step.Kind != obsdk.StepDone {
			seenPayment = true
			fmt.Fprintf(os.Stderr, "payment created at the bank: id %s, status %s\nref: %s\n", p.ID, p.Status, p.Ref)
		}
		if step.Message != "" {
			fmt.Fprintln(os.Stderr, step.Message)
		}
		if ch := step.Challenge; ch != nil {
			if ch.Code != "" {
				fmt.Fprintln(os.Stderr, "Code shown to the user:", ch.Code)
			}
			if ch.Text != "" {
				fmt.Fprintln(os.Stderr, ch.Text)
			}
		}
		var input obsdk.StepInput
		switch step.Kind {
		case obsdk.StepDone:
			return step, nil
		case obsdk.StepRedirect:
			fmt.Fprintln(os.Stderr, "\nOpen this URL, log in, then paste the full callback URL (or its query string):\n\n  "+step.Redirect.URL+"\n")
			cb, err := ask("callback> ")
			if err != nil {
				return nil, err
			}
			input.Callback = cb
		case obsdk.StepInputRequired:
			input.Values = map[string]string{}
			for _, f := range step.Fields {
				label := f.Label
				if len(f.Options) > 0 {
					var opts []string
					for _, o := range f.Options {
						opts = append(opts, o.Value+"="+o.Label)
					}
					label += " [" + strings.Join(opts, ", ") + "]"
				}
				v, err := ask(label + "> ")
				if err != nil {
					return nil, err
				}
				input.Values[f.Key] = v
			}
		case obsdk.StepDisplay, obsdk.StepWait:
			if step.NeedsUser {
				if _, err := ask("press Enter once done> "); err != nil {
					return nil, err
				}
			}
			select {
			case <-time.After(step.WaitFor):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var err error
		if step, err = c.Resume(ctx, step.State, input); err != nil {
			var fe *obsdk.FlowError
			if errors.As(err, &fe) {
				keep(fe.Session)
				fmt.Fprintln(os.Stderr, "the flow failed after login; the session was saved")
				if fe.Payment != nil {
					fmt.Fprintf(os.Stderr, "payment %s exists at the bank (status %s), ref: %s\n", fe.Payment.ID, fe.Payment.Status, fe.Payment.Ref)
				}
			}
			return nil, err
		}
	}
	return nil, fmt.Errorf("flow did not finish after 100 steps")
}

func replay(ctx context.Context, dir string) error {
	s, err := obsdktest.LoadScenario(dir)
	if err != nil {
		return err
	}
	out, unused, err := obsdktest.Replay(ctx, s)
	if err != nil {
		return err
	}
	b, err := obsdktest.MarshalOutcomes(out)
	if err != nil {
		return err
	}
	os.Stdout.Write(b)
	for _, u := range unused {
		fmt.Fprintln(os.Stderr, "unused exchange:", u)
	}
	return nil
}

// printJWKS prints the public half of the signing key as a JWKS, for banks
// that fetch it from a URL registered in their portal. It holds only public
// data (modulus, exponent, certificate).
func printJWKS() error {
	path := os.Getenv(obsdktest.EnvSealCert)
	if path == "" {
		path = os.Getenv(obsdktest.EnvTLSCert)
	}
	kid := os.Getenv(obsdktest.EnvSealKID)
	if path == "" || kid == "" {
		return fmt.Errorf("set %s (or %s) and %s", obsdktest.EnvSealCert, obsdktest.EnvTLSCert, obsdktest.EnvSealKID)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%s: only RSA keys are supported", path)
	}
	enc := base64.RawURLEncoding
	return printJSON(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "kid": kid,
		"n":   enc.EncodeToString(pub.N.Bytes()),
		"e":   enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}}})
}
