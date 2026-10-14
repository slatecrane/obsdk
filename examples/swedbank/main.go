// Command swedbank connects to a Swedbank sandbox (or production) account and
// prints accounts, balances and recent transactions. It is a reference for how
// to drive the SDK's steps, not production code.
//
//	export SWEDBANK_CLIENT_ID=... SWEDBANK_CLIENT_SECRET=... SWEDBANK_REDIRECT_URL=https://localhost/callback
//	go run ./examples/swedbank -country SE -method redirect -psu-ip <your public IP>
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	_ "github.com/slatecrane/obsdk/banks/all"
)

func main() {
	country := flag.String("country", "SE", "SE, EE, LV or LT")
	method := flag.String("method", "redirect", "redirect or decoupled")
	env := flag.String("env", "sandbox", "sandbox or production")
	psuIP := flag.String("psu-ip", "", "the user's public IP address (required by the bank)")
	sessionFile := flag.String("session", "swedbank-session.json", "where to save the session")
	flag.Parse()
	if *psuIP == "" {
		log.Fatal("-psu-ip is required")
	}

	cfg := obsdk.Config{
		Env: obsdk.Env(*env),
		Credentials: obsdk.Credentials{
			ClientID:     os.Getenv("SWEDBANK_CLIENT_ID"),
			ClientSecret: obsdk.Secret(os.Getenv("SWEDBANK_CLIENT_SECRET")),
			RedirectURL:  os.Getenv("SWEDBANK_REDIRECT_URL"),
		},
	}
	ctx := context.Background()
	c, err := obsdk.New(obsdk.Target{Bank: "swedbank", Country: obsdk.Country(*country)}, cfg)
	if err != nil {
		log.Fatal(err)
	}

	psu := obsdk.PSUContext{IP: *psuIP, UserAgent: "ob-sdk-example/0"}
	step, err := c.Connect(ctx, obsdk.ConnectRequest{Method: *method, PSU: psu})
	if err != nil {
		log.Fatal(err)
	}
	in := bufio.NewReader(os.Stdin)
	for step.Kind != obsdk.StepDone {
		input := obsdk.StepInput{}
		switch step.Kind {
		case obsdk.StepRedirect:
			fmt.Printf("\nOpen this URL, log in, then paste the URL you were redirected to:\n%s\n> ", step.Redirect.URL)
			input.Callback = readLine(in)
		case obsdk.StepInputRequired:
			input.Values = map[string]string{}
			for _, f := range step.Fields {
				fmt.Printf("%s", f.Label)
				for i, o := range f.Options {
					fmt.Printf("\n  %d) %s", i+1, o.Label)
				}
				fmt.Print(": ")
				v := readLine(in)
				if n := 0; len(f.Options) > 0 {
					fmt.Sscan(v, &n)
					if n >= 1 && n <= len(f.Options) {
						v = f.Options[n-1].Value
					}
				}
				input.Values[f.Key] = v
			}
		case obsdk.StepWait, obsdk.StepDisplay:
			if step.Message != "" {
				fmt.Println(step.Message)
			}
			if ch := step.Challenge; ch != nil {
				fmt.Printf("Confirm in your bank app. Code: %q  App token: %q\n", ch.Code, ch.AutoStartToken)
			}
			time.Sleep(step.WaitFor)
		}
		if step, err = c.Resume(ctx, step.State, input); err != nil {
			log.Fatal(err)
		}
	}

	sess := step.Session
	save(*sessionFile, sess)
	fmt.Printf("\nConnected. Session saved to %s\n", *sessionFile)

	accs, err := c.Accounts(ctx, sess, obsdk.CallOptions{PSU: &psu})
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range accs.Data {
		fmt.Printf("\n%s  %s  (%s)\n", a.Name, a.Identifiers[0].Value, a.Currency)
		bal, err := c.Balances(ctx, sess, a.ID, obsdk.CallOptions{PSU: &psu})
		if err != nil {
			fmt.Println("  balances:", err)
			continue
		}
		for _, b := range bal.Data {
			fmt.Printf("  %-18s %s %s\n", b.BankType, b.Amount.Amount, b.Amount.Currency)
		}
		tx, err := c.Transactions(ctx, sess, obsdk.TxQuery{AccountID: a.ID, From: time.Now().AddDate(0, 0, -30), Options: obsdk.CallOptions{PSU: &psu}})
		if err != nil {
			fmt.Println("  transactions:", err)
			continue
		}
		for _, t := range tx.Transactions {
			fmt.Printf("  %s  %10s %s  %s\n", t.BookingDate, t.Amount.Amount, t.Amount.Currency, t.Counterparty.Name)
		}
	}
}

func readLine(r *bufio.Reader) string {
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

func save(path string, s *obsdk.Session) {
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		log.Fatal(err)
	}
}
