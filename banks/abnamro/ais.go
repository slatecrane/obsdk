package abnamro

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// The account-information API is per account: there is no account list, the
// consent names one IBAN (read at Connect and kept as the consent's account),
// and that IBAN is the account id.

// sessionIBAN is the account the session's consent covers.
func sessionIBAN(s *obsdk.Session) string {
	if s == nil {
		return ""
	}
	if a := s.Consents[consentKind].Accounts; len(a) > 0 {
		return a[0]
	}
	return ""
}

// aisCall performs an account-information GET with the user's token.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, r req) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" {
		return nil, &obsdk.ReauthError{Reason: "no_access_token"}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	r.method, r.bearer = http.MethodGet, s.AccessToken
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

// accountPath checks that id is the session's account: any other IBAN is
// refused by ABN AMRO anyway (403, no access).
func accountPath(s *obsdk.Session, id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return "", fmt.Errorf("%w: %q is not an ABN AMRO account id", obsdk.ErrInvalidRequest, id)
	}
	if iban := sessionIBAN(s); iban != "" && id != iban {
		return "", fmt.Errorf("%w: the session's consent covers %s, not %s", obsdk.ErrInvalidRequest, iban, id)
	}
	return "/v1/accounts/" + url.PathEscape(id), nil
}

// amount turns ABN AMRO's amount (a JSON number, unsigned on activities and
// signed on balances) and its creditDebitIndicator into a signed decimal.
// The number's text is kept as sent, so no precision is lost.
func amount(n json.Number, indicator string) (obsdk.Decimal, obsdk.Direction) {
	s := strings.TrimPrefix(n.String(), "-")
	if strings.ContainsAny(s, "eE") {
		if r, ok := new(big.Rat).SetString(s); ok {
			s = r.FloatString(2)
		}
	}
	if s == "" {
		s = "0"
	}
	if indicator == "DBIT" || (indicator == "" && strings.HasPrefix(n.String(), "-")) {
		return obsdk.Decimal("-" + s), obsdk.Debit
	}
	return obsdk.Decimal(s), obsdk.Credit
}

// ---- accounts ----

type detailsJSON struct {
	AccountNumber     string `json:"accountNumber"`
	Currency          string `json:"currency"`
	AccountHolderName string `json:"accountHolderName"`
}

// account reads the details of the session's account.
func (c *client) account(ctx context.Context, s *obsdk.Session, _ *obsdk.PSUContext) (obsdk.Account, *resp, error) {
	iban := sessionIBAN(s)
	if iban == "" {
		return obsdk.Account{}, nil, &obsdk.ReauthError{Reason: "no_account", Consent: consentKind}
	}
	p, err := accountPath(s, iban)
	if err != nil {
		return obsdk.Account{}, nil, err
	}
	res, err := c.aisCall(ctx, s, req{op: opAccounts, path: p + "/details"})
	if err != nil {
		return obsdk.Account{}, nil, err
	}
	var d detailsJSON
	if err := json.Unmarshal(res.body, &d); err != nil {
		return obsdk.Account{}, res, fmt.Errorf("abnamro: unreadable account details: %w", err)
	}
	if d.AccountNumber == "" {
		d.AccountNumber = iban
	}
	acc := obsdk.Account{ID: d.AccountNumber, OwnerName: d.AccountHolderName, Currency: d.Currency, BIC: bic, Raw: res.body,
		Identifiers: []obsdk.Identifier{{Scheme: obsdk.SchemeIBAN, Value: d.AccountNumber}}}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, d.Currency)
	return acc, res, nil
}

// Accounts returns the one account the consent covers.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	acc, res, err := c.account(ctx, s, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: []obsdk.Account{acc}, Raw: res.body}, nil
}

// ---- balances ----

type balanceJSON struct {
	BalanceType          string      `json:"balanceType"`
	Amount               json.Number `json:"amount"`
	Currency             string      `json:"currency"`
	CreditDebitIndicator string      `json:"creditDebitIndicator"`
}

// balanceTypes are read one call each. Only BOOKBALANCE exists for accounts
// outside the Netherlands; the others answer 400 there and are skipped.
var balanceTypes = []struct {
	bank string
	kind obsdk.BalanceKind
}{
	{"BOOKBALANCE", obsdk.BalanceInterimBooked},
	// Booked balance minus reservations (card holds and similar).
	{"BOOKBALANCEINCLUDINGRESERVATION", obsdk.BalanceInterimAvailable},
	// Balance by value date; no normalized kind.
	{"VALUEBALANCE", obsdk.BalanceOther},
}

// Balances returns the account's book, available (after reservations) and
// value-dated balances.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	p, err := accountPath(s, accountID)
	if err != nil {
		return nil, err
	}
	var out []obsdk.Balance
	var raws []json.RawMessage
	for i, bt := range balanceTypes {
		res, err := c.aisCall(ctx, s, req{op: opBalances, path: p + "/balances", query: url.Values{"balanceType": {bt.bank}}})
		if err != nil {
			var ae *obsdk.APIError
			if i > 0 && errors.As(err, &ae) && ae.Status == http.StatusBadRequest {
				continue
			}
			return nil, err
		}
		var b balanceJSON
		if err := json.Unmarshal(res.body, &b); err != nil {
			return nil, fmt.Errorf("abnamro: unreadable balance: %w", err)
		}
		amt, _ := amount(b.Amount, b.CreditDebitIndicator)
		out = append(out, obsdk.Balance{Kind: bt.kind, BankType: b.BalanceType, Amount: obsdk.Money{Amount: amt, Currency: b.Currency}})
		raws = append(raws, res.body)
	}
	raw, _ := json.Marshal(raws)
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: raw}, nil
}

// ---- transactions ----

type activityJSON struct {
	ID                          string      `json:"id"`
	MutationCode                string      `json:"mutationCode"`
	DescriptionLines            []string    `json:"descriptionLines"`
	Timestamp                   string      `json:"timestamp"`
	BookDate                    string      `json:"bookDate"`
	Amount                      json.Number `json:"amount"`
	CreditDebitIndicator        string      `json:"creditDebitIndicator"`
	Currency                    string      `json:"currency"`
	BalanceAfterMutation        json.Number `json:"balanceAfterMutation"`
	BalanceCreditDebitIndicator string      `json:"balanceCreditDebitIndicator"`
	CounterPartyAccountNumber   string      `json:"counterPartyAccountNumber"`
	CounterPartyName            string      `json:"counterPartyName"`
	Status                      string      `json:"status"`
}

var ibanRE = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)

// remittance cleans the description lines: ABN AMRO pads them with commas
// (",,") and sends empty ones. The original stays in Raw.
func remittance(lines []string) []string {
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(l), ","))
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func toTransaction(raw json.RawMessage, status obsdk.TxStatus) (obsdk.Transaction, error) {
	var a activityJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Transaction{}, err
	}
	amt, dir := amount(a.Amount, a.CreditDebitIndicator)
	tx := obsdk.Transaction{
		ID: a.ID, Status: status, Direction: dir, Amount: obsdk.Money{Amount: amt, Currency: a.Currency},
		BookingDate: a.BookDate, BankCode: a.MutationCode, Remittance: remittance(a.DescriptionLines), Raw: raw,
		Counterparty: obsdk.Party{Name: strings.TrimSpace(a.CounterPartyName)},
	}
	if n := strings.ToUpper(strings.ReplaceAll(a.CounterPartyAccountNumber, " ", "")); n != "" {
		scheme := obsdk.SchemeBBAN
		if ibanRE.MatchString(n) {
			scheme = obsdk.SchemeIBAN
		}
		tx.Counterparty.Identifiers = []obsdk.Identifier{{Scheme: scheme, Value: n}}
	}
	if a.BalanceAfterMutation != "" {
		bal, _ := amount(a.BalanceAfterMutation, a.BalanceCreditDebitIndicator)
		tx.BalanceAfter = &obsdk.Money{Amount: bal, Currency: a.Currency}
	}
	return tx, nil
}

func parseActivities(body []byte) (obsdk.TxPage, string, error) {
	var b struct {
		NextPageKey string `json:"nextPageKey"`
		Activities  struct {
			Booked       []json.RawMessage `json:"booked"`
			Reservations []json.RawMessage `json:"reservations"`
		} `json:"activities"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, "", fmt.Errorf("abnamro: unreadable activities response: %w", err)
	}
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: body}
	for _, l := range []struct {
		raws []json.RawMessage
		st   obsdk.TxStatus
	}{{b.Activities.Booked, obsdk.TxBooked}, {b.Activities.Reservations, obsdk.TxPending}} {
		for _, r := range l.raws {
			t, err := toTransaction(r, l.st)
			if err != nil {
				return page, "", fmt.Errorf("abnamro: unreadable activity: %w", err)
			}
			page.Transactions = append(page.Transactions, t)
		}
	}
	return page, b.NextPageKey, nil
}

const (
	activityBooked      = "BOOKED"
	activityReservation = "RESERVATION"
)

// activityQueries returns the activity types to read, in order: booked
// transactions, then reservations (ABN AMRO's pending items) when asked for.
func activityQueries(st []obsdk.TxStatus) []string {
	var booked, pending bool
	for _, s := range st {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	switch {
	case pending && booked:
		return []string{activityBooked, activityReservation}
	case pending:
		return []string{activityReservation}
	}
	return []string{activityBooked}
}

// Transactions returns a page of activities, 50 at most.
//
// The cursor is the query of the next request: ABN AMRO's nextPageKey plus
// the filters, which it wants repeated. When both booked and pending items
// are asked for, the booked pages come first and the last one's cursor
// switches to reservations (cursor parameter "then").
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	p, err := accountPath(s, q.AccountID)
	if err != nil {
		return nil, err
	}
	var query url.Values
	if q.Cursor != "" {
		query, err = url.ParseQuery(q.Cursor)
		if err != nil || query.Get("activityType") == "" {
			return nil, fmt.Errorf("%w: cursor is not an ABN AMRO activities cursor", obsdk.ErrInvalidRequest)
		}
	} else {
		types := activityQueries(q.Status)
		query = url.Values{"activityType": {types[0]}}
		if len(types) > 1 {
			query.Set("then", types[1])
		}
		if !q.From.IsZero() {
			query.Set("dateFrom", q.From.Format(time.DateOnly))
		}
		if !q.To.IsZero() {
			query.Set("dateTo", q.To.Format(time.DateOnly))
		}
	}
	then := query.Get("then")
	send := url.Values{}
	for k, v := range query {
		if k != "then" {
			send[k] = v
		}
	}
	if send.Get("activityType") == activityReservation {
		// Without a status ABN AMRO also returns cancelled reservations,
		// which are not pending items.
		send.Set("status", "ACTIVE")
	}
	res, err := c.aisCall(ctx, s, req{op: opTransactions, path: p + "/activities", query: send})
	if err != nil {
		return nil, err
	}
	page, next, err := parseActivities(res.body)
	if err != nil {
		return nil, err
	}
	switch {
	case next != "":
		nq := url.Values{}
		for k, v := range query {
			nq[k] = v
		}
		nq.Set("nextPageKey", next)
		page.NextCursor = nq.Encode()
	case then != "":
		nq := url.Values{"activityType": {then}}
		for _, k := range []string{"dateFrom", "dateTo"} {
			if v := query.Get(k); v != "" {
				nq.Set(k, v)
			}
		}
		page.NextCursor = nq.Encode()
	}
	return &obsdk.TxResult{TxPage: page}, nil
}
