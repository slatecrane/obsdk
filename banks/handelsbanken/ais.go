package handelsbanken

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

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
	r.method, r.bearer, r.api = http.MethodGet, s.AccessToken, true
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

// ---- accounts ----

// amountJSON is {"content": 1.00, "currency"}. The LU sandbox writes
// {"amount": 1.00, "currency"} instead (and calls the object balanceAmount /
// transactionAmount), against its own spec; both are read.
type amountJSON struct {
	Currency string      `json:"currency"`
	Content  json.Number `json:"content"`
	Amount   json.Number `json:"amount"`
}

func (a *amountJSON) value() string {
	if a == nil {
		return ""
	}
	if a.Content != "" {
		return a.Content.String()
	}
	return a.Amount.String()
}

func (a *amountJSON) money() obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.value()), Currency: a.Currency}
}

type balanceJSON struct {
	BalanceType   string      `json:"balanceType"`
	Amount        *amountJSON `json:"amount"`
	BalanceAmount *amountJSON `json:"balanceAmount"` // LU sandbox
	Date          string      `json:"referenceDate"`
}

func (b balanceJSON) amount() *amountJSON {
	if b.Amount != nil {
		return b.Amount
	}
	return b.BalanceAmount
}

type accountJSON struct {
	AccountID      string        `json:"accountId"`
	IBAN           string        `json:"iban"`
	BBAN           string        `json:"bban"`
	Currency       string        `json:"currency"`
	AccountType    string        `json:"accountType"`
	BIC            string        `json:"bic"`
	ClearingNumber string        `json:"clearingNumber"`
	Name           string        `json:"name"`
	OwnerName      string        `json:"ownerName"`
	CreditLimit    json.Number   `json:"creditLimit"`
	Balances       []balanceJSON `json:"balances"`
}

// balanceKinds maps Handelsbanken's balance types.
var balanceKinds = map[string]obsdk.BalanceKind{
	"AVAILABLE_AMOUNT": obsdk.BalanceInterimAvailable, // includes reservations and credit
	"CURRENT":          obsdk.BalanceInterimBooked,    // booked, at the time of the request
	"BOOKED":           obsdk.BalanceInterimBooked,
}

func toBalances(bs []balanceJSON) []obsdk.Balance {
	out := make([]obsdk.Balance, 0, len(bs))
	for _, b := range bs {
		amt := b.amount()
		if amt.value() == "" {
			continue // the LU sandbox lists a VALUE_DATE balance without an amount
		}
		kind, ok := balanceKinds[b.BalanceType]
		if !ok {
			kind = obsdk.BalanceOther // VALUE_DATE, CLEARED (GB business)
		}
		out = append(out, obsdk.Balance{Kind: kind, BankType: b.BalanceType, Amount: amt.money(), ReferenceDate: day(b.Date)})
	}
	return out
}

func (c *client) toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{ID: a.AccountID, Name: a.Name, OwnerName: a.OwnerName, Currency: a.Currency, Product: a.AccountType, BIC: a.BIC, Raw: raw}
	if a.IBAN != "" {
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: "IBAN", Value: a.IBAN})
	}
	if a.BBAN != "" {
		bban := a.BBAN
		if c.target.Country == "SE" && a.ClearingNumber != "" && !strings.HasPrefix(bban, a.ClearingNumber) {
			// A Swedish BBAN for payments is clearing number + account number.
			bban = a.ClearingNumber + bban
		}
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: "BBAN", Value: bban})
	}
	if c.business() {
		acc.Usage = "ORGA"
	} else {
		acc.Usage = "PRIV"
	}
	if a.CreditLimit != "" {
		acc.CreditLimit = &obsdk.Money{Amount: obsdk.Decimal(a.CreditLimit.String()), Currency: a.Currency}
	}
	if len(a.Balances) > 0 {
		acc.Balances = toBalances(a.Balances)
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	res, err := c.aisCall(ctx, s, req{op: opAccounts, url: c.apiURL(c.accountsPath()), country: c.countryHeader(), psu: psu})
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Accounts []json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("handelsbanken: unreadable accounts response: %w", err)
	}
	out := make([]obsdk.Account, 0, len(body.Accounts))
	for _, raw := range body.Accounts {
		a, err := c.toAccount(raw)
		if err != nil {
			return nil, res, fmt.Errorf("handelsbanken: unreadable account: %w", err)
		}
		out = append(out, a)
	}
	return out, res, nil
}

func meta(h http.Header) obsdk.Meta { return obsdk.Meta{RequestID: h.Get("X-Request-ID")} }

// Accounts lists the accounts covered by the consent.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, res, err := c.listAccounts(ctx, s, opts.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: res.body, Meta: meta(res.header)}, nil
}

func checkID(id string) error {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return fmt.Errorf("%w: %q is not a Handelsbanken account id", obsdk.ErrInvalidRequest, id)
	}
	return nil
}

// Balances reads the account with withBalance=true; balances come inline.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if err := checkID(accountID); err != nil {
		return nil, err
	}
	res, err := c.aisCall(ctx, s, req{op: opBalances, url: c.apiURL(c.accountsPath() + "/" + url.PathEscape(accountID)),
		query: url.Values{"withBalance": {"true"}}, country: c.countryHeader(), psu: opts.PSU})
	if err != nil {
		return nil, err
	}
	var a accountJSON
	if err := json.Unmarshal(res.body, &a); err != nil {
		return nil, fmt.Errorf("handelsbanken: unreadable account details: %w", err)
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: toBalances(a.Balances), Raw: res.body, Meta: meta(res.header)}, nil
}

// ---- transactions ----

type txJSON struct {
	TransactionID     string       `json:"transactionId"`
	Status            string       `json:"status"`
	Amount            *amountJSON  `json:"amount"`
	TransactionAmount *amountJSON  `json:"transactionAmount"` // LU sandbox
	LedgerDate        string       `json:"ledgerDate"`
	BookingDate       string       `json:"bookingDate"`
	ValueDate         string       `json:"valueDate"`
	TransactionDate   string       `json:"transactionDate"`
	CreditDebit       string       `json:"creditDebit"`
	Remittance        string       `json:"remittanceInformation"`
	DebtorName        string       `json:"debtorName"`   // payer of a credit
	CreditorName      string       `json:"creditorName"` // payee of a debit
	Balance           *balanceJSON `json:"balance"`
}

// day cuts an ISO 8601 timestamp ("2017-11-17T00:00:00.000Z", as the spec
// shows) to its date; plain dates (what the sandbox sends) pass through.
func day(s string) string {
	if len(s) > 10 && s[10] == 'T' {
		return s[:10]
	}
	return s
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{ID: t.TransactionID, BookingDate: day(t.BookingDate), ValueDate: day(t.ValueDate),
		TransactionDate: day(t.TransactionDate), Raw: raw}
	tx.Status = obsdk.TxPending
	if strings.EqualFold(t.Status, "booked") {
		tx.Status = obsdk.TxBooked
		if tx.BookingDate == "" {
			tx.BookingDate = day(t.LedgerDate)
		}
	}
	amt := t.Amount
	if amt == nil {
		amt = t.TransactionAmount
	}
	if amt == nil {
		amt = &amountJSON{}
	}
	v := strings.TrimPrefix(amt.value(), "-")
	switch {
	case strings.EqualFold(t.CreditDebit, "debited"), t.CreditDebit == "" && strings.HasPrefix(amt.value(), "-"):
		tx.Direction = obsdk.Debit
		tx.Counterparty.Name = t.CreditorName
		if v != "" {
			v = "-" + v
		}
	default:
		tx.Direction = obsdk.Credit
		tx.Counterparty.Name = t.DebtorName
	}
	tx.Amount = obsdk.Money{Amount: obsdk.Decimal(v), Currency: amt.Currency}
	if r := strings.TrimSpace(t.Remittance); r != "" {
		tx.Remittance = []string{r}
	}
	if t.Balance != nil {
		if b := t.Balance.amount(); b.value() != "" {
			m := b.money()
			tx.BalanceAfter = &m
		}
	}
	return tx, nil
}

// Transactions returns the transactions in the date range. Handelsbanken
// does not page: it caps a request (and answers 206 then) and asks to narrow
// the dates, so there is a next cursor only if the bank ever sends a next link.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if err := checkID(q.AccountID); err != nil {
		return nil, err
	}
	u := c.apiURL(c.accountsPath() + "/" + url.PathEscape(q.AccountID) + "/transactions")
	query := url.Values{}
	// The NL sandbox rejects dateFrom/dateTo in every format ("Invalid date
	// format"), including the YYYY-MM-DD the other Handelsbanken APIs take. There
	// the dates are applied here instead; production gets them like elsewhere.
	filterHere := c.cfg.Env == obsdk.Sandbox && c.target.Country == "NL"
	if q.Cursor != "" {
		if !strings.HasPrefix(q.Cursor, c.api+"/") {
			return nil, fmt.Errorf("%w: not a Handelsbanken transactions cursor", obsdk.ErrInvalidRequest)
		}
		u = q.Cursor
	} else if !filterHere {
		if !q.From.IsZero() {
			query.Set("dateFrom", q.From.UTC().Format("2006-01-02"))
		}
		if !q.To.IsZero() {
			query.Set("dateTo", q.To.UTC().Format("2006-01-02"))
		}
	}
	res, err := c.aisCall(ctx, s, req{op: opTransactions, url: u, query: query, country: c.countryHeader(), psu: q.Options.PSU})
	if err != nil {
		return nil, err
	}
	page, err := c.parseTransactions(res.body, q.Status)
	if err != nil {
		return nil, err
	}
	if filterHere {
		page.Transactions = inRange(page.Transactions, q.From, q.To)
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res.header)}, nil
}

// inRange keeps the transactions dated within [from, to] (booking date, else
// value date); undated ones are kept.
func inRange(ts []obsdk.Transaction, from, to time.Time) []obsdk.Transaction {
	lo, hi := "", "9999-12-31"
	if !from.IsZero() {
		lo = from.UTC().Format("2006-01-02")
	}
	if !to.IsZero() {
		hi = to.UTC().Format("2006-01-02")
	}
	var out []obsdk.Transaction
	for _, t := range ts {
		d := t.BookingDate
		if d == "" {
			d = t.ValueDate
		}
		if d == "" || (d >= lo && d <= hi) {
			out = append(out, t)
		}
	}
	return out
}

func (c *client) parseTransactions(body []byte, want []obsdk.TxStatus) (obsdk.TxPage, error) {
	page := obsdk.TxPage{Raw: body}
	if len(bytes.TrimSpace(body)) == 0 {
		return page, nil // 204: no transactions
	}
	var b struct {
		Transactions []json.RawMessage `json:"transactions"`
		Links        struct {
			Next *struct{ Href string } `json:"next"`
		} `json:"_links"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, fmt.Errorf("handelsbanken: unreadable transactions response: %w", err)
	}
	booked, pending := len(want) == 0, false
	for _, s := range want {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	for _, raw := range b.Transactions {
		t, err := toTransaction(raw)
		if err != nil {
			return page, fmt.Errorf("handelsbanken: unreadable transaction: %w", err)
		}
		if (t.Status == obsdk.TxBooked && booked) || (t.Status == obsdk.TxPending && pending) {
			page.Transactions = append(page.Transactions, t)
		}
	}
	if n := b.Links.Next; n != nil && n.Href != "" {
		page.NextCursor = c.abs(n.Href)
	}
	return page, nil
}

// abs makes a link from the bank absolute.
func (c *client) abs(l string) string {
	if strings.HasPrefix(l, "http") {
		return l
	}
	if strings.HasPrefix(l, "/openbanking/") {
		return strings.TrimSuffix(c.api, "/openbanking") + l
	}
	return c.api + "/" + strings.TrimPrefix(l, "/")
}
