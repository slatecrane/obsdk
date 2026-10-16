package nordea

import (
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

func (c *client) accountsPath() string { return "/" + c.segment() + "/" + c.aisVersion() + "/accounts" }

// ---- accounts ----

type accountJSON struct {
	ID             string `json:"_id"`
	Country        string `json:"country"`
	AccountNumbers []struct {
		Value string `json:"value"`
		Type  string `json:"_type"`
	} `json:"account_numbers"`
	Currency      string                        `json:"currency"`
	AccountName   string                        `json:"account_name"`
	AccountHolder string                        `json:"account_holder"`
	AccountRoles  []struct{ Type, Name string } `json:"account_roles"`
	Product       string                        `json:"product"`
	AccountType   string                        `json:"account_type"`
	Available     string                        `json:"available_balance"`
	Booked        string                        `json:"booked_balance"`
	ValueDated    string                        `json:"value_dated_balance"`
	CreditLimit   string                        `json:"credit_limit"`
	LatestBooking string                        `json:"latest_transaction_booking_date"`
	Bank          struct{ BIC string }          `json:"bank"`
	Status        string                        `json:"status"`
}

// accountTypes maps Nordea's account_type to ISO 20022 cash account types.
var accountTypes = map[string]string{
	"Current": "CACC", "Savings": "SVGS", "Loan": "LOAN", "Card": "CARD", "Credit": "CARD",
}

func (c *client) toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{ID: a.ID, Name: a.AccountName, Currency: a.Currency, Product: a.Product,
		Type: accountTypes[a.AccountType], BIC: a.Bank.BIC, Raw: raw}
	for _, n := range a.AccountNumbers {
		scheme := n.Type
		if strings.HasPrefix(scheme, "BBAN") {
			scheme = "BBAN" // BBAN_SE, BBAN_DK, BBAN_NO
		}
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: scheme, Value: n.Value})
	}
	acc.OwnerName = a.AccountHolder
	for _, r := range a.AccountRoles {
		if r.Type == "OWNER" && acc.OwnerName == "" {
			acc.OwnerName = r.Name
		}
	}
	if c.target.Segment == obsdk.Business {
		acc.Usage = "ORGA"
	} else {
		acc.Usage = "PRIV"
	}
	if a.CreditLimit != "" {
		acc.CreditLimit = &obsdk.Money{Amount: obsdk.Decimal(a.CreditLimit), Currency: a.Currency}
	}
	acc.Balances = balancesOf(a)
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

// balancesOf reads the balances Nordea puts on the account itself.
func balancesOf(a accountJSON) []obsdk.Balance {
	var out []obsdk.Balance
	add := func(amount string, kind obsdk.BalanceKind, bankType string) {
		if amount != "" {
			out = append(out, obsdk.Balance{Kind: kind, BankType: bankType, Amount: obsdk.Money{Amount: obsdk.Decimal(amount), Currency: a.Currency}})
		}
	}
	add(a.Available, obsdk.BalanceInterimAvailable, "available_balance")
	add(a.Booked, obsdk.BalanceInterimBooked, "booked_balance")
	add(a.ValueDated, obsdk.BalanceOther, "value_dated_balance")
	return out
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	res, err := c.aisCall(ctx, s, req{op: opAccounts, path: c.accountsPath(), psu: psu})
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Response struct {
			Accounts []json.RawMessage `json:"accounts"`
		} `json:"response"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("nordea: unreadable accounts response: %w", err)
	}
	out := make([]obsdk.Account, 0, len(body.Response.Accounts))
	for _, raw := range body.Response.Accounts {
		a, err := c.toAccount(raw)
		if err != nil {
			return nil, res, fmt.Errorf("nordea: unreadable account: %w", err)
		}
		out = append(out, a)
	}
	return out, res, nil
}

func meta(h http.Header) obsdk.Meta { return obsdk.Meta{RequestID: h.Get("X-Global-Transaction-Id")} }

// Accounts lists the accounts the user granted access to, with balances.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, res, err := c.listAccounts(ctx, s, opts.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: res.body, Meta: meta(res.header)}, nil
}

func checkID(id string) error {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return fmt.Errorf("%w: %q is not a Nordea account id", obsdk.ErrInvalidRequest, id)
	}
	return nil
}

// Balances reads the account details, which carry the balances.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if err := checkID(accountID); err != nil {
		return nil, err
	}
	res, err := c.aisCall(ctx, s, req{op: opBalances, path: c.accountsPath() + "/" + url.PathEscape(accountID), psu: opts.PSU})
	if err != nil {
		return nil, err
	}
	var body struct {
		Response accountJSON `json:"response"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, fmt.Errorf("nordea: unreadable account details: %w", err)
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: balancesOf(body.Response), Raw: res.body, Meta: meta(res.header)}, nil
}

// ---- transactions ----

type txJSON struct {
	TransactionID    string `json:"transaction_id"`
	Currency         string `json:"currency"`
	Amount           string `json:"amount"`
	BookingDate      string `json:"booking_date"`
	ValueDate        string `json:"value_date"`
	TransactionDate  string `json:"transaction_date"`
	TypeDescription  string `json:"type_description"`
	Message          string `json:"message"`
	Narrative        string `json:"narrative"`
	Reference        string `json:"reference"`
	Status           string `json:"status"`
	CounterpartyName string `json:"counterparty_name"`
	CounterpartyAcct string `json:"counterparty_account"`
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{
		ID: t.TransactionID, Amount: obsdk.Money{Amount: obsdk.Decimal(t.Amount), Currency: t.Currency},
		BookingDate: t.BookingDate, ValueDate: t.ValueDate, TransactionDate: t.TransactionDate,
		ReferenceNumber: t.Reference, BankCodeText: t.TypeDescription, Raw: raw,
		Counterparty: obsdk.Party{Name: t.CounterpartyName},
	}
	if t.CounterpartyAcct != "" {
		tx.Counterparty.Identifiers = []obsdk.Identifier{{Scheme: schemeOf(t.CounterpartyAcct), Value: t.CounterpartyAcct}}
	}
	tx.Status = obsdk.TxPending
	if t.Status == "billed" {
		tx.Status = obsdk.TxBooked
	}
	tx.Direction = obsdk.Credit
	if strings.HasPrefix(t.Amount, "-") {
		tx.Direction = obsdk.Debit
	}
	msg := t.Message
	if msg == "" {
		msg = t.Narrative
	}
	if msg = strings.TrimSpace(msg); msg != "" {
		tx.Remittance = []string{msg}
	}
	return tx, nil
}

func schemeOf(acct string) string {
	if len(acct) > 4 && acct[0] >= 'A' && acct[0] <= 'Z' && acct[1] >= 'A' && acct[1] <= 'Z' {
		return "IBAN"
	}
	return "BBAN"
}

// Transactions returns a page. The cursor is Nordea's continuation_key; the
// date range comes from the query on every page.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if err := checkID(q.AccountID); err != nil {
		return nil, err
	}
	query := url.Values{}
	if !q.From.IsZero() {
		query.Set("from_date", q.From.UTC().Format("2006-01-02"))
	}
	if !q.To.IsZero() {
		query.Set("to_date", q.To.UTC().Format("2006-01-02"))
	}
	if q.Cursor != "" {
		query.Set("continuation_key", q.Cursor)
	}
	res, err := c.aisCall(ctx, s, req{op: opTransactions, path: c.accountsPath() + "/" + url.PathEscape(q.AccountID) + "/transactions",
		query: query, psu: q.Options.PSU})
	if err != nil {
		return nil, err
	}
	page, err := parseTransactions(res.body, q.Status)
	if err != nil {
		return nil, err
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res.header)}, nil
}

func parseTransactions(body []byte, want []obsdk.TxStatus) (obsdk.TxPage, error) {
	var b struct {
		Response struct {
			Transactions []json.RawMessage `json:"transactions"`
			Links        []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"_links"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, fmt.Errorf("nordea: unreadable transactions response: %w", err)
	}
	page := obsdk.TxPage{Raw: body}
	booked, pending := len(want) == 0, false
	for _, s := range want {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	for _, raw := range b.Response.Transactions {
		t, err := toTransaction(raw)
		if err != nil {
			return page, fmt.Errorf("nordea: unreadable transaction: %w", err)
		}
		if (t.Status == obsdk.TxBooked && booked) || (t.Status == obsdk.TxPending && pending) {
			page.Transactions = append(page.Transactions, t)
		}
	}
	// The next link carries continuation_key; its path differs between the
	// sandbox (/v5/...) and production (/personal/v5/...), so only the key is kept.
	for _, l := range b.Response.Links {
		if l.Rel == "next" {
			if u, err := url.Parse(l.Href); err == nil {
				page.NextCursor = u.Query().Get("continuation_key")
			}
		}
	}
	return page, nil
}
