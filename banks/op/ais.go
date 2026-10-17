package op

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/flowstate"
)

const aisBase = "/accounts-psd2/v1"

// cardPrefix marks card ids in Account.ID: cards have their own endpoints.
const cardPrefix = "card~"

// cardCurrency: OP's card objects carry no currency; its cards are in euros.
const cardCurrency = "EUR"

// aisCall performs an account-information GET with the session's token.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, op, path string, query url.Values, psu *obsdk.PSUContext) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	now := c.now()
	if s.AccessExpired(now) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	if cons, ok := s.Consents[consentKind]; ok && cons.ValidUntil != nil && !now.Before(*cons.ValidUntil) {
		return nil, &obsdk.ReauthError{Reason: "consent_expired", Consent: consentKind}
	}
	res, err := c.do(ctx, req{op: op, method: http.MethodGet, path: aisBase + path, query: query, bearer: s.AccessToken, psu: psu})
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(op, res)
	}
	return res, nil
}

// ---- accounts ----

type accountJSON struct {
	AccountID              string `json:"accountId"`
	ProductName            string `json:"productName"`
	IdentifierSchema       string `json:"identifierSchema"`
	Identifier             string `json:"identifier"`
	ServicerSchema         string `json:"servicerSchema"`
	Servicer               string `json:"servicer"`
	Owner                  string `json:"owner"`
	NetBalance             string `json:"netBalance"`
	GrossBalance           string `json:"grossBalance"`
	CounterBalance         string `json:"counterBalance"`
	CoverReservationAmount string `json:"coverReservationAmount"`
	Currency               string `json:"currency"`
}

type cardJSON struct {
	CardID                      string `json:"cardId"`
	ProductName                 string `json:"productName"`
	CardNumber                  string `json:"cardNumber"`
	StatementBalance            string `json:"statementBalance"`
	AuthorizedOutstandingAmount string `json:"authorizedOutstandingAmount"`
}

func toAccount(raw json.RawMessage, usage string) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{
		ID: a.AccountID, Name: a.ProductName, Product: a.ProductName, OwnerName: a.Owner,
		Currency: a.Currency, Type: "CACC", Usage: usage, Raw: raw, Balances: accountBalances(a),
	}
	if a.ServicerSchema == "" || a.ServicerSchema == "BIC" {
		acc.BIC = a.Servicer
	}
	if a.Identifier != "" {
		scheme := a.IdentifierSchema
		if scheme == "" {
			scheme = obsdk.SchemeIBAN
		}
		acc.Identifiers = []obsdk.Identifier{{Scheme: scheme, Value: a.Identifier}}
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

// accountBalances maps OP's balances: net is what can be spent (cover
// reservations deducted), gross the balance before them, and counterBalance
// the euro value of a foreign-currency account.
func accountBalances(a accountJSON) []obsdk.Balance {
	var out []obsdk.Balance
	add := func(kind obsdk.BalanceKind, bankType, amount, currency string) {
		if amount != "" {
			out = append(out, obsdk.Balance{Kind: kind, BankType: bankType, Amount: obsdk.Money{Amount: obsdk.Decimal(amount), Currency: currency}})
		}
	}
	add(obsdk.BalanceInterimAvailable, "netBalance", a.NetBalance, a.Currency)
	add(obsdk.BalanceInterimBooked, "grossBalance", a.GrossBalance, a.Currency)
	if a.CounterBalance != "" && a.Currency != "EUR" {
		add(obsdk.BalanceOther, "counterBalance", a.CounterBalance, "EUR")
	}
	return out
}

func toCard(raw json.RawMessage, usage string) (obsdk.Account, error) {
	var k cardJSON
	if err := json.Unmarshal(raw, &k); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{
		ID: cardPrefix + k.CardID, Name: k.ProductName, Product: k.ProductName, Type: "CARD", Usage: usage,
		Currency: cardCurrency, Raw: raw, Balances: cardBalances(k),
	}
	if k.CardNumber != "" {
		acc.Identifiers = []obsdk.Identifier{{Scheme: "MASKED_PAN", Value: k.CardNumber}}
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, cardCurrency)
	return acc, nil
}

// cardBalances turns used credit into balances: what the card owes is
// negative. statementBalance leaves out open authorisations, which
// authorizedOutstandingAmount holds.
func cardBalances(k cardJSON) []obsdk.Balance {
	var out []obsdk.Balance
	if k.StatementBalance != "" {
		out = append(out, obsdk.Balance{Kind: obsdk.BalanceInterimBooked, BankType: "statementBalance",
			Amount: obsdk.Money{Amount: negate(k.StatementBalance), Currency: cardCurrency}})
	}
	if k.AuthorizedOutstandingAmount != "" {
		out = append(out, obsdk.Balance{Kind: obsdk.BalanceOther, BankType: "authorizedOutstandingAmount",
			Amount: obsdk.Money{Amount: negate(k.AuthorizedOutstandingAmount), Currency: cardCurrency}})
	}
	return out
}

func negate(s string) obsdk.Decimal {
	switch {
	case isZero(s):
		return obsdk.Decimal(s)
	case strings.HasPrefix(s, "-"):
		return obsdk.Decimal(s[1:])
	}
	return obsdk.Decimal("-" + s)
}

func isZero(s string) bool { return strings.Trim(strings.TrimPrefix(s, "-"), "0.") == "" }

func (c *client) usage() string {
	if c.target.Segment == obsdk.Business {
		return "ORGA"
	}
	return "PRIV"
}

// listAccounts returns the accounts and then the cards of the authorisation.
func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, []byte, error) {
	res, err := c.aisCall(ctx, s, opAccounts, "/accounts", nil, psu)
	if err != nil {
		return nil, nil, err
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(res.body, &raws); err != nil {
		return nil, res.body, fmt.Errorf("op: unreadable accounts response: %w", err)
	}
	accs := []obsdk.Account{}
	for _, raw := range raws {
		a, err := toAccount(raw, c.usage())
		if err != nil {
			return nil, res.body, fmt.Errorf("op: unreadable account: %w", err)
		}
		accs = append(accs, a)
	}
	cards, cardsBody, err := c.listCards(ctx, s, psu)
	if err != nil {
		return nil, res.body, err
	}
	for _, raw := range cards {
		a, err := toCard(raw, c.usage())
		if err != nil {
			return nil, res.body, fmt.Errorf("op: unreadable card: %w", err)
		}
		accs = append(accs, a)
	}
	all, _ := json.Marshal(map[string]json.RawMessage{"accounts": res.body, "cards": orNull(cardsBody)})
	return accs, all, nil
}

func (c *client) listCards(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]json.RawMessage, []byte, error) {
	res, err := c.aisCall(ctx, s, opAccounts, "/cards", nil, psu)
	if err != nil {
		return nil, nil, err
	}
	var raws []json.RawMessage
	if len(strings.TrimSpace(string(res.body))) > 0 {
		if err := json.Unmarshal(res.body, &raws); err != nil {
			return nil, res.body, fmt.Errorf("op: unreadable cards response: %w", err)
		}
	}
	return raws, res.body, nil
}

func orNull(b []byte) json.RawMessage {
	if len(strings.TrimSpace(string(b))) == 0 {
		return json.RawMessage("null")
	}
	return b
}

// Accounts lists the accounts and cards covered by the authorisation.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, raw, err := c.listAccounts(ctx, s, opts.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: raw}, nil
}

// ---- balances ----

// Balances reads one account (or card) again for its current balances.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if accountID == "" {
		return nil, fmt.Errorf("%w: empty account id", obsdk.ErrInvalidRequest)
	}
	if id, ok := strings.CutPrefix(accountID, cardPrefix); ok {
		// There is no single-card endpoint: find the card in the list.
		cards, body, err := c.listCards(ctx, s, opts.PSU)
		if err != nil {
			return nil, err
		}
		for _, raw := range cards {
			var k cardJSON
			if json.Unmarshal(raw, &k) == nil && k.CardID == id {
				return &obsdk.Result[[]obsdk.Balance]{Data: cardBalances(k), Raw: body}, nil
			}
		}
		return nil, fmt.Errorf("%w: card %s is not covered by the authorisation", obsdk.ErrInvalidRequest, id)
	}
	res, err := c.aisCall(ctx, s, opBalances, "/accounts/"+url.PathEscape(accountID), nil, opts.PSU)
	if err != nil {
		return nil, err
	}
	var a accountJSON
	if err := json.Unmarshal(res.body, &a); err != nil {
		return nil, fmt.Errorf("op: unreadable account response: %w", err)
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: accountBalances(a), Raw: res.body, Meta: meta(res)}, nil
}

// ---- transactions ----

type txJSON struct {
	ArchiveID   string `json:"archiveId"`
	Message     string `json:"message"`
	Reference   string `json:"reference"`
	Amount      string `json:"amount"`
	Currency    string `json:"currency"`
	BookingDate string `json:"bookingDate"`
	ValueDate   string `json:"valueDate"`
	PaymentDate string `json:"paymentDate"`
	Payer       *struct {
		Name string `json:"name"`
	} `json:"payer"`
	Recipient *struct {
		Name       string   `json:"name"`
		Identifier string   `json:"identifier"`
		Servicer   string   `json:"servicer"`
		Address    []string `json:"address"`
	} `json:"recipient"`
	Description string `json:"proprietaryTransactionDescription"`
}

type cardTxJSON struct {
	Description     string `json:"description"`
	Amount          string `json:"amount"`
	Currency        string `json:"currency"`
	PostingDate     string `json:"postingDate"`
	TransactionDate string `json:"transactionDate"`
}

type txPageJSON struct {
	Transactions      []json.RawMessage `json:"transactions"`
	ContinuationToken string            `json:"continuationToken"`
}

// txCursor is TxPage.NextCursor: OP's continuation token and the date
// window being filtered, since OP itself takes no dates.
type txCursor struct {
	Token string `json:"t"`
	From  string `json:"f,omitempty"`
	To    string `json:"to,omitempty"`
}

func direction(amount string) obsdk.Direction {
	if strings.HasPrefix(amount, "-") {
		return obsdk.Debit
	}
	return obsdk.Credit
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	// archiveId is not unique (related transactions with several recipients
	// share one), so it is the entry reference rather than the id.
	tx := obsdk.Transaction{
		EntryReference: t.ArchiveID, Status: obsdk.TxBooked, Direction: direction(t.Amount),
		Amount:      obsdk.Money{Amount: obsdk.Decimal(t.Amount), Currency: t.Currency},
		BookingDate: t.BookingDate, ValueDate: t.ValueDate, TransactionDate: t.PaymentDate,
		ReferenceNumber: t.Reference, BankCodeText: t.Description, Raw: raw,
	}
	if t.Message != "" {
		tx.Remittance = []string{t.Message}
	}
	// The other side: the recipient of a debit, the payer of a credit.
	if tx.Direction == obsdk.Debit && t.Recipient != nil {
		tx.Counterparty.Name = t.Recipient.Name
		if t.Recipient.Identifier != "" {
			tx.Counterparty.Identifiers = append(tx.Counterparty.Identifiers, obsdk.Identifier{Scheme: accountScheme(t.Recipient.Identifier), Value: t.Recipient.Identifier})
		}
		if t.Recipient.Servicer != "" {
			tx.Counterparty.Identifiers = append(tx.Counterparty.Identifiers, obsdk.Identifier{Scheme: "BIC", Value: t.Recipient.Servicer})
		}
	} else if tx.Direction == obsdk.Credit && t.Payer != nil {
		tx.Counterparty.Name = t.Payer.Name
	}
	return tx, nil
}

// accountScheme guesses the scheme of a counterparty account: OP sends IBANs
// for SEPA payments and other formats otherwise.
func accountScheme(id string) string {
	if obsdk.ValidateIdentifier(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: id}) == nil {
		return obsdk.SchemeIBAN
	}
	return obsdk.SchemeBBAN
}

// toCardTransaction maps a card transaction. Card amounts are what was
// spent, so a purchase (positive) is a debit and a refund (negative) a credit.
func toCardTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t cardTxJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	amt := negate(t.Amount)
	tx := obsdk.Transaction{
		Status: obsdk.TxBooked, Direction: direction(string(amt)),
		Amount:      obsdk.Money{Amount: amt, Currency: t.Currency},
		BookingDate: t.PostingDate, TransactionDate: t.TransactionDate,
		Counterparty: obsdk.Party{Name: t.Description}, Raw: raw,
	}
	return tx, nil
}

// Transactions returns one page of booked transactions (OP reports no
// pending ones). OP pages with continuation tokens and has no date filter,
// so each page is filtered to From..To and may come back empty while
// NextCursor is set; paging stops at the first page that reaches before From.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if q.AccountID == "" {
		return nil, fmt.Errorf("%w: empty account id", obsdk.ErrInvalidRequest)
	}
	if !wantsBooked(q.Status) {
		return &obsdk.TxResult{TxPage: obsdk.TxPage{Transactions: []obsdk.Transaction{}}}, nil
	}
	from, to := day(q.From), day(q.To)
	query := url.Values{}
	if q.Cursor != "" {
		var cur txCursor
		if err := flowstate.Decode(q.Cursor, &cur); err != nil || cur.Token == "" {
			return nil, fmt.Errorf("%w: not an OP transactions cursor", obsdk.ErrInvalidRequest)
		}
		query.Set("continuationToken", cur.Token)
		from, to = cur.From, cur.To
	}
	path, card := "/accounts/"+url.PathEscape(q.AccountID)+"/transactions", false
	if id, ok := strings.CutPrefix(q.AccountID, cardPrefix); ok {
		path, card = "/cards/"+url.PathEscape(id)+"/transactions", true
	}
	res, err := c.aisCall(ctx, s, opTransactions, path, query, q.Options.PSU)
	if err != nil {
		return nil, err
	}
	var pj txPageJSON
	if len(strings.TrimSpace(string(res.body))) > 0 {
		if err := json.Unmarshal(res.body, &pj); err != nil {
			return nil, fmt.Errorf("op: unreadable transactions response: %w", err)
		}
	}
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: res.body}
	pastFrom := false
	for _, raw := range pj.Transactions {
		var tx obsdk.Transaction
		if card {
			tx, err = toCardTransaction(raw)
		} else {
			tx, err = toTransaction(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("op: unreadable transaction: %w", err)
		}
		if inRange(tx, from, to) {
			page.Transactions = append(page.Transactions, tx)
		} else if d := txDate(tx); from != "" && d != "" && d < from {
			pastFrom = true
		}
	}
	// OP lists newest first (seen in the sandbox): once a page reaches
	// dates before From, the following pages hold nothing in the window.
	if pj.ContinuationToken != "" && !pastFrom {
		if page.NextCursor, err = flowstate.Encode(txCursor{Token: pj.ContinuationToken, From: from, To: to}); err != nil {
			return nil, err
		}
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res)}, nil
}

func wantsBooked(st []obsdk.TxStatus) bool {
	if len(st) == 0 {
		return true
	}
	for _, s := range st {
		if s == obsdk.TxBooked {
			return true
		}
	}
	return false
}

func day(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

// inRange compares the booking date (or, without one, the payment date) with
// the window. Transactions without any date are kept.
func inRange(t obsdk.Transaction, from, to string) bool {
	d := txDate(t)
	return d == "" || ((from == "" || d >= from) && (to == "" || d <= to))
}

func txDate(t obsdk.Transaction) string {
	if t.BookingDate != "" {
		return t.BookingDate
	}
	return t.TransactionDate
}
