package kbc

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

// defaultHistoryDays is how far back Transactions reads when TxQuery.From is
// zero: KBC requires dateFrom.
const defaultHistoryDays = 90

// aisCall performs an account-information request with the user's token and
// the consent id.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext, r req) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" {
		return nil, &obsdk.ReauthError{Reason: "no_access_token"}
	}
	cons, ok := s.Consents[consentKind]
	if !ok || cons.ID == "" {
		return nil, &obsdk.ReauthError{Reason: "no_consent", Consent: consentKind}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	h := psuHeaders(psu)
	h["Consent-ID"] = cons.ID
	r.method, r.bearer, r.header = http.MethodGet, s.AccessToken, h
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

func accountPath(id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return "", fmt.Errorf("%w: %q is not a KBC account id", obsdk.ErrInvalidRequest, id)
	}
	return "/accounts/" + url.PathEscape(id), nil
}

// ---- accounts ----

type amountJSON struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

func (a amountJSON) money() obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.Amount), Currency: a.Currency}
}

type balanceJSON struct {
	Type   string     `json:"balanceType"`
	Amount amountJSON `json:"balanceAmount"`
}

// toBalance maps KBC's balance types; KBC only reports closingBooked.
func toBalance(b balanceJSON) obsdk.Balance {
	kind := obsdk.BalanceOther
	switch b.Type {
	case "closingBooked":
		kind = obsdk.BalanceClosingBooked
	case "openingBooked":
		kind = obsdk.BalanceOpeningBooked
	case "interimBooked":
		kind = obsdk.BalanceInterimBooked
	case "interimAvailable":
		kind = obsdk.BalanceInterimAvailable
	}
	return obsdk.Balance{Kind: kind, BankType: b.Type, Amount: b.Amount.money()}
}

func toBalances(bs []balanceJSON) []obsdk.Balance {
	if len(bs) == 0 {
		return nil
	}
	out := make([]obsdk.Balance, 0, len(bs))
	for _, b := range bs {
		out = append(out, toBalance(b))
	}
	return out
}

type accountJSON struct {
	ResourceID      string        `json:"resourceId"`
	IBAN            string        `json:"iban"`
	Currency        string        `json:"currency"`
	Name            string        `json:"name"`
	Product         string        `json:"product"`
	CashAccountType string        `json:"cashAccountType"`
	Balances        []balanceJSON `json:"balances"`
}

func (c *client) toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, fmt.Errorf("kbc: unreadable account: %w", err)
	}
	acc := obsdk.Account{ID: a.ResourceID, Name: a.Name, Currency: a.Currency, Product: a.Product, Type: a.CashAccountType,
		BIC: c.brand.bic, Balances: toBalances(a.Balances), Raw: raw}
	if a.IBAN != "" {
		acc.Identifiers = []obsdk.Identifier{{Scheme: obsdk.SchemeIBAN, Value: a.IBAN}}
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

// listAccounts reads the consented account with its balance (KBC returns
// balances inline with withBalance=true).
func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	res, err := c.aisCall(ctx, s, psu, req{op: opAccounts, path: "/accounts", query: url.Values{"withBalance": {"true"}}})
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Accounts []json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("kbc: unreadable accounts response: %w", err)
	}
	out := make([]obsdk.Account, 0, len(body.Accounts))
	for _, raw := range body.Accounts {
		a, err := c.toAccount(raw)
		if err != nil {
			return nil, res, err
		}
		out = append(out, a)
	}
	return out, res, nil
}

// Accounts lists the accounts covered by the consent.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, res, err := c.listAccounts(ctx, s, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: res.body, Meta: meta(res.header)}, nil
}

// ---- balances ----

// Balances returns an account's balances.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	p, err := accountPath(accountID)
	if err != nil {
		return nil, err
	}
	res, err := c.aisCall(ctx, s, o.PSU, req{op: opBalances, path: p + "/balances"})
	if err != nil {
		return nil, err
	}
	var body struct {
		Balances []balanceJSON `json:"balances"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, fmt.Errorf("kbc: unreadable balances response: %w", err)
	}
	out := toBalances(body.Balances)
	if out == nil {
		out = []obsdk.Balance{}
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body, Meta: meta(res.header)}, nil
}

// ---- transactions ----

type partyAccountJSON struct {
	IBAN string `json:"iban"`
}

type txJSON struct {
	TransactionID       string           `json:"transactionId"`
	BookingDate         string           `json:"bookingDate"`
	ValueDate           string           `json:"valueDate"`
	Amount              amountJSON       `json:"transactionAmount"`
	CreditorName        string           `json:"creditorName"`
	CreditorAccount     partyAccountJSON `json:"creditorAccount"`
	DebtorName          string           `json:"debtorName"`
	DebtorAccount       partyAccountJSON `json:"debtorAccount"`
	Unstructured        string           `json:"remittanceInformationUnstructured"`
	Structured          string           `json:"remittanceInformationStructured"` // plain text at KBC, not an object
	BankTransactionCode string           `json:"bankTransactionCode"`
	ProprietaryCode     string           `json:"proprietaryBankTransactionCode"`
}

func partyOf(name string, a partyAccountJSON) obsdk.Party {
	p := obsdk.Party{Name: name}
	if a.IBAN != "" {
		p.Identifiers = []obsdk.Identifier{{Scheme: obsdk.SchemeIBAN, Value: a.IBAN}}
	}
	return p
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{
		ID: t.TransactionID, Status: obsdk.TxBooked, Amount: t.Amount.money(),
		BookingDate: t.BookingDate, ValueDate: t.ValueDate, ReferenceNumber: t.Structured,
		BankCode: t.BankTransactionCode, Raw: raw,
	}
	if tx.BankCode == "" {
		tx.BankCode = t.ProprietaryCode
	}
	if s := strings.TrimSpace(t.Unstructured); s != "" {
		tx.Remittance = []string{s}
	}
	// Amounts are signed: negative leaves the account. The counterparty is the
	// creditor of outgoing and the debtor of incoming money.
	if strings.HasPrefix(t.Amount.Amount, "-") {
		tx.Direction, tx.Counterparty = obsdk.Debit, partyOf(t.CreditorName, t.CreditorAccount)
	} else {
		tx.Direction, tx.Counterparty = obsdk.Credit, partyOf(t.DebtorName, t.DebtorAccount)
	}
	return tx, nil
}

// link reads a Berlin Group link, which KBC sends as a plain string; the
// standard's {"href": ...} object is accepted too.
type link string

func (l *link) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*l = link(s)
		return nil
	}
	var o struct {
		Href string `json:"href"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	*l = link(o.Href)
	return nil
}

func parseTransactions(body []byte) (obsdk.TxPage, error) {
	var b struct {
		Transactions struct {
			Booked []json.RawMessage `json:"booked"`
			Links  struct {
				Next link `json:"next"`
			} `json:"_links"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, fmt.Errorf("kbc: unreadable transactions response: %w", err)
	}
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: body, NextCursor: string(b.Transactions.Links.Next)}
	for _, r := range b.Transactions.Booked {
		t, err := toTransaction(r)
		if err != nil {
			return page, fmt.Errorf("kbc: unreadable transaction: %w", err)
		}
		page.Transactions = append(page.Transactions, t)
	}
	return page, nil
}

// cursorRequest turns a next link back into a request on the account's
// transactions. KBC's links may be absolute, start with the API's /psd2/v2
// base, or be relative to it; only links to the queried account are followed.
func (c *client) cursorRequest(accountPath, cursor string) (req, error) {
	u, err := url.Parse(cursor)
	if err != nil {
		return req{}, fmt.Errorf("%w: cursor is not a KBC next link", obsdk.ErrInvalidRequest)
	}
	base, _ := url.Parse(c.api)
	p := u.Path
	if base != nil && base.Path != "" {
		p = strings.TrimPrefix(p, base.Path)
	}
	p = strings.TrimPrefix(p, apiPath)
	if !strings.HasPrefix(p, accountPath+"/transactions") {
		return req{}, fmt.Errorf("%w: cursor is not a next link of this account's transactions", obsdk.ErrInvalidRequest)
	}
	return req{op: opTransactions, path: p, query: u.Query()}, nil
}

// checkStatuses: KBC only returns booked transactions. Asking for pending
// alone is refused; asking for both returns the booked ones.
func checkStatuses(st []obsdk.TxStatus) error {
	for _, s := range st {
		if s == obsdk.TxBooked {
			return nil
		}
	}
	if len(st) == 0 {
		return nil
	}
	return fmt.Errorf("%w: KBC only returns booked transactions", obsdk.ErrUnsupported)
}

// Transactions returns a page of transactions. The cursor is the bank's next
// link.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	p, err := accountPath(q.AccountID)
	if err != nil {
		return nil, err
	}
	if err := checkStatuses(q.Status); err != nil {
		return nil, err
	}
	var r req
	if q.Cursor != "" {
		if r, err = c.cursorRequest(p, q.Cursor); err != nil {
			return nil, err
		}
	} else {
		from := q.From
		if from.IsZero() {
			from = c.now().AddDate(0, 0, -defaultHistoryDays)
		}
		r = req{op: opTransactions, path: p + "/transactions",
			query: url.Values{"bookingStatus": {"booked"}, "dateFrom": {from.Format("2006-01-02")}}}
		if !q.To.IsZero() {
			r.query.Set("dateTo", q.To.Format("2006-01-02"))
		}
	}
	res, err := c.aisCall(ctx, s, q.Options.PSU, r)
	if err != nil {
		return nil, err
	}
	page, err := parseTransactions(res.body)
	if err != nil {
		return nil, err
	}
	if page.NextCursor != "" && page.NextCursor == q.Cursor {
		// A next link pointing at the page just read would loop forever.
		page.NextCursor = ""
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res.header)}, nil
}
