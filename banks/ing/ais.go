package ing

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

// aisCall performs a signed account-information request with the customer token.
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
	r.method, r.bearer, r.signed = http.MethodGet, s.AccessToken, true
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

// ---- account ids ----

// Account.ID is the resourceId, with two additions ING needs to route a
// call: "card~" in front of card accounts (their transactions live under
// /card-accounts), and "~CUR" behind Belgian multi-currency accounts, whose
// currencies share one resourceId and are told apart by a currency parameter.
type accountRef struct {
	resourceID string
	currency   string
	card       bool
}

func (a accountRef) id() string {
	s := a.resourceID
	if a.card {
		s = "card~" + s
	}
	if a.currency != "" {
		s += "~" + a.currency
	}
	return s
}

func parseAccountID(id string) (accountRef, error) {
	var a accountRef
	if rest, ok := strings.CutPrefix(id, "card~"); ok {
		a.card, id = true, rest
	}
	a.resourceID, a.currency, _ = strings.Cut(id, "~")
	if a.resourceID == "" || strings.ContainsAny(a.resourceID, "/?#") {
		return a, fmt.Errorf("%w: %q is not an ING account id", obsdk.ErrInvalidRequest, id)
	}
	return a, nil
}

func (a accountRef) currencyQuery() url.Values {
	if a.currency == "" {
		return nil
	}
	return url.Values{"currency": {a.currency}}
}

// ---- accounts ----

type linkJSON struct {
	Href string `json:"href"`
}

type accountJSON struct {
	ResourceID string `json:"resourceId"`
	IBAN       string `json:"iban"`
	MaskedPan  string `json:"maskedPan"`
	Name       string `json:"name"`
	Currency   string `json:"currency"`
	Product    string `json:"product"`
	Links      struct {
		Balances     linkJSON `json:"balances"`
		Transactions linkJSON `json:"transactions"`
	} `json:"_links"`
}

// toAccounts maps the accounts response. A resourceId listed more than once
// is a multi-currency account: each currency becomes its own Account.
func toAccounts(raws []json.RawMessage) ([]obsdk.Account, error) {
	parsed := make([]accountJSON, len(raws))
	seen := map[string]int{}
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &parsed[i]); err != nil {
			return nil, fmt.Errorf("ing: unreadable account: %w", err)
		}
		seen[parsed[i].ResourceID]++
	}
	out := make([]obsdk.Account, 0, len(raws))
	for i, a := range parsed {
		ref := accountRef{resourceID: a.ResourceID, card: strings.Contains(a.Links.Transactions.Href, "/card-accounts/")}
		if seen[a.ResourceID] > 1 {
			ref.currency = a.Currency
		}
		acc := obsdk.Account{ID: ref.id(), Name: a.Product, OwnerName: a.Name, Currency: a.Currency, Product: a.Product, Raw: raws[i]}
		if a.IBAN != "" {
			acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: "IBAN", Value: a.IBAN})
		}
		if a.MaskedPan != "" {
			acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: "MASKED_PAN", Value: a.MaskedPan})
		}
		if ref.card {
			acc.Type = "CARD"
		}
		acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
		out = append(out, acc)
	}
	return out, nil
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session) ([]obsdk.Account, *resp, error) {
	res, err := c.aisCall(ctx, s, req{op: opAccounts, path: "/v4/accounts"})
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Accounts []json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("ing: unreadable accounts response: %w", err)
	}
	accs, err := toAccounts(body.Accounts)
	return accs, res, err
}

// Accounts lists the accounts the user granted access to.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, _ obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, res, err := c.listAccounts(ctx, s)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: res.body, Meta: meta(res.header)}, nil
}

func meta(h http.Header) obsdk.Meta { return obsdk.Meta{RequestID: h.Get("X-ING-Response-ID")} }

// ---- balances ----

type amountJSON struct {
	Amount   json.Number `json:"amount"` // a JSON number; kept as text so it stays exact
	Currency string      `json:"currency"`
}

type balanceJSON struct {
	Type               string     `json:"balanceType"`
	Amount             amountJSON `json:"balanceAmount"`
	LastChangeDateTime string     `json:"lastChangeDateTime"`
	ReferenceDate      string     `json:"referenceDate"`
}

func toMoney(a amountJSON) obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.Amount.String()), Currency: a.Currency}
}

func toBalance(b balanceJSON) obsdk.Balance {
	kind := obsdk.BalanceOther
	switch b.Type {
	case "interimBooked":
		kind = obsdk.BalanceInterimBooked
	case "interimAvailable":
		kind = obsdk.BalanceInterimAvailable
	case "closingBooked":
		kind = obsdk.BalanceClosingBooked
	}
	ref := b.ReferenceDate
	if ref == "" && len(b.LastChangeDateTime) >= 10 {
		ref = b.LastChangeDateTime[:10]
	}
	return obsdk.Balance{Kind: kind, BankType: b.Type, Amount: toMoney(b.Amount), ReferenceDate: ref}
}

// Balances returns an account's balances: every type ING has for it.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, _ obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	ref, err := parseAccountID(accountID)
	if err != nil {
		return nil, err
	}
	res, err := c.aisCall(ctx, s, req{op: opBalances, path: "/v4/accounts/" + url.PathEscape(ref.resourceID) + "/balances", query: ref.currencyQuery()})
	if err != nil {
		return nil, err
	}
	bals, err := parseBalances(res.body)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: bals, Raw: res.body, Meta: meta(res.header)}, nil
}

func parseBalances(body []byte) ([]obsdk.Balance, error) {
	var b struct {
		Balances []balanceJSON `json:"balances"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("ing: unreadable balances response: %w", err)
	}
	out := make([]obsdk.Balance, 0, len(b.Balances))
	for _, x := range b.Balances {
		out = append(out, toBalance(x))
	}
	return out, nil
}

// ---- transactions ----

type partyAccountJSON struct {
	IBAN string `json:"iban"`
	BBAN string `json:"bban"`
	BIC  string `json:"bic"`
}

type txJSON struct {
	TransactionID     string           `json:"transactionId"`
	EndToEndID        string           `json:"endToEndId"`
	BookingDate       string           `json:"bookingDate"`
	ValueDate         string           `json:"valueDate"`
	ExecutionDateTime string           `json:"executionDateTime"`
	Amount            amountJSON       `json:"transactionAmount"`
	CreditorName      string           `json:"creditorName"`
	CreditorAccount   partyAccountJSON `json:"creditorAccount"`
	DebtorName        string           `json:"debtorName"`
	DebtorAccount     partyAccountJSON `json:"debtorAccount"`
	TransactionType   string           `json:"transactionType"`
	Unstructured      string           `json:"remittanceInformationUnstructured"`
	Structured        *struct {
		ReferenceType string `json:"referenceType"`
		Reference     string `json:"reference"`
	} `json:"remittanceInformationStructured"`
}

func partyOf(name string, a partyAccountJSON) obsdk.Party {
	p := obsdk.Party{Name: name}
	if a.IBAN != "" {
		p.Identifiers = append(p.Identifiers, obsdk.Identifier{Scheme: "IBAN", Value: a.IBAN})
	}
	if a.BBAN != "" {
		p.Identifiers = append(p.Identifiers, obsdk.Identifier{Scheme: "BBAN", Value: a.BBAN})
	}
	return p
}

// remittanceLines splits ING's unstructured text, which uses <br> as a line break.
func remittanceLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "<br>") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func toTransaction(raw json.RawMessage, status obsdk.TxStatus) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{
		ID: t.TransactionID, Status: status, Amount: toMoney(t.Amount),
		BookingDate: t.BookingDate, ValueDate: t.ValueDate, BankCodeText: t.TransactionType,
		Remittance: remittanceLines(t.Unstructured), Raw: raw,
	}
	if len(t.ExecutionDateTime) >= 10 {
		tx.TransactionDate = t.ExecutionDateTime[:10]
	}
	if t.EndToEndID != "NOTPROVIDED" {
		tx.EndToEndID = t.EndToEndID
	}
	if t.Structured != nil {
		tx.ReferenceNumber = t.Structured.Reference
	}
	// Amounts are signed: negative leaves the account. The counterparty is the
	// creditor of outgoing and the debtor of incoming money.
	if strings.HasPrefix(string(tx.Amount.Amount), "-") {
		tx.Direction, tx.Counterparty = obsdk.Debit, partyOf(t.CreditorName, t.CreditorAccount)
	} else {
		tx.Direction, tx.Counterparty = obsdk.Credit, partyOf(t.DebtorName, t.DebtorAccount)
	}
	return tx, nil
}

type cardTxJSON struct {
	ID                 string     `json:"cardTransactionId"`
	TransactionDate    string     `json:"transactionDate"`
	BookingDate        string     `json:"bookingDate"`
	Amount             amountJSON `json:"transactionAmount"`
	TransactionDetails string     `json:"transactionDetails"`
}

func toCardTransaction(raw json.RawMessage, status obsdk.TxStatus) (obsdk.Transaction, error) {
	var t cardTxJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{
		ID: t.ID, Status: status, Amount: toMoney(t.Amount), BookingDate: t.BookingDate,
		TransactionDate: t.TransactionDate, Direction: obsdk.Credit, Raw: raw,
	}
	if strings.HasPrefix(string(tx.Amount.Amount), "-") {
		tx.Direction = obsdk.Debit
	}
	if t.TransactionDetails != "" {
		tx.Counterparty.Name = t.TransactionDetails
		tx.Remittance = []string{t.TransactionDetails}
	}
	return tx, nil
}

// parseTransactions reads both the account and the card account format.
// ING always returns every status; the ones not asked for are dropped.
func parseTransactions(body []byte, card bool, want []obsdk.TxStatus) (obsdk.TxPage, error) {
	type lists struct {
		Booked  []json.RawMessage `json:"booked"`
		Pending []json.RawMessage `json:"pending"`
		Info    []json.RawMessage `json:"info"`
		Links   struct {
			Next linkJSON `json:"next"`
		} `json:"_links"`
	}
	var b struct {
		Transactions     lists `json:"transactions"`
		CardTransactions lists `json:"cardTransactions"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, fmt.Errorf("ing: unreadable transactions response: %w", err)
	}
	l, conv := b.Transactions, toTransaction
	if card {
		l, conv = b.CardTransactions, toCardTransaction
	}
	booked, pending := wants(want)
	page := obsdk.TxPage{Raw: body, NextCursor: l.Links.Next.Href}
	add := func(raws []json.RawMessage, st obsdk.TxStatus) error {
		for _, r := range raws {
			t, err := conv(r, st)
			if err != nil {
				return fmt.Errorf("ing: unreadable transaction: %w", err)
			}
			page.Transactions = append(page.Transactions, t)
		}
		return nil
	}
	if booked {
		if err := add(l.Booked, obsdk.TxBooked); err != nil {
			return page, err
		}
	}
	if pending {
		if err := add(l.Pending, obsdk.TxPending); err != nil {
			return page, err
		}
		if err := add(l.Info, obsdk.TxPending); err != nil {
			return page, err
		}
	}
	return page, nil
}

func wants(st []obsdk.TxStatus) (booked, pending bool) {
	if len(st) == 0 {
		return true, false
	}
	for _, s := range st {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	return booked, pending
}

// dateTime formats a query time the way ING asks: UTC, fraction and Z. The
// fraction is always .000: sub-second bounds add nothing to a date filter.
func dateTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05.000Z")
}

// Transactions returns a page of transactions. The cursor is the bank's
// next link, followed as given.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	ref, err := parseAccountID(q.AccountID)
	if err != nil {
		return nil, err
	}
	r := req{op: opTransactions}
	if q.Cursor != "" {
		u, err := url.Parse(q.Cursor)
		if err != nil || u.IsAbs() || !strings.HasPrefix(u.Path, "/") || !strings.HasSuffix(u.Path, "/transactions") {
			return nil, fmt.Errorf("%w: cursor is not an ING next link", obsdk.ErrInvalidRequest)
		}
		r.path = q.Cursor
	} else {
		r.path = "/v4/accounts/" + url.PathEscape(ref.resourceID) + "/transactions"
		if ref.card {
			r.path = "/v2/card-accounts/" + url.PathEscape(ref.resourceID) + "/transactions"
		}
		r.query = url.Values{}
		if !q.From.IsZero() {
			r.query.Set("fromDateTime", dateTime(q.From))
		}
		if !q.To.IsZero() {
			r.query.Set("toDateTime", dateTime(q.To))
		}
		if ref.currency != "" {
			r.query.Set("currency", ref.currency)
		}
		size := q.PageSize
		if size <= 0 {
			size = 100 // ING's maximum; its default is 10
		}
		r.query.Set("limit", fmt.Sprint(size))
	}
	res, err := c.aisCall(ctx, s, r)
	if err != nil {
		return nil, err
	}
	page, err := parseTransactions(res.body, ref.card, q.Status)
	if err != nil {
		return nil, err
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res.header)}, nil
}
