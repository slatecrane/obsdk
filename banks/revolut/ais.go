package revolut

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

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
	res, err := c.do(ctx, req{op: op, method: http.MethodGet, path: path, query: query, bearer: s.AccessToken, psu: psu})
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(op, res)
	}
	return res, nil
}

type links struct {
	Self string `json:"Self"`
	Next string `json:"Next"`
}

type amountJSON struct {
	Amount   string `json:"Amount"`
	Currency string `json:"Currency"`
}

// signed applies the OBIE credit/debit indicator to an unsigned amount.
func signed(a amountJSON, indicator string) obsdk.Money {
	amt := a.Amount
	if indicator == "Debit" && amt != "" && !strings.HasPrefix(amt, "-") && !isZero(amt) {
		amt = "-" + amt
	}
	return obsdk.Money{Amount: obsdk.Decimal(amt), Currency: a.Currency}
}

func isZero(s string) bool { return strings.Trim(s, "0.") == "" }

// ---- accounts ----

type accountIDJSON struct {
	SchemeName              string `json:"SchemeName"`
	Identification          string `json:"Identification"`
	Name                    string `json:"Name"`
	SecondaryIdentification string `json:"SecondaryIdentification"`
}

type accountJSON struct {
	AccountID      string          `json:"AccountId"`
	Currency       string          `json:"Currency"`
	AccountType    string          `json:"AccountType"`
	AccountSubType string          `json:"AccountSubType"`
	Nickname       string          `json:"Nickname"`
	Account        []accountIDJSON `json:"Account"`
}

// scheme shortens OBIE scheme names: UK.OBIE.IBAN -> IBAN, UK.OBIE.SortCodeAccountNumber -> SortCodeAccountNumber.
// StableID is derived from this form, so it must not change.
func scheme(s string) string {
	if strings.HasPrefix(s, "UK.OBIE.") {
		return strings.TrimPrefix(s, "UK.OBIE.")
	}
	return s
}

var subTypes = map[string]string{"CurrentAccount": "CACC", "Savings": "SVGS", "CreditCard": "CARD"}
var usages = map[string]string{"Personal": "PRIV", "Business": "ORGA"}

// sdkScheme maps an OBIE scheme name to the SDK's identifier scheme.
func sdkScheme(s string) string {
	switch s {
	case "UK.OBIE.IBAN":
		return obsdk.SchemeIBAN
	case "UK.OBIE.SortCodeAccountNumber":
		return obsdk.SchemeSortCodeAccount
	}
	return scheme(s)
}

func toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{
		ID: a.AccountID, Name: a.Nickname, Currency: a.Currency, Product: a.AccountSubType,
		Type: subTypes[a.AccountSubType], Usage: usages[a.AccountType], Raw: raw,
	}
	for _, id := range a.Account {
		if id.Identification == "" {
			continue
		}
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: sdkScheme(id.SchemeName), Value: id.Identification})
		if acc.OwnerName == "" {
			acc.OwnerName = id.Name
		}
	}
	// Several currency accounts share one IBAN at Revolut, so the stable id
	// always includes the currency (StableAccountID would use the IBAN alone).
	for _, id := range a.Account {
		if id.Identification != "" {
			acc.StableID = obsdk.StableAccountID([]obsdk.Identifier{{Scheme: "revolut:" + scheme(id.SchemeName), Value: id.Identification}}, a.Currency)
			break
		}
	}
	return acc, nil
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	res, err := c.aisCall(ctx, s, opAccounts, "/accounts", nil, psu)
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Data struct {
			Account []json.RawMessage `json:"Account"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("revolut: unreadable accounts response: %w", err)
	}
	accs := []obsdk.Account{}
	for _, raw := range body.Data.Account {
		a, err := toAccount(raw)
		if err != nil {
			return nil, res, fmt.Errorf("revolut: unreadable account: %w", err)
		}
		accs = append(accs, a)
	}
	return accs, res, nil
}

// Accounts lists the accounts covered by the consent.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, res, err := c.listAccounts(ctx, s, opts.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: res.body, Meta: meta(res)}, nil
}

func meta(r *resp) obsdk.Meta { return obsdk.Meta{RequestID: r.header.Get("x-fapi-interaction-id")} }

// ---- balances ----

type balanceJSON struct {
	CreditDebitIndicator string     `json:"CreditDebitIndicator"`
	Type                 string     `json:"Type"`
	DateTime             string     `json:"DateTime"`
	Amount               amountJSON `json:"Amount"`
}

var balanceKinds = map[string]obsdk.BalanceKind{
	"OpeningBooked":    obsdk.BalanceOpeningBooked,
	"ClosingBooked":    obsdk.BalanceClosingBooked,
	"InterimBooked":    obsdk.BalanceInterimBooked,
	"InterimAvailable": obsdk.BalanceInterimAvailable,
}

func toBalance(b balanceJSON) obsdk.Balance {
	kind, ok := balanceKinds[b.Type]
	if !ok {
		kind = obsdk.BalanceOther
	}
	return obsdk.Balance{Kind: kind, BankType: b.Type, Amount: signed(b.Amount, b.CreditDebitIndicator), ReferenceDate: datePart(b.DateTime)}
}

// datePart returns YYYY-MM-DD from an ISO date-time as the bank wrote it
// (without converting time zones).
func datePart(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// Balances returns the balances of one account.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if accountID == "" {
		return nil, fmt.Errorf("%w: account id is required", obsdk.ErrInvalidRequest)
	}
	res, err := c.aisCall(ctx, s, opBalances, "/accounts/"+url.PathEscape(accountID)+"/balances", nil, opts.PSU)
	if err != nil {
		return nil, err
	}
	var body struct {
		Data struct {
			Balance []balanceJSON `json:"Balance"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, fmt.Errorf("revolut: unreadable balances response: %w", err)
	}
	out := []obsdk.Balance{}
	for _, b := range body.Data.Balance {
		out = append(out, toBalance(b))
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body, Meta: meta(res)}, nil
}

// ---- transactions ----

type txJSON struct {
	TransactionID          string     `json:"TransactionId"`
	CreditDebitIndicator   string     `json:"CreditDebitIndicator"`
	Status                 string     `json:"Status"`
	BookingDateTime        string     `json:"BookingDateTime"`
	ValueDateTime          string     `json:"ValueDateTime"`
	Amount                 amountJSON `json:"Amount"`
	TransactionInformation string     `json:"TransactionInformation"`
	ProprietaryCode        *struct {
		Code   string `json:"Code"`
		Issuer string `json:"Issuer"`
	} `json:"ProprietaryBankTransactionCode"`
	SupplementaryData *struct {
		StartedDate string `json:"StartedDate"`
	} `json:"SupplementaryData"`
	Balance *struct {
		CreditDebitIndicator string     `json:"CreditDebitIndicator"`
		Amount               amountJSON `json:"Amount"`
	} `json:"Balance"`
	MerchantDetails *struct {
		MerchantName         string `json:"MerchantName"`
		MerchantCategoryCode string `json:"MerchantCategoryCode"`
	} `json:"MerchantDetails"`
	CreditorAccount *accountIDJSON `json:"CreditorAccount"`
	DebtorAccount   *accountIDJSON `json:"DebtorAccount"`
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{
		ID: t.TransactionID, Status: obsdk.TxBooked, Direction: obsdk.Credit,
		Amount:      signed(t.Amount, t.CreditDebitIndicator),
		BookingDate: datePart(t.BookingDateTime), ValueDate: datePart(t.ValueDateTime), Raw: raw,
	}
	if t.Status == "Pending" {
		tx.Status = obsdk.TxPending
	}
	if t.CreditDebitIndicator == "Debit" {
		tx.Direction = obsdk.Debit
	}
	if t.SupplementaryData != nil {
		tx.TransactionDate = datePart(t.SupplementaryData.StartedDate)
	}
	if t.TransactionInformation != "" {
		tx.Remittance = []string{t.TransactionInformation}
	}
	if t.ProprietaryCode != nil {
		tx.BankCode = t.ProprietaryCode.Code
	}
	if t.Balance != nil {
		m := signed(t.Balance.Amount, t.Balance.CreditDebitIndicator)
		tx.BalanceAfter = &m
	}
	// The counterparty is the creditor of a debit and the debtor of a credit.
	other := t.CreditorAccount
	if tx.Direction == obsdk.Credit {
		other = t.DebtorAccount
	}
	if other != nil {
		tx.Counterparty.Name = other.Name
		if other.Identification != "" {
			tx.Counterparty.Identifiers = []obsdk.Identifier{{Scheme: scheme(other.SchemeName), Value: other.Identification}}
		}
	}
	if m := t.MerchantDetails; m != nil {
		if tx.Counterparty.Name == "" {
			tx.Counterparty.Name = m.MerchantName
		}
		tx.MerchantCategory = m.MerchantCategoryCode
	}
	return tx, nil
}

// statusFilter reports whether a transaction is wanted (empty means booked only).
func statusFilter(want []obsdk.TxStatus) func(obsdk.TxStatus) bool {
	if len(want) == 0 {
		want = []obsdk.TxStatus{obsdk.TxBooked}
	}
	return func(s obsdk.TxStatus) bool {
		for _, w := range want {
			if w == s {
				return true
			}
		}
		return false
	}
}

// cursor continues a transaction listing. Revolut pages backwards in time:
// the next page is requested with toBookingDateTime set to the oldest booking
// time of the current one. The filter is exclusive and only has second
// precision, so the cursor asks for one second more and skips the
// transactions it already returned from that second. Limit: if one second
// holds more transactions than a page, the rest of that second can't be
// requested and the listing moves on. A listing also ends with one or two
// requests that return nothing new; that is what proves it is complete.
type cursor struct {
	From string   `json:"f,omitempty"`
	To   string   `json:"t"`
	Skip []string `json:"s,omitempty"` // ids already returned with a booking time in [To-1s, To)
}

const (
	cursorPrefix = "rv1."
	isoSecond    = "2006-01-02T15:04:05Z"
)

func encodeCursor(cur cursor) string {
	b, _ := json.Marshal(cur)
	return cursorPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	var cur cursor
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, cursorPrefix))
	if err == nil {
		err = json.Unmarshal(b, &cur)
	}
	if err == nil && cur.To == "" {
		err = fmt.Errorf("no end time")
	}
	return cur, err
}

// txKey identifies a transaction for de-duplication across pages.
func txKey(t txJSON, raw json.RawMessage) string {
	if t.TransactionID != "" {
		return t.TransactionID
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// Transactions returns one page of transactions. The cursor is the bank's
// next link when it sends one, otherwise an opaque cursor built from the
// page (see cursor). The listing ends with a page that has nothing new.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if q.AccountID == "" {
		return nil, fmt.Errorf("%w: AccountID is required", obsdk.ErrInvalidRequest)
	}
	path := "/accounts/" + url.PathEscape(q.AccountID) + "/transactions"
	query := url.Values{}
	var cur cursor
	switch {
	case strings.HasPrefix(q.Cursor, cursorPrefix):
		var err error
		if cur, err = decodeCursor(q.Cursor); err != nil {
			return nil, fmt.Errorf("%w: invalid cursor: %v", obsdk.ErrInvalidRequest, err)
		}
		if cur.From != "" {
			query.Set("fromBookingDateTime", cur.From)
		}
		query.Set("toBookingDateTime", cur.To)
	case q.Cursor != "":
		u, err := url.Parse(q.Cursor)
		if err != nil || !u.IsAbs() || u.Scheme+"://"+u.Host != c.host {
			// Never send the access token to a host the cursor names.
			return nil, fmt.Errorf("%w: cursor is not a Revolut link", obsdk.ErrInvalidRequest)
		}
		path, query = q.Cursor, nil
	default:
		if !q.From.IsZero() {
			cur.From = q.From.UTC().Format(isoSecond)
			query.Set("fromBookingDateTime", cur.From)
		}
		if !q.To.IsZero() {
			query.Set("toBookingDateTime", q.To.UTC().Format(isoSecond))
		}
	}
	res, err := c.aisCall(ctx, s, opTransactions, path, query, q.Options.PSU)
	if err != nil {
		return nil, err
	}
	var body struct {
		Data struct {
			Transaction []json.RawMessage `json:"Transaction"`
		} `json:"Data"`
		Links links `json:"Links"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, fmt.Errorf("revolut: unreadable transactions response: %w", err)
	}
	skip := map[string]bool{}
	for _, id := range cur.Skip {
		skip[id] = true
	}
	keep := statusFilter(q.Status)
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: res.body}
	var oldest time.Time
	fresh := map[string]time.Time{} // new transactions by key, with their booking time
	for _, raw := range body.Data.Transaction {
		var t txJSON
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("revolut: unreadable transaction: %w", err)
		}
		key := txKey(t, raw)
		if skip[key] {
			continue
		}
		booked, err := time.Parse(time.RFC3339Nano, t.BookingDateTime)
		if err != nil {
			return nil, fmt.Errorf("revolut: transaction %s has an unreadable BookingDateTime %q", key, t.BookingDateTime)
		}
		fresh[key] = booked
		if oldest.IsZero() || booked.Before(oldest) {
			oldest = booked
		}
		tx, err := toTransaction(raw)
		if err != nil {
			return nil, fmt.Errorf("revolut: unreadable transaction: %w", err)
		}
		if keep(tx.Status) {
			page.Transactions = append(page.Transactions, tx)
		}
	}
	switch {
	case body.Links.Next != "":
		page.NextCursor = body.Links.Next
	case len(fresh) > 0:
		// Continue from the second the oldest new transaction is in, skipping
		// what this page and earlier pages already returned from that second.
		sec := oldest.UTC().Truncate(time.Second)
		next := cursor{From: cur.From, To: sec.Add(time.Second).Format(isoSecond)}
		if next.To == cur.To {
			next.Skip = append(next.Skip, cur.Skip...)
		}
		for key, booked := range fresh {
			if !booked.Before(sec) {
				next.Skip = append(next.Skip, key)
			}
		}
		sort.Strings(next.Skip)
		page.NextCursor = encodeCursor(next)
	case len(cur.Skip) > 0 && len(body.Data.Transaction) > 0:
		// Everything returned was already seen. Either the listing is done or
		// the bank's page is full of transactions from one second; any more
		// from that second can't be reached with a second-precision filter.
		// Move past it.
		to, err := time.Parse(isoSecond, cur.To)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid cursor: %v", obsdk.ErrInvalidRequest, err)
		}
		page.NextCursor = encodeCursor(cursor{From: cur.From, To: to.Add(-time.Second).Format(isoSecond)})
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res)}, nil
}
