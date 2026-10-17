package hsbc

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

// The UK brands speak OBIE v4.0 (ISO 20022 codes: BOOK, ITAV, CACC...), HSBC
// Malta v3.1 (Booked, InterimAvailable, CurrentAccount...). The mappings
// below accept both.

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
	AccountID       string          `json:"AccountId"`
	Status          string          `json:"Status"`
	Currency        string          `json:"Currency"`
	AccountCategory string          `json:"AccountCategory"` // v4.0: Personal, Business
	AccountTypeCode string          `json:"AccountTypeCode"` // v4.0: CACC, SVGS, CARD, LOAN, MORT, CHAR
	AccountType     string          `json:"AccountType"`     // v3.1: Personal, Business
	AccountSubType  string          `json:"AccountSubType"`  // v3.1: CurrentAccount, Savings, ...
	Description     string          `json:"Description"`
	Nickname        string          `json:"Nickname"`
	Account         []accountIDJSON `json:"Account"`
}

// v31SubTypes maps v3.1 account sub-types to the v4.0 (ISO) codes.
var v31SubTypes = map[string]string{
	"CurrentAccount": "CACC", "Savings": "SVGS", "CreditCard": "CARD", "Loan": "LOAN", "Mortgage": "MORT", "ChargeCard": "CHAR",
}

var usages = map[string]string{"Personal": "PRIV", "Business": "ORGA"}

// sdkScheme maps an OBIE scheme name to the SDK's identifier scheme.
func sdkScheme(s string) string {
	switch s {
	case "UK.OBIE.IBAN":
		return obsdk.SchemeIBAN
	case "UK.OBIE.SortCodeAccountNumber":
		return obsdk.SchemeSortCodeAccount
	}
	return strings.TrimPrefix(s, "UK.OBIE.")
}

func toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	typ, product := a.AccountTypeCode, a.Description
	if typ == "" {
		typ = v31SubTypes[a.AccountSubType]
	}
	if product == "" {
		product = a.AccountSubType
	}
	cat := a.AccountCategory
	if cat == "" {
		cat = a.AccountType
	}
	acc := obsdk.Account{
		ID: a.AccountID, Name: a.Nickname, Currency: a.Currency, Product: product,
		Type: typ, Usage: usages[cat], Raw: raw,
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
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	res, err := c.aisCall(ctx, s, opAccounts, c.apiPath("aisp")+"/accounts", nil, psu)
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Data struct {
			Account []json.RawMessage `json:"Account"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("hsbc: unreadable accounts response: %w", err)
	}
	accs := []obsdk.Account{}
	for _, raw := range body.Data.Account {
		a, err := toAccount(raw)
		if err != nil {
			return nil, res, fmt.Errorf("hsbc: unreadable account: %w", err)
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
	"OPBD": obsdk.BalanceOpeningBooked, "OpeningBooked": obsdk.BalanceOpeningBooked,
	"CLBD": obsdk.BalanceClosingBooked, "ClosingBooked": obsdk.BalanceClosingBooked,
	"ITBD": obsdk.BalanceInterimBooked, "InterimBooked": obsdk.BalanceInterimBooked,
	"ITAV": obsdk.BalanceInterimAvailable, "InterimAvailable": obsdk.BalanceInterimAvailable,
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
	res, err := c.aisCall(ctx, s, opBalances, c.apiPath("aisp")+"/accounts/"+url.PathEscape(accountID)+"/balances", nil, opts.PSU)
	if err != nil {
		return nil, err
	}
	var body struct {
		Data struct {
			Balance []balanceJSON `json:"Balance"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, fmt.Errorf("hsbc: unreadable balances response: %w", err)
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
	TransactionReference   string     `json:"TransactionReference"`
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

// txStatus maps the entry status; ok is false for entries that are not
// money movements (RJCT: rejected, shown by the Global Money Account).
func txStatus(s string) (obsdk.TxStatus, bool) {
	switch s {
	case "BOOK", "Booked":
		return obsdk.TxBooked, true
	case "RJCT", "Rejected":
		return "", false
	}
	return obsdk.TxPending, true // PDNG, FUTR, INFO, Pending
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, bool, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, false, err
	}
	status, ok := txStatus(t.Status)
	if !ok {
		return obsdk.Transaction{}, false, nil
	}
	tx := obsdk.Transaction{
		ID: t.TransactionID, Status: status, Direction: obsdk.Credit,
		Amount:      signed(t.Amount, t.CreditDebitIndicator),
		BookingDate: datePart(t.BookingDateTime), ValueDate: datePart(t.ValueDateTime), Raw: raw,
	}
	if t.CreditDebitIndicator == "Debit" {
		tx.Direction = obsdk.Debit
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
			tx.Counterparty.Identifiers = []obsdk.Identifier{{Scheme: sdkScheme(other.SchemeName), Value: other.Identification}}
		}
	}
	if m := t.MerchantDetails; m != nil {
		if tx.Counterparty.Name == "" {
			tx.Counterparty.Name = m.MerchantName
		}
		tx.MerchantCategory = m.MerchantCategoryCode
	}
	return tx, true, nil
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

// bookingTime is the filter format. HSBC ignores the time: a range covers
// from 00:00:00 on the first day to 23:59:59 on the last.
const bookingTime = "2006-01-02T15:04:05"

// Transactions returns one page of transactions, most recent first. The
// cursor is the bank's next link (HSBC's page size varies; only the link
// says whether there is more).
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if q.AccountID == "" {
		return nil, fmt.Errorf("%w: AccountID is required", obsdk.ErrInvalidRequest)
	}
	path := c.apiPath("aisp") + "/accounts/" + url.PathEscape(q.AccountID) + "/transactions"
	query := url.Values{}
	if q.Cursor != "" {
		u, err := url.Parse(q.Cursor)
		if err != nil || !u.IsAbs() || u.Scheme+"://"+u.Host != c.host {
			// Never send the access token to a host the cursor names.
			return nil, fmt.Errorf("%w: cursor is not an HSBC link", obsdk.ErrInvalidRequest)
		}
		path, query = q.Cursor, nil
	} else {
		if !q.From.IsZero() {
			query.Set("fromBookingDateTime", q.From.UTC().Format(bookingTime))
		}
		if !q.To.IsZero() {
			query.Set("toBookingDateTime", q.To.UTC().Format(bookingTime))
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
		return nil, fmt.Errorf("hsbc: unreadable transactions response: %w", err)
	}
	keep := statusFilter(q.Status)
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: res.body, NextCursor: body.Links.Next}
	for _, raw := range body.Data.Transaction {
		tx, ok, err := toTransaction(raw)
		if err != nil {
			return nil, fmt.Errorf("hsbc: unreadable transaction: %w", err)
		}
		if ok && keep(tx.Status) {
			page.Transactions = append(page.Transactions, tx)
		}
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res)}, nil
}
