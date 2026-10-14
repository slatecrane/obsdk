package swedbank

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

const (
	kindAll      = "allAccounts"
	kindDetailed = "detailed"
	kindOver90   = "transactionsOver90Days"

	historyWindow = 90 * 24 * time.Hour
)

// aisCall performs an account-information request with the right headers and
// pre-flight checks. consentKind selects which consent id to send.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, consentKind string, r req, opts *obsdk.PSUContext) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	now := c.now()
	if s.AccessExpired(now) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	cons, ok := s.Consents[consentKind]
	if !ok {
		return nil, &obsdk.ReauthError{Reason: "no_" + consentKind + "_consent", Consent: consentKind}
	}
	if cons.ValidUntil != nil && !now.Before(*cons.ValidUntil) {
		return nil, &obsdk.ReauthError{Reason: "consent_expired", Consent: consentKind}
	}
	if r.header == nil {
		r.header = map[string]string{}
	}
	r.header["Authorization"] = bearer(s)
	r.header["Consent-ID"] = cons.ID
	psuHeaders(r.header, opts)
	r.ais = true
	if r.method == "" {
		r.method = http.MethodGet
	}
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

type accountJSON struct {
	ResourceID string        `json:"resourceId"`
	IBAN       string        `json:"iban"`
	BBAN       string        `json:"bban"`
	Name       string        `json:"name"`
	OwnerName  string        `json:"ownerName"`
	Currency   string        `json:"currency"`
	Product    string        `json:"product"`
	Type       string        `json:"cashAccountType"`
	BankID     string        `json:"bankId"`
	Balances   []balanceJSON `json:"balances"`
}

type amountJSON struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

type balanceJSON struct {
	Amount        amountJSON `json:"balanceAmount"`
	Type          string     `json:"balanceType"`
	ReferenceDate string     `json:"referenceDate"`
}

func toMoney(a amountJSON) obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.Amount), Currency: a.Currency}
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
	case "openingBooked":
		kind = obsdk.BalanceOpeningBooked
	}
	return obsdk.Balance{Kind: kind, BankType: b.Type, Amount: toMoney(b.Amount), ReferenceDate: b.ReferenceDate}
}

func toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{
		ID: a.ResourceID, Name: a.Name, OwnerName: a.OwnerName, Currency: a.Currency,
		Product: a.Product, Type: a.Type, Raw: raw,
	}
	if a.IBAN != "" {
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: "IBAN", Value: a.IBAN})
	}
	if a.BBAN != "" {
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: "BBAN", Value: a.BBAN})
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	for _, b := range a.Balances {
		acc.Balances = append(acc.Balances, toBalance(b))
	}
	return acc, nil
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, kind string, psu *obsdk.PSUContext) ([]obsdk.Account, json.RawMessage, *resp, error) {
	res, err := c.aisCall(ctx, s, kind, req{op: opAccounts, path: c.aisBase() + "/accounts", query: url.Values{"withBalance": {"false"}}}, psu)
	if err != nil {
		return nil, nil, nil, err
	}
	var body struct {
		Accounts []json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, nil, res, fmt.Errorf("swedbank: unreadable accounts response: %w", err)
	}
	out := make([]obsdk.Account, 0, len(body.Accounts))
	for _, raw := range body.Accounts {
		a, err := toAccount(raw)
		if err != nil {
			return nil, nil, res, fmt.Errorf("swedbank: unreadable account: %w", err)
		}
		out = append(out, a)
	}
	return out, res.body, res, nil
}

// Accounts lists the accounts covered by the session.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	kind := kindDetailed
	if s != nil {
		if _, ok := s.Consents[kindDetailed]; !ok {
			kind = kindAll
		}
	}
	accs, raw, res, err := c.listAccounts(ctx, s, kind, opts.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: raw, Meta: rateLimitMeta(res.header)}, nil
}

// Balances returns an account's balances.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if accountID == "" {
		return nil, fmt.Errorf("%w: account id required", obsdk.ErrInvalidRequest)
	}
	res, err := c.aisCall(ctx, s, kindDetailed, req{op: opBalances, path: c.aisBase() + "/accounts/" + url.PathEscape(accountID) + "/balances"}, opts.PSU)
	if err != nil {
		return nil, err
	}
	var body struct {
		Balances []balanceJSON `json:"balances"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, fmt.Errorf("swedbank: unreadable balances response: %w", err)
	}
	out := make([]obsdk.Balance, 0, len(body.Balances))
	for _, b := range body.Balances {
		out = append(out, toBalance(b))
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body, Meta: rateLimitMeta(res.header)}, nil
}

// ---- transactions ----

type partyAccountJSON struct {
	IBAN string `json:"iban"`
	BBAN string `json:"bban"`
}

type txJSON struct {
	TransactionID   string           `json:"transactionId"`
	BookingDate     string           `json:"bookingDate"`
	ValueDate       string           `json:"valueDate"`
	TransactionDate string           `json:"transactionDate"`
	Amount          amountJSON       `json:"transactionAmount"`
	CreditorName    string           `json:"creditorName"`
	CreditorAccount partyAccountJSON `json:"creditorAccount"`
	DebtorName      string           `json:"debtorName"`
	DebtorAccount   partyAccountJSON `json:"debtorAccount"`
	Unstructured    string           `json:"remittanceInformationUnstructured"`
	Structured      string           `json:"remittanceInformationStructured"`
	EndToEndID      string           `json:"endToEndId"`
	BankCode        string           `json:"bankTransactionCode"`
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

func toTransaction(raw json.RawMessage, status obsdk.TxStatus) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{
		ID: t.TransactionID, Status: status, Amount: toMoney(t.Amount),
		BookingDate: t.BookingDate, ValueDate: t.ValueDate, TransactionDate: t.TransactionDate,
		EndToEndID: t.EndToEndID, BankCode: t.BankCode, Raw: raw,
	}
	// Swedbank reports signed amounts: negative leaves the account. The
	// counterparty is the creditor of outgoing and the debtor of incoming money.
	if strings.HasPrefix(string(tx.Amount.Amount), "-") {
		tx.Direction, tx.Counterparty = obsdk.Debit, partyOf(t.CreditorName, t.CreditorAccount)
	} else {
		tx.Direction, tx.Counterparty = obsdk.Credit, partyOf(t.DebtorName, t.DebtorAccount)
	}
	if t.Unstructured != "" {
		tx.Remittance = append(tx.Remittance, t.Unstructured)
	}
	if t.Structured != "" {
		tx.Remittance = append(tx.Remittance, t.Structured)
	}
	return tx, nil
}

// parseTransactions reads a transactions body: {"transactions":{"booked":[..],"pending":[..]}, "_links":{"nextPage":..}}.
func parseTransactions(body []byte) (obsdk.TxPage, error) {
	var b struct {
		Links        map[string]link `json:"_links"`
		Transactions struct {
			Booked  []json.RawMessage `json:"booked"`
			Pending []json.RawMessage `json:"pending"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, fmt.Errorf("swedbank: unreadable transactions response: %w", err)
	}
	page := obsdk.TxPage{Raw: body}
	for _, r := range b.Transactions.Booked {
		t, err := toTransaction(r, obsdk.TxBooked)
		if err != nil {
			return page, err
		}
		page.Transactions = append(page.Transactions, t)
	}
	for _, r := range b.Transactions.Pending {
		t, err := toTransaction(r, obsdk.TxPending)
		if err != nil {
			return page, err
		}
		page.Transactions = append(page.Transactions, t)
	}
	if l, ok := b.Links["nextPage"]; ok && l.Href != "" {
		if u, err := url.Parse(l.Href); err == nil {
			page.NextCursor = u.Query().Get("pageId")
		}
	}
	return page, nil
}

func bookingStatus(st []obsdk.TxStatus) string {
	var booked, pending bool
	for _, s := range st {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	switch {
	case booked && pending:
		return "both"
	case pending:
		return "pending"
	default:
		return "booked"
	}
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Transactions returns a page of transactions. Requests reaching beyond 90
// days return a Step: the bank wants the user to approve extended history.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if q.AccountID == "" || q.From.IsZero() {
		return nil, fmt.Errorf("%w: AccountID and From are required", obsdk.ErrInvalidRequest)
	}
	to := q.To
	if to.IsZero() {
		to = c.now()
	}
	if q.From.Before(c.now().Add(-historyWindow)) {
		return c.startStatement(ctx, s, q, to)
	}
	query := url.Values{
		"dateFrom": {day(q.From)}, "dateTo": {day(to)},
		"bookingStatus": {bookingStatus(q.Status)}, "withBalance": {"false"},
	}
	size := q.PageSize
	if size <= 0 {
		size = 500 // always paginate so the bank answers online instead of switching to an offline statement
	}
	query.Set("pageSize", fmt.Sprint(size))
	if q.Cursor != "" {
		query.Set("pageId", q.Cursor)
	}
	res, err := c.aisCall(ctx, s, kindDetailed, req{
		op: opTransactions, path: c.aisBase() + "/accounts/" + url.PathEscape(q.AccountID) + "/transactions", query: query,
	}, q.Options.PSU)
	if err != nil {
		var np *notPostedError
		if asNotPosted(err, &np) {
			return c.startStatement(ctx, s, q, to)
		}
		return nil, err
	}
	meta := rateLimitMeta(res.header)
	if res.status == 210 {
		// The bank switched to its offline statement flow; the response carries download links.
		return c.statementFromLinks(ctx, s, q, res)
	}
	page, err := parseTransactions(res.body)
	if err != nil {
		return nil, err
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta}, nil
}

func asNotPosted(err error, target **notPostedError) bool {
	for err != nil {
		if e, ok := err.(*notPostedError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
