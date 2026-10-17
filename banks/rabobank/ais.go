package rabobank

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const aisBase = "/payments/account-information/ais"

// maxPageSize is Rabobank's maximum (and default) number of transactions per page.
const maxPageSize = 500

// aisCall performs a signed account-information request with the user's token.
// The PSU's IP marks the call as user-initiated: without it, balances and
// transactions may be read four times a day per account.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext, r req) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" {
		return nil, &obsdk.ReauthError{Reason: "no_access_token"}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	r.method, r.bearer, r.header = http.MethodGet, s.AccessToken, psuHeader(psu)
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

func psuHeader(p *obsdk.PSUContext) map[string]string {
	if p == nil || p.IP == "" {
		return nil
	}
	return map[string]string{"PSU-IP-Address": p.IP}
}

func accountPath(id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return "", fmt.Errorf("%w: %q is not a Rabobank account id", obsdk.ErrInvalidRequest, id)
	}
	return aisBase + "/accounts/" + url.PathEscape(id), nil
}

func meta(h http.Header) obsdk.Meta { return obsdk.Meta{RequestID: h.Get("X-Request-ID")} }

// ---- accounts ----

type accountJSON struct {
	ResourceID string `json:"resourceId"`
	IBAN       string `json:"iban"`
	Currency   string `json:"currency"`
	OwnerName  string `json:"ownerName"`
	Status     string `json:"status"` // enabled, deleted, blocked
}

func toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, fmt.Errorf("rabobank: unreadable account: %w", err)
	}
	acc := obsdk.Account{ID: a.ResourceID, OwnerName: a.OwnerName, Currency: a.Currency, BIC: "RABONL2U", Raw: raw}
	if a.IBAN != "" {
		acc.Identifiers = []obsdk.Identifier{{Scheme: obsdk.SchemeIBAN, Value: a.IBAN}}
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	res, err := c.aisCall(ctx, s, psu, req{op: opAccounts, path: aisBase + "/accounts"})
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Accounts []json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("rabobank: unreadable accounts response: %w", err)
	}
	out := make([]obsdk.Account, 0, len(body.Accounts))
	for _, raw := range body.Accounts {
		a, err := toAccount(raw)
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

type amountJSON struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

func (a amountJSON) money() obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.Amount), Currency: a.Currency}
}

type balanceJSON struct {
	Type               string     `json:"balanceType"`
	Amount             amountJSON `json:"balanceAmount"`
	LastChangeDateTime string     `json:"lastChangeDateTime"`
	ReferenceDate      string     `json:"referenceDate"`
}

// toBalance maps Rabobank's two types. "expected" (booked plus pending
// items) has no normalized kind and stays "other" with its bank type.
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
	return obsdk.Balance{Kind: kind, BankType: b.Type, Amount: b.Amount.money(), ReferenceDate: ref}
}

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
		return nil, fmt.Errorf("rabobank: unreadable balances response: %w", err)
	}
	out := make([]obsdk.Balance, 0, len(body.Balances))
	for _, b := range body.Balances {
		out = append(out, toBalance(b))
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body, Meta: meta(res.header)}, nil
}

// ---- transactions ----

type partyAccountJSON struct {
	IBAN string `json:"iban"`
	BBAN string `json:"bban"`
}

type txJSON struct {
	EntryReference   string           `json:"entryReference"`
	EndToEndID       string           `json:"endToEndId"`
	BookingDate      string           `json:"bookingDate"`
	ValueDate        string           `json:"valueDate"`
	Amount           amountJSON       `json:"transactionAmount"`
	CreditorName     string           `json:"creditorName"`
	CreditorAccount  partyAccountJSON `json:"creditorAccount"`
	UltimateCreditor string           `json:"ultimateCreditor"`
	DebtorName       string           `json:"debtorName"`
	DebtorAccount    partyAccountJSON `json:"debtorAccount"`
	UltimateDebtor   string           `json:"ultimateDebtor"`
	Unstructured     string           `json:"remittanceInformationUnstructured"`
	Structured       string           `json:"remittanceInformationStructured"` // plain text at Rabobank, not an object
	DetailedType     string           `json:"raboDetailedTransactionType"`
	TypeName         string           `json:"raboTransactionTypeName"`
}

func partyOf(name, ultimate string, a partyAccountJSON) obsdk.Party {
	if name == "" {
		name = ultimate
	}
	p := obsdk.Party{Name: name}
	if a.IBAN != "" {
		p.Identifiers = append(p.Identifiers, obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: a.IBAN})
	}
	if a.BBAN != "" {
		p.Identifiers = append(p.Identifiers, obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: a.BBAN})
	}
	return p
}

func toTransaction(raw json.RawMessage, status obsdk.TxStatus) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	// entryReference is Rabobank's sequential, unique number per account and
	// the identifier its docs advise using.
	tx := obsdk.Transaction{
		ID: t.EntryReference, EntryReference: t.EntryReference, Status: status, Amount: t.Amount.money(),
		BookingDate: t.BookingDate, ValueDate: t.ValueDate, ReferenceNumber: t.Structured,
		BankCode: t.DetailedType, BankCodeText: t.TypeName, Raw: raw,
	}
	if s := strings.TrimSpace(t.Unstructured); s != "" {
		tx.Remittance = []string{s}
	}
	if t.EndToEndID != "NOTPROVIDED" {
		tx.EndToEndID = t.EndToEndID
	}
	// Amounts are signed: negative leaves the account. The counterparty is the
	// creditor of outgoing and the debtor of incoming money.
	if strings.HasPrefix(t.Amount.Amount, "-") {
		tx.Direction, tx.Counterparty = obsdk.Debit, partyOf(t.CreditorName, t.UltimateCreditor, t.CreditorAccount)
	} else {
		tx.Direction, tx.Counterparty = obsdk.Credit, partyOf(t.DebtorName, t.UltimateDebtor, t.DebtorAccount)
	}
	return tx, nil
}

func parseTransactions(body []byte) (obsdk.TxPage, error) {
	var b struct {
		Transactions struct {
			Booked  []json.RawMessage `json:"booked"`
			Pending []json.RawMessage `json:"pending"`
			Links   struct {
				Next struct {
					Href string `json:"href"`
				} `json:"next"`
			} `json:"_links"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, fmt.Errorf("rabobank: unreadable transactions response: %w", err)
	}
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: body, NextCursor: b.Transactions.Links.Next.Href}
	for _, l := range []struct {
		raws []json.RawMessage
		st   obsdk.TxStatus
	}{{b.Transactions.Booked, obsdk.TxBooked}, {b.Transactions.Pending, obsdk.TxPending}} {
		for _, r := range l.raws {
			t, err := toTransaction(r, l.st)
			if err != nil {
				return page, fmt.Errorf("rabobank: unreadable transaction: %w", err)
			}
			page.Transactions = append(page.Transactions, t)
		}
	}
	return page, nil
}

// checkStatuses: Rabobank documents bookingStatus pending and both, but
// answers 400 "Currently only bookingStatus booked is allowed" to them, so
// only booked transactions are read. Asking for pending alone is refused;
// asking for both returns the booked ones.
func checkStatuses(st []obsdk.TxStatus) error {
	for _, s := range st {
		if s == obsdk.TxBooked {
			return nil
		}
	}
	if len(st) == 0 {
		return nil
	}
	return fmt.Errorf("%w: Rabobank only returns booked transactions", obsdk.ErrUnsupported)
}

// dateTime formats a query bound in Zulu time, as Rabobank asks.
func dateTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Transactions returns a page of transactions. The cursor is the bank's next
// link; its query (nextPageToken and the original filters) is sent again to
// the account's transactions path.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	p, err := accountPath(q.AccountID)
	if err != nil {
		return nil, err
	}
	if err := checkStatuses(q.Status); err != nil {
		return nil, err
	}
	r := req{op: opTransactions, path: p + "/transactions"}
	if q.Cursor != "" {
		u, err := url.Parse(q.Cursor)
		if err != nil || u.Query().Get("nextPageToken") == "" {
			return nil, fmt.Errorf("%w: cursor is not a Rabobank next link", obsdk.ErrInvalidRequest)
		}
		r.query = u.Query()
	} else {
		// Without either bound Rabobank returns only yesterday; dateTo alone
		// covers the 90 days before it. dateFrom may be at most eight years
		// back (400 FORMAT_ERROR otherwise).
		to := q.To
		if to.IsZero() {
			to = c.now().Truncate(time.Second)
		}
		r.query = url.Values{"bookingStatus": {"booked"}, "dateTo": {dateTime(to)}}
		if !q.From.IsZero() {
			r.query.Set("dateFrom", dateTime(q.From))
		}
		if q.PageSize > 0 {
			r.query.Set("size", strconv.Itoa(min(q.PageSize, maxPageSize)))
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
	return &obsdk.TxResult{TxPage: page, Meta: meta(res.header)}, nil
}
