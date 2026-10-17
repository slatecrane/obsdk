package bunq

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
	"github.com/slatecrane/obsdk/internal/flowstate"
)

// maxCount is bunq's largest page (count) for listings; its default is 10.
const maxCount = 200

// amsterdam is the time zone bunq books in; dates are taken in it.
var amsterdam = func() *time.Location {
	if l, err := time.LoadLocation("Europe/Amsterdam"); err == nil {
		return l
	}
	return time.UTC
}()

// timeLayout is bunq's timestamp format, in UTC: "2026-10-17 09:22:40.452604".
const timeLayout = "2006-01-02 15:04:05.999999"

func parseTime(s string) (time.Time, bool) {
	t, err := time.ParseInLocation(timeLayout, s, time.UTC)
	return t, err == nil
}

func dateOf(s string) string {
	t, ok := parseTime(s)
	if !ok {
		return ""
	}
	return t.In(amsterdam).Format("2006-01-02")
}

// userCall performs a request with the user's session token.
func (c *client) userCall(ctx context.Context, s *obsdk.Session, r req) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" {
		return nil, &obsdk.ReauthError{Reason: "no_session_token"}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	r.auth = s.AccessToken
	if r.method == "" {
		r.method = http.MethodGet
	}
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

func userPath(s *obsdk.Session) string { return "/user/" + url.PathEscape(s.Meta[metaUserID]) }

func accountPath(s *obsdk.Session, id string) (string, error) {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return "", fmt.Errorf("%w: %q is not a bunq monetary account id", obsdk.ErrInvalidRequest, id)
	}
	return userPath(s) + "/monetary-account/" + id, nil
}

func meta(h http.Header) obsdk.Meta { return obsdk.Meta{RequestID: h.Get("X-Bunq-Client-Response-Id")} }

// ---- accounts ----

type amountJSON struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

func (a amountJSON) money() obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.Value), Currency: a.Currency}
}

type pointerJSON struct {
	Type  string `json:"type"` // IBAN, EMAIL, PHONE_NUMBER
	Value string `json:"value"`
	Name  string `json:"name"`
}

type accountJSON struct {
	ID          json.Number   `json:"id"`
	Created     string        `json:"created"`
	Updated     string        `json:"updated"`
	Description string        `json:"description"`
	Currency    string        `json:"currency"`
	DisplayName string        `json:"display_name"`
	Status      string        `json:"status"`
	Balance     *amountJSON   `json:"balance"`
	Overdraft   *amountJSON   `json:"overdraft_limit"`
	Alias       []pointerJSON `json:"alias"`
}

// accountTypes maps bunq's monetary account types to ISO 20022 cash
// account types. External accounts are other banks' accounts the user linked
// in bunq; they are listed like the rest.
var accountTypes = map[string]string{
	"MonetaryAccountBank": "CACC", "MonetaryAccountJoint": "CACC", "MonetaryAccountLight": "CACC", "MonetaryAccountCard": "CACC",
	"MonetaryAccountSavings": "SVGS", "MonetaryAccountExternalSavings": "SVGS", "MonetaryAccountSavingsExternal": "SVGS",
}

// accountObject returns the single typed object of a listing entry.
func accountObject(m map[string]json.RawMessage) (string, json.RawMessage) {
	for k, v := range m {
		if strings.HasPrefix(k, "MonetaryAccount") {
			return k, v
		}
	}
	return "", nil
}

func usage(s *obsdk.Session) string {
	t := s.Meta[metaUserType]
	if t == "UserApiKey" {
		t = s.Meta[metaGrantedBy]
	}
	switch t {
	case "UserPerson":
		return "PRIV"
	case "UserCompany":
		return "ORGA"
	}
	return ""
}

func toAccount(typ string, raw json.RawMessage, use string) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
		return obsdk.Account{}, fmt.Errorf("bunq: unreadable %s", typ)
	}
	acc := obsdk.Account{
		ID: a.ID.String(), Name: a.Description, OwnerName: a.DisplayName, Currency: a.Currency,
		Product: strings.TrimPrefix(typ, "MonetaryAccount"), Type: accountTypes[typ], Usage: use, Raw: raw,
	}
	for _, al := range a.Alias {
		if al.Type == "IBAN" && al.Value != "" {
			acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: al.Value})
		}
	}
	if !strings.Contains(typ, "External") {
		acc.BIC = bunqBIC
	}
	if o := a.Overdraft; o != nil && o.Value != "" {
		if r, ok := obsdk.Decimal(o.Value).Rat(); ok && r.Sign() != 0 {
			m := o.money()
			acc.CreditLimit = &m
		}
	}
	if b := toBalance(a.Balance, a.Updated); b != nil {
		acc.Balances = []obsdk.Balance{*b}
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

// toBalance: bunq gives one balance per account, the available balance now.
func toBalance(b *amountJSON, updated string) *obsdk.Balance {
	if b == nil || b.Value == "" {
		return nil
	}
	return &obsdk.Balance{Kind: obsdk.BalanceInterimAvailable, BankType: "balance", Amount: b.money(), ReferenceDate: dateOf(updated)}
}

// listAccounts reads every monetary account the access covers, following
// older_url until bunq reports no more.
func (c *client) listAccounts(ctx context.Context, s *obsdk.Session) ([]obsdk.Account, []json.RawMessage, error) {
	out := []obsdk.Account{}
	var raws []json.RawMessage
	r := req{op: opAccounts, path: userPath(s) + "/monetary-account", query: url.Values{"count": {strconv.Itoa(maxCount)}}}
	for page := 0; page < 50; page++ {
		res, err := c.userCall(ctx, s, r)
		if err != nil {
			return nil, nil, err
		}
		raws = append(raws, res.body)
		e, err := parseEnvelope(res.body)
		if err != nil {
			return nil, nil, err
		}
		for _, m := range e.Response {
			typ, raw := accountObject(m)
			if raw == nil {
				continue
			}
			a, err := toAccount(typ, raw, usage(s))
			if err != nil {
				return nil, nil, err
			}
			out = append(out, a)
		}
		if e.Pagination == nil || e.Pagination.OlderURL == "" {
			return out, raws, nil
		}
		if r.path, r.query, err = c.followPath(e.Pagination.OlderURL, userPath(s)+"/monetary-account"); err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("bunq: too many pages of accounts")
}

// followPath turns one of bunq's pagination URLs ("/v1/user/1/...?count=10&older_id=5")
// into a request path and query, refusing anything outside want.
func (c *client) followPath(link, want string) (string, url.Values, error) {
	u, err := url.Parse(link)
	if err != nil || u.Host != "" || u.Scheme != "" {
		return "", nil, fmt.Errorf("%w: not a bunq pagination link", obsdk.ErrInvalidRequest)
	}
	p := u.Path
	if base, err := url.Parse(c.api); err == nil {
		p = strings.TrimPrefix(p, strings.TrimRight(base.Path, "/"))
	}
	if p != want {
		return "", nil, fmt.Errorf("%w: pagination link %q is not for %s", obsdk.ErrInvalidRequest, u.Path, want)
	}
	return p, u.Query(), nil
}

// Accounts lists the accounts the user shared. Each carries its balance.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, _ obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, raws, err := c.listAccounts(ctx, s)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: joinRaw(raws)}, nil
}

// joinRaw returns one raw response as is and several as a JSON array.
func joinRaw(raws []json.RawMessage) json.RawMessage {
	if len(raws) == 1 {
		return raws[0]
	}
	b, _ := json.Marshal(raws)
	return b
}

// ---- balances ----

// Balances reads the account and returns its one balance.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, _ obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	p, err := accountPath(s, accountID)
	if err != nil {
		return nil, err
	}
	res, err := c.userCall(ctx, s, req{op: opBalances, path: p})
	if err != nil {
		return nil, err
	}
	e, err := parseEnvelope(res.body)
	if err != nil {
		return nil, err
	}
	out := []obsdk.Balance{}
	for _, m := range e.Response {
		if _, raw := accountObject(m); raw != nil {
			var a accountJSON
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, fmt.Errorf("bunq: unreadable account: %w", err)
			}
			if b := toBalance(a.Balance, a.Updated); b != nil {
				out = append(out, *b)
			}
			break
		}
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body, Meta: meta(res.header)}, nil
}

// ---- transactions ----

type labelJSON struct {
	IBAN               string `json:"iban"`
	DisplayName        string `json:"display_name"`
	SwiftBIC           string `json:"swift_bic"`
	MerchantCategory   string `json:"merchant_category_code"`
	SwiftAccountNumber string `json:"swift_account_number"`
}

type paymentJSON struct {
	ID                json.Number `json:"id"`
	Created           string      `json:"created"`
	Amount            amountJSON  `json:"amount"`
	Description       string      `json:"description"`
	Type              string      `json:"type"`     // BUNQ, EBA_SCT, EBA_SDD, IDEAL, SWIFT, MASTERCARD, ...
	SubType           string      `json:"sub_type"` // PAYMENT, WITHDRAWAL, REVERSAL, REQUEST, BILLING, SCT, SDD, NLO
	MerchantReference string      `json:"merchant_reference"`
	Counterparty      labelJSON   `json:"counterparty_alias"`
	BalanceAfter      *amountJSON `json:"balance_after_mutation"`
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, time.Time, error) {
	var p paymentJSON
	if err := json.Unmarshal(raw, &p); err != nil || p.ID == "" {
		return obsdk.Transaction{}, time.Time{}, fmt.Errorf("bunq: unreadable payment")
	}
	at, _ := parseTime(p.Created)
	d := dateOf(p.Created)
	tx := obsdk.Transaction{
		ID: p.ID.String(), Status: obsdk.TxBooked, Amount: p.Amount.money(), BookingDate: d, TransactionDate: d,
		ReferenceNumber: p.MerchantReference, BankCode: p.Type, BankCodeText: p.SubType,
		MerchantCategory: p.Counterparty.MerchantCategory, Raw: raw,
		Counterparty: obsdk.Party{Name: p.Counterparty.DisplayName},
	}
	if p.Counterparty.IBAN != "" {
		tx.Counterparty.Identifiers = []obsdk.Identifier{{Scheme: obsdk.SchemeIBAN, Value: p.Counterparty.IBAN}}
	}
	if s := strings.TrimSpace(p.Description); s != "" {
		tx.Remittance = []string{s}
	}
	if b := p.BalanceAfter; b != nil && b.Value != "" {
		m := b.money()
		tx.BalanceAfter = &m
	}
	// Amounts are signed relative to the account: negative left it.
	tx.Direction = obsdk.Credit
	if strings.HasPrefix(p.Amount.Value, "-") {
		tx.Direction = obsdk.Debit
	}
	return tx, at, nil
}

// txCursor is TxPage.NextCursor: bunq's older_url plus the date window, which
// bunq cannot filter on and the SDK applies to every page.
type txCursor struct {
	URL  string `json:"u"`
	From int64  `json:"f,omitempty"`
	To   int64  `json:"t,omitempty"`
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

// checkStatuses: bunq lists executed payments only. Asking for pending
// alone is refused; asking for both returns the booked ones.
func checkStatuses(st []obsdk.TxStatus) error {
	if len(st) == 0 {
		return nil
	}
	for _, s := range st {
		if s == obsdk.TxBooked {
			return nil
		}
	}
	return fmt.Errorf("%w: bunq only lists booked payments", obsdk.ErrUnsupported)
}

// Transactions returns one page of an account's payments, newest first.
// bunq has no date filter, so the SDK pages backwards and keeps what lies
// between From and To; a page can come back empty with a NextCursor while
// it walks past payments newer than To. Paging stops at the first payment
// older than From.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if err := checkStatuses(q.Status); err != nil {
		return nil, err
	}
	p, err := accountPath(s, q.AccountID)
	if err != nil {
		return nil, err
	}
	p += "/payment"
	r := req{op: opTransactions, path: p}
	from, to := q.From, q.To
	if q.Cursor != "" {
		var cur txCursor
		if err := flowstate.Decode(q.Cursor, &cur); err != nil || cur.URL == "" {
			return nil, fmt.Errorf("%w: not a bunq transactions cursor", obsdk.ErrInvalidRequest)
		}
		if r.path, r.query, err = c.followPath(cur.URL, p); err != nil {
			return nil, err
		}
		from, to = fromUnix(cur.From), fromUnix(cur.To)
	} else {
		count := maxCount
		if q.PageSize > 0 {
			count = min(q.PageSize, maxCount)
		}
		r.query = url.Values{"count": {strconv.Itoa(count)}}
	}
	res, err := c.userCall(ctx, s, r)
	if err != nil {
		return nil, err
	}
	e, err := parseEnvelope(res.body)
	if err != nil {
		return nil, err
	}
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: res.body}
	past := false
	for _, m := range e.Response {
		raw := m["Payment"]
		if raw == nil {
			continue
		}
		tx, at, err := toTransaction(raw)
		if err != nil {
			return nil, err
		}
		if !from.IsZero() && !at.IsZero() && at.Before(from) {
			past = true
			break
		}
		if !to.IsZero() && at.After(to) {
			continue
		}
		page.Transactions = append(page.Transactions, tx)
	}
	if !past && e.Pagination != nil && e.Pagination.OlderURL != "" {
		next, err := flowstate.Encode(txCursor{URL: e.Pagination.OlderURL, From: unix(from), To: unix(to)})
		if err != nil {
			return nil, err
		}
		page.NextCursor = next
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res.header)}, nil
}
