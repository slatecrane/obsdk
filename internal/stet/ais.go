package stet

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// maxAccountPages bounds how many pages of the account list are read.
const maxAccountPages = 20

// aisCall performs an account-information request with the session's token.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, r req) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" {
		return nil, &obsdk.ReauthError{Reason: "no_access_token", Consent: consentKind}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	r.bearer = s.AccessToken
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

type link struct {
	Href string `json:"href"`
}

// resolveLink turns a HAL href into an absolute URL on the API's host.
// Hrefs may be absolute, absolute paths, or (as in STET's examples) paths
// without a leading slash, which are taken from the host root.
func (c *client) resolveLink(href string) (string, error) {
	if href == "" {
		return "", nil
	}
	u, err := url.Parse(href)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() {
		root, _ := url.Parse(c.origin() + "/")
		u = root.ResolveReference(u)
	}
	if u.Scheme+"://"+u.Host != c.origin() {
		// Never send the access token to a host a link names.
		return "", fmt.Errorf("%w: link %q is not on the bank's API host", obsdk.ErrInvalidRequest, href)
	}
	return u.String(), nil
}

// amountJSON is STET's AmountType. The amount is a JSON number in the
// specification and a string at some banks; both are kept as exact text.
type amountJSON struct {
	Amount   json.RawMessage `json:"amount"`
	Currency string          `json:"currency"`
}

func (a amountJSON) text() string {
	s := strings.Trim(strings.TrimSpace(string(a.Amount)), `"`)
	if strings.ContainsAny(s, "eE") {
		if r, ok := new(big.Rat).SetString(s); ok {
			s = r.FloatString(2)
		}
	}
	return s
}

func (a amountJSON) money() obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.text()), Currency: a.Currency}
}

// signed applies a credit/debit indicator to an amount the bank may or may
// not have signed itself.
func signed(a amountJSON, indicator string) obsdk.Money {
	amt := a.text()
	abs := strings.TrimPrefix(amt, "-")
	switch indicator {
	case "DBIT":
		if !isZero(abs) {
			amt = "-" + abs
		}
	case "CRDT":
		amt = abs
	}
	return obsdk.Money{Amount: obsdk.Decimal(amt), Currency: a.Currency}
}

func isZero(s string) bool { return strings.Trim(s, "0.") == "" }

// datePart returns YYYY-MM-DD from a date or date-time as the bank wrote it.
func datePart(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// ---- accounts ----

type genericID struct {
	Identification string `json:"identification"`
	SchemeName     string `json:"schemeName"`
}

type accountIDJSON struct {
	IBAN     string     `json:"iban"`
	Other    *genericID `json:"other"`
	Currency string     `json:"currency"`
}

func (a *accountIDJSON) identifiers() []obsdk.Identifier {
	if a == nil {
		return nil
	}
	var out []obsdk.Identifier
	if a.IBAN != "" {
		out = append(out, obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: a.IBAN})
	}
	if o := a.Other; o != nil && o.Identification != "" {
		out = append(out, obsdk.Identifier{Scheme: firstNonEmpty(o.SchemeName, "OTHER"), Value: o.Identification})
	}
	return out
}

type balanceJSON struct {
	Name               string     `json:"name"`
	Amount             amountJSON `json:"balanceAmount"`
	Type               string     `json:"balanceType"`
	ReferenceDate      string     `json:"referenceDate"`
	LastChangeDateTime string     `json:"lastChangeDateTime"`
}

type accountJSON struct {
	ResourceID      string         `json:"resourceId"`
	BIC             string         `json:"bicFi"`
	AccountID       *accountIDJSON `json:"accountId"`
	Name            string         `json:"name"`
	Usage           string         `json:"usage"`
	CashAccountType string         `json:"cashAccountType"`
	Product         string         `json:"product"`
	Balances        []balanceJSON  `json:"balances"`
}

func toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{
		ID: a.ResourceID, Identifiers: a.AccountID.identifiers(), Name: a.Name, Product: a.Product,
		Type: a.CashAccountType, Usage: a.Usage, BIC: a.BIC, Raw: raw,
	}
	if a.AccountID != nil {
		acc.Currency = a.AccountID.Currency
	}
	for _, b := range a.Balances {
		acc.Balances = append(acc.Balances, toBalance(b))
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, acc.Currency)
	return acc, nil
}

// listAccounts reads every page of GET /accounts. In STET's mixed consent
// model, accounts the user has not (yet) given access to come without a
// resourceId; they are returned too, with an empty ID.
func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	accs := []obsdk.Account{}
	var first *resp
	path := "/accounts"
	for page := 0; path != "" && page < maxAccountPages; page++ {
		res, err := c.aisCall(ctx, s, req{op: opAccounts, method: http.MethodGet, path: path, psu: psu})
		if err != nil {
			return nil, nil, err
		}
		if first == nil {
			first = res
		}
		if res.status == http.StatusNoContent || len(res.body) == 0 {
			break
		}
		var body struct {
			Accounts []json.RawMessage `json:"accounts"`
			Links    struct {
				Next link `json:"next"`
			} `json:"_links"`
		}
		if err := json.Unmarshal(res.body, &body); err != nil {
			return nil, res, fmt.Errorf("stet: unreadable accounts response: %w", err)
		}
		for _, raw := range body.Accounts {
			a, err := toAccount(raw)
			if err != nil {
				return nil, res, fmt.Errorf("stet: unreadable account: %w", err)
			}
			accs = append(accs, a)
		}
		if path, err = c.resolveLink(body.Links.Next.Href); err != nil {
			return nil, res, err
		}
	}
	return accs, first, nil
}

// usable keeps the accounts that can be read (they have a resource id).
func usable(accs []obsdk.Account) []obsdk.Account {
	out := []obsdk.Account{}
	for _, a := range accs {
		if a.ID != "" {
			out = append(out, a)
		}
	}
	return out
}

// Accounts lists the accounts the user gave access to.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	accs, res, err := c.listAccounts(ctx, s, opts.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: usable(accs), Raw: res.body, Meta: meta(res)}, nil
}

// forwardConsent tells the bank which accounts the user chose (STET's mixed
// model): every listed account, for balances and/or transactions as the
// capabilities ask. The session's consent records the accounts.
func (c *client) forwardConsent(ctx context.Context, s *obsdk.Session, accs []obsdk.Account, caps []obsdk.Capability, psu *obsdk.PSUContext) error {
	bal, tx := len(caps) == 0, len(caps) == 0
	for _, cp := range caps {
		switch cp {
		case obsdk.CapBalances:
			bal = true
		case obsdk.CapTransactions, obsdk.CapTransactionsHistory:
			tx = true
		}
	}
	ids := []json.RawMessage{}
	cons := s.Consents[consentKind]
	cons.Accounts = nil
	for _, a := range accs {
		var raw struct {
			AccountID json.RawMessage `json:"accountId"`
		}
		if json.Unmarshal(a.Raw, &raw) != nil || len(raw.AccountID) == 0 {
			continue
		}
		ids = append(ids, raw.AccountID)
		if len(a.Identifiers) > 0 {
			cons.Accounts = append(cons.Accounts, a.Identifiers[0].Value)
		}
	}
	none := []json.RawMessage{}
	access := map[string]any{"owners": none, "balances": none, "transactions": none, "psuIdentity": false, "trustedBeneficiaries": false}
	if bal {
		access["balances"] = ids
	}
	if tx {
		access["transactions"] = ids
	}
	if _, err := c.aisCall(ctx, s, req{op: opConsent, method: http.MethodPut, path: "/consents", body: access, psu: psu}); err != nil {
		return err
	}
	s.Consents[consentKind] = cons
	s.Touch(c.now())
	return nil
}

// ---- balances ----

var balanceKinds = map[string]obsdk.BalanceKind{
	"CLBD": obsdk.BalanceClosingBooked,
	"OPBD": obsdk.BalanceOpeningBooked,
	"ITBD": obsdk.BalanceInterimBooked,
	"ITAV": obsdk.BalanceInterimAvailable,
}

func toBalance(b balanceJSON) obsdk.Balance {
	kind, ok := balanceKinds[b.Type]
	if !ok {
		kind = obsdk.BalanceOther // XPCD (expected), VALU, PRCD, OTHR (cards)
	}
	return obsdk.Balance{Kind: kind, BankType: b.Type, Amount: b.Amount.money(),
		ReferenceDate: datePart(firstNonEmpty(b.ReferenceDate, b.LastChangeDateTime))}
}

// Balances returns the balances of one account.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, opts obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if accountID == "" {
		return nil, fmt.Errorf("%w: account id is required", obsdk.ErrInvalidRequest)
	}
	res, err := c.aisCall(ctx, s, req{op: opBalances, method: http.MethodGet, path: "/accounts/" + url.PathEscape(accountID) + "/balances", psu: opts.PSU})
	if err != nil {
		return nil, err
	}
	var body struct {
		Balances []balanceJSON `json:"balances"`
	}
	if len(res.body) > 0 {
		if err := json.Unmarshal(res.body, &body); err != nil {
			return nil, fmt.Errorf("stet: unreadable balances response: %w", err)
		}
	}
	out := []obsdk.Balance{}
	for _, b := range body.Balances {
		out = append(out, toBalance(b))
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body, Meta: meta(res)}, nil
}

// ---- transactions ----

type partyJSON struct {
	Name string `json:"name"`
}

type txJSON struct {
	ResourceID           string     `json:"resourceId"`
	EntryReference       string     `json:"entryReference"`
	Amount               amountJSON `json:"transactionAmount"`
	CreditDebitIndicator string     `json:"creditDebitIndicator"`
	Status               string     `json:"status"`
	EndToEndID           string     `json:"endToEndId"`
	BookingDate          string     `json:"bookingDate"`
	ValueDate            string     `json:"valueDate"`
	TransactionDate      string     `json:"transactionDate"`
	BankTransactionCode  *struct {
		Domain    string `json:"domain"`
		Family    string `json:"family"`
		SubFamily string `json:"subFamily"`
		Code      string `json:"code"`
	} `json:"bankTransactionCode"`
	RelatedParties *struct {
		Debtor          *partyJSON     `json:"debtor"`
		DebtorAccount   *accountIDJSON `json:"debtorAccount"`
		Creditor        *partyJSON     `json:"creditor"`
		CreditorAccount *accountIDJSON `json:"creditorAccount"`
	} `json:"relatedParties"`
	Remittance       json.RawMessage `json:"remittanceInformation"`
	AdditionalInfo   string          `json:"additionalTransactionInformation"`
	MerchantCategory string          `json:"merchantCategoryCode"`
}

// remittance reads remittanceInformation: an object with unstructured lines
// and structured references, or (STET before 1.4.2) a plain list of lines.
func remittance(raw json.RawMessage) (lines []string, reference string) {
	if len(raw) == 0 {
		return nil, ""
	}
	if json.Unmarshal(raw, &lines) == nil {
		return lines, ""
	}
	var r struct {
		Unstructured []string `json:"unstructured"`
		Structured   []struct {
			CreditorReference *struct {
				Reference string `json:"reference"`
			} `json:"creditorReferenceInformation"`
		} `json:"structured"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, ""
	}
	for _, s := range r.Structured {
		if s.CreditorReference != nil && s.CreditorReference.Reference != "" {
			reference = s.CreditorReference.Reference
			break
		}
	}
	return r.Unstructured, reference
}

// txStatus maps the entry status; ok is false for entries that are not
// money movements (INFO: announced standing orders and the like).
func txStatus(s string) (obsdk.TxStatus, bool) {
	switch s {
	case "BOOK":
		return obsdk.TxBooked, true
	case "PDNG", "FUTR":
		return obsdk.TxPending, true
	}
	return "", false
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
		ID: t.ResourceID, EntryReference: t.EntryReference, Status: status, Direction: obsdk.Credit,
		Amount:      signed(t.Amount, t.CreditDebitIndicator),
		BookingDate: datePart(t.BookingDate), ValueDate: datePart(t.ValueDate), TransactionDate: datePart(t.TransactionDate),
		EndToEndID: t.EndToEndID, MerchantCategory: t.MerchantCategory, Raw: raw,
	}
	if t.CreditDebitIndicator == "DBIT" || (t.CreditDebitIndicator == "" && strings.HasPrefix(string(tx.Amount.Amount), "-")) {
		tx.Direction = obsdk.Debit
	}
	tx.Remittance, tx.ReferenceNumber = remittance(t.Remittance)
	if t.AdditionalInfo != "" && len(tx.Remittance) == 0 {
		tx.Remittance = []string{t.AdditionalInfo}
	}
	if b := t.BankTransactionCode; b != nil {
		if b.Domain != "" || b.Family != "" {
			tx.BankCode = strings.Trim(b.Domain+"-"+b.Family+"-"+b.SubFamily, "-")
		} else {
			tx.BankCode = b.Code
		}
	}
	// The counterparty is the creditor of a debit and the debtor of a credit.
	if rp := t.RelatedParties; rp != nil {
		party, acc := rp.Creditor, rp.CreditorAccount
		if tx.Direction == obsdk.Credit {
			party, acc = rp.Debtor, rp.DebtorAccount
		}
		if party != nil {
			tx.Counterparty.Name = party.Name
		}
		tx.Counterparty.Identifiers = acc.identifiers()
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

func (c *client) dateQuery(t time.Time) string {
	if c.p.DateQuery != nil {
		return c.p.DateQuery(t)
	}
	return t.UTC().Format(time.RFC3339)
}

// dayStart is midnight UTC of t's calendar date.
func dayStart(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Transactions returns one page of transactions. From and To are calendar
// dates, both included (STET's dateTo is exclusive, so the day after To is
// sent). The cursor is the bank's next link.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if q.AccountID == "" {
		return nil, fmt.Errorf("%w: AccountID is required", obsdk.ErrInvalidRequest)
	}
	r := req{op: opTransactions, method: http.MethodGet, path: "/accounts/" + url.PathEscape(q.AccountID) + "/transactions", psu: q.Options.PSU}
	if q.Cursor != "" {
		next, err := c.resolveLink(q.Cursor)
		if err != nil {
			return nil, fmt.Errorf("%w: cursor is not a link of this bank", obsdk.ErrInvalidRequest)
		}
		r.path = next
	} else {
		r.query = url.Values{}
		if !q.From.IsZero() {
			r.query.Set("dateFrom", c.dateQuery(dayStart(q.From)))
		}
		if !q.To.IsZero() {
			r.query.Set("dateTo", c.dateQuery(dayStart(q.To).AddDate(0, 0, 1)))
		}
	}
	res, err := c.aisCall(ctx, s, r)
	if err != nil {
		return nil, err
	}
	var body struct {
		Transactions []json.RawMessage `json:"transactions"`
		Links        struct {
			Next link `json:"next"`
		} `json:"_links"`
	}
	if len(res.body) > 0 {
		if err := json.Unmarshal(res.body, &body); err != nil {
			return nil, fmt.Errorf("stet: unreadable transactions response: %w", err)
		}
	}
	next, err := c.resolveLink(body.Links.Next.Href)
	if err != nil {
		return nil, err
	}
	keep := statusFilter(q.Status)
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: res.body, NextCursor: next}
	for _, raw := range body.Transactions {
		tx, ok, err := toTransaction(raw)
		if err != nil {
			return nil, fmt.Errorf("stet: unreadable transaction: %w", err)
		}
		if ok && keep(tx.Status) {
			page.Transactions = append(page.Transactions, tx)
		}
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res)}, nil
}
