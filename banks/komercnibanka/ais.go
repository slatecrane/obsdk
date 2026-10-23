package komercnibanka

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const aisBase = "/aisp/v2/my/accounts"

// maxAccountPages bounds the account listing, in case a page number never
// advances.
const maxAccountPages = 50

// aisCall performs an account-information GET with the user's token.
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

// accountPath checks an account id. KB's ids are encrypted base64 and may
// hold "/" and "+", so they are escaped.
func accountPath(id string) (string, error) {
	if id == "" || len(id) > 120 {
		return "", fmt.Errorf("%w: %q is not a Komerční banka account id", obsdk.ErrInvalidRequest, id)
	}
	return aisBase + "/" + url.PathEscape(id), nil
}

// amount turns KB's amount (a JSON number, unsigned) and its
// creditDebitIndicator into a signed decimal. The number's text is kept as
// sent, so no precision is lost.
func amount(n json.Number, indicator string) (obsdk.Decimal, obsdk.Direction) {
	s := strings.TrimPrefix(n.String(), "-")
	if strings.ContainsAny(s, "eE") {
		if r, ok := new(big.Rat).SetString(s); ok {
			s = r.FloatString(2)
		}
	}
	if s == "" {
		s = "0"
	}
	if indicator == "DBIT" || (indicator == "" && strings.HasPrefix(n.String(), "-")) {
		return obsdk.Decimal("-" + s), obsdk.Debit
	}
	return obsdk.Decimal(s), obsdk.Credit
}

// page is KB's pagination envelope. nextPage is 0 (not absent) on the last
// page of the account list, so a next page exists only when it moves forward.
type page struct {
	PageNumber int  `json:"pageNumber"`
	PageCount  int  `json:"pageCount"`
	NextPage   *int `json:"nextPage"`
}

func (p page) next() (int, bool) {
	if p.NextPage == nil || *p.NextPage <= p.PageNumber {
		return 0, false
	}
	return *p.NextPage, true
}

// ---- accounts ----

type accountJSON struct {
	ID             string `json:"id"`
	Identification struct {
		IBAN  string `json:"iban"`
		Other string `json:"other"`
	} `json:"identification"`
	Currency string `json:"currency"`
	Servicer struct {
		BankCode string `json:"bankCode"`
		BIC      string `json:"bic"`
	} `json:"servicer"`
	Name        string   `json:"nameI18N"`
	Product     string   `json:"productI18N"`
	OwnersNames []string `json:"ownersNames"`
}

func toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, err
	}
	acc := obsdk.Account{ID: a.ID, Name: a.Name, Product: a.Product, Currency: a.Currency, BIC: a.Servicer.BIC,
		OwnerName: strings.Join(a.OwnersNames, ", "), Raw: raw}
	if a.Identification.IBAN != "" {
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: a.Identification.IBAN})
	}
	if a.Identification.Other != "" {
		// The domestic account number (prefix and number, without the bank code).
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: a.Identification.Other})
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

// accounts reads every page of the account list. user says the PSU is present.
func (c *client) accounts(ctx context.Context, s *obsdk.Session, user bool) ([]obsdk.Account, json.RawMessage, error) {
	out := []obsdk.Account{}
	var raws []json.RawMessage
	q := url.Values{}
	for i := 0; i < maxAccountPages; i++ {
		res, err := c.aisCall(ctx, s, req{op: opAccounts, path: aisBase, query: q, user: user})
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			page
			Accounts []json.RawMessage `json:"accounts"`
		}
		if err := json.Unmarshal(res.body, &b); err != nil {
			return nil, nil, fmt.Errorf("komercnibanka: unreadable account list: %w", err)
		}
		for _, r := range b.Accounts {
			a, err := toAccount(r)
			if err != nil {
				return nil, nil, fmt.Errorf("komercnibanka: unreadable account: %w", err)
			}
			out = append(out, a)
		}
		raws = append(raws, res.body)
		n, ok := b.next()
		if !ok {
			break
		}
		q = url.Values{"page": {strconv.Itoa(n)}}
	}
	if len(raws) == 1 {
		return out, raws[0], nil
	}
	raw, _ := json.Marshal(raws)
	return out, raw, nil
}

// Accounts lists the user's payment accounts, one entry per currency of a
// multi-currency account.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	accs, raw, err := c.accounts(ctx, s, o.PSU != nil)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: raw}, nil
}

// ---- balances ----

type balanceJSON struct {
	Type struct {
		CodeOrProprietary struct {
			Code string `json:"code"`
		} `json:"codeOrProprietary"`
	} `json:"type"`
	Amount struct {
		Value    json.Number `json:"value"`
		Currency string      `json:"currency"`
	} `json:"amount"`
	CreditDebitIndicator string `json:"creditDebitIndicator"`
	Date                 struct {
		Date     string `json:"date"`
		DateTime string `json:"dateTime"`
	} `json:"date"`
}

// balanceKinds maps KB's two balance types. KB calls PRCD (in ISO 20022
// "previously closed booked") the current balance and dates it now, so it is
// read as the booked balance of the moment.
var balanceKinds = map[string]obsdk.BalanceKind{
	"CLAV": obsdk.BalanceInterimAvailable,
	"PRCD": obsdk.BalanceInterimBooked,
}

// Balances returns the account's available (CLAV) and current (PRCD) balances.
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	p, err := accountPath(accountID)
	if err != nil {
		return nil, err
	}
	res, err := c.aisCall(ctx, s, req{op: opBalances, path: p + "/balance", user: o.PSU != nil})
	if err != nil {
		return nil, err
	}
	var b struct {
		Balances []balanceJSON `json:"balances"`
	}
	if err := json.Unmarshal(res.body, &b); err != nil {
		return nil, fmt.Errorf("komercnibanka: unreadable balances: %w", err)
	}
	out := []obsdk.Balance{}
	for _, x := range b.Balances {
		code := x.Type.CodeOrProprietary.Code
		kind, ok := balanceKinds[code]
		if !ok {
			kind = obsdk.BalanceOther
		}
		amt, _ := amount(x.Amount.Value, x.CreditDebitIndicator)
		bal := obsdk.Balance{Kind: kind, BankType: code, Amount: obsdk.Money{Amount: amt, Currency: x.Amount.Currency}}
		bal.ReferenceDate = dateOnly(x.Date.Date, x.Date.DateTime)
		out = append(out, bal)
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body}, nil
}

// dateOnly returns the first of the values that is set, cut to YYYY-MM-DD.
func dateOnly(vs ...string) string {
	for _, v := range vs {
		if len(v) >= 10 {
			return v[:10]
		}
	}
	return ""
}

// ---- transactions ----

type partyJSON struct {
	Name string `json:"name"`
}

type partyAccountJSON struct {
	Identification struct {
		IBAN  string `json:"iban"`
		Other struct {
			Identification string `json:"identification"`
		} `json:"other"`
	} `json:"identification"`
}

func (a *partyAccountJSON) identifiers() []obsdk.Identifier {
	if a == nil {
		return nil
	}
	if a.Identification.IBAN != "" {
		return []obsdk.Identifier{{Scheme: obsdk.SchemeIBAN, Value: a.Identification.IBAN}}
	}
	if o := a.Identification.Other.Identification; o != "" {
		return []obsdk.Identifier{{Scheme: obsdk.SchemeBBAN, Value: o}}
	}
	return nil
}

type transactionJSON struct {
	EntryReference string `json:"entryReference"`
	Amount         struct {
		Value    json.Number `json:"value"`
		Currency string      `json:"currency"`
	} `json:"amount"`
	CreditDebitIndicator string `json:"creditDebitIndicator"`
	Status               string `json:"status"`
	BookingDate          struct {
		Date string `json:"date"`
	} `json:"bookingDate"`
	ValueDate struct {
		Date string `json:"date"`
	} `json:"valueDate"`
	BankTransactionCode struct {
		Proprietary struct {
			Code json.Number `json:"code"`
		} `json:"proprietary"`
	} `json:"bankTransactionCode"`
	EntryDetails struct {
		TransactionDetails struct {
			References struct {
				AccountServicerReference string `json:"accountServicerReference"`
				EndToEndIdentification   string `json:"endToEndIdentification"`
			} `json:"references"`
			RelatedParties struct {
				Debtor          *partyJSON        `json:"debtor"`
				DebtorAccount   *partyAccountJSON `json:"debtorAccount"`
				Creditor        *partyJSON        `json:"creditor"`
				CreditorAccount *partyAccountJSON `json:"creditorAccount"`
			} `json:"relatedParties"`
			RemittanceInformation struct {
				Unstructured string `json:"unstructured"`
				Structured   struct {
					CreditorReferenceInformation struct {
						Reference []string `json:"reference"`
					} `json:"creditorReferenceInformation"`
				} `json:"structured"`
			} `json:"remittanceInformation"`
			AdditionalTransactionInformation string `json:"additionalTransactionInformation"`
		} `json:"transactionDetails"`
	} `json:"entryDetails"`
}

// variableSymbol returns the VS among the payment symbols ("VS:123"), unless
// it is empty or zero (KB fills missing symbols with 0).
func variableSymbol(refs []string) string {
	for _, r := range refs {
		v, ok := strings.CutPrefix(strings.TrimSpace(r), "VS:")
		if ok && strings.Trim(v, "0 ") != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func toTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t transactionJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	amt, dir := amount(t.Amount.Value, t.CreditDebitIndicator)
	d := t.EntryDetails.TransactionDetails
	tx := obsdk.Transaction{
		ID: t.EntryReference, EntryReference: t.EntryReference, Status: obsdk.TxBooked, Direction: dir,
		Amount:      obsdk.Money{Amount: amt, Currency: t.Amount.Currency},
		BookingDate: dateOnly(t.BookingDate.Date), ValueDate: dateOnly(t.ValueDate.Date),
		BankCode: t.BankTransactionCode.Proprietary.Code.String(), BankCodeText: d.AdditionalTransactionInformation,
		EndToEndID: d.References.EndToEndIdentification, ReferenceNumber: variableSymbol(d.RemittanceInformation.Structured.CreditorReferenceInformation.Reference),
		Raw: raw,
	}
	if t.Status == "PDNG" {
		// Card holds and other items not yet booked.
		tx.Status = obsdk.TxPending
	}
	if u := strings.TrimSpace(d.RemittanceInformation.Unstructured); u != "" {
		tx.Remittance = []string{u}
	}
	// The counterparty is the creditor of a debit and the debtor of a credit.
	party, acc := d.RelatedParties.Creditor, d.RelatedParties.CreditorAccount
	if dir == obsdk.Credit {
		party, acc = d.RelatedParties.Debtor, d.RelatedParties.DebtorAccount
	}
	if party != nil {
		tx.Counterparty.Name = strings.TrimSpace(party.Name)
	}
	tx.Counterparty.Identifiers = acc.identifiers()
	return tx, nil
}

// wantStatus says which of booked and pending items a query asked for.
func wantStatus(st []obsdk.TxStatus) (booked, pending bool) {
	for _, s := range st {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	if !booked && !pending {
		booked = true
	}
	return booked, pending
}

// Transactions returns a page of the account's history. KB lists booked and
// pending items (PDNG, e.g. card holds) together and has no filter for them,
// so items of a status not asked for are dropped from the page.
//
// The cursor is the query of the next request: KB's next page number plus
// the date filters and page size, which it wants repeated.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	p, err := accountPath(q.AccountID)
	if err != nil {
		return nil, err
	}
	var query url.Values
	if q.Cursor != "" {
		query, err = url.ParseQuery(q.Cursor)
		if err != nil || query.Get("page") == "" {
			return nil, fmt.Errorf("%w: cursor is not a Komerční banka transactions cursor", obsdk.ErrInvalidRequest)
		}
	} else {
		query = url.Values{}
		if !q.From.IsZero() {
			query.Set("fromDate", q.From.Format(time.DateOnly))
		}
		if !q.To.IsZero() {
			query.Set("toDate", q.To.Format(time.DateOnly))
		}
		if q.PageSize > 0 {
			query.Set("size", strconv.Itoa(q.PageSize))
		}
	}
	res, err := c.aisCall(ctx, s, req{op: opTransactions, path: p + "/transactions", query: query, user: q.Options.PSU != nil})
	if err != nil {
		return nil, err
	}
	var b struct {
		page
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := json.Unmarshal(res.body, &b); err != nil {
		return nil, fmt.Errorf("komercnibanka: unreadable transactions: %w", err)
	}
	booked, pending := wantStatus(q.Status)
	pg := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: res.body}
	for _, r := range b.Transactions {
		t, err := toTransaction(r)
		if err != nil {
			return nil, fmt.Errorf("komercnibanka: unreadable transaction: %w", err)
		}
		if (t.Status == obsdk.TxBooked && booked) || (t.Status == obsdk.TxPending && pending) {
			pg.Transactions = append(pg.Transactions, t)
		}
	}
	if n, ok := b.next(); ok {
		nq := url.Values{}
		for k, v := range query {
			nq[k] = v
		}
		nq.Set("page", strconv.Itoa(n))
		pg.NextCursor = nq.Encode()
	}
	return &obsdk.TxResult{TxPage: pg}, nil
}
