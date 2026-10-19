package berlingroup

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
// zero: the standard makes dateFrom mandatory for booked transactions.
const defaultHistoryDays = 90

// aisCall performs an account-information request under the session's
// consent, at the session's institution.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext, r req) (*resp, error) {
	c, err := c.forSession(s)
	if err != nil {
		return nil, err
	}
	cons, ok := s.Consents[consentKind]
	if !ok || cons.ID == "" {
		return nil, &obsdk.ReauthError{Reason: "no_consent", Consent: consentKind}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	h := psuHeaders(psu)
	delete(h, "PSU-ID") // AIS reads are made under the consent, without the login id
	h["Consent-ID"] = cons.ID
	if s.AccessToken != "" {
		h["Authorization"] = "Bearer " + s.AccessToken
	}
	for k, v := range r.header {
		h[k] = v
	}
	r.method, r.header = http.MethodGet, h
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 300 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

func accountPath(id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return "", fmt.Errorf("%w: %q is not an account id", obsdk.ErrInvalidRequest, id)
	}
	return "/v1/accounts/" + url.PathEscape(id), nil
}

// ---- shared shapes ----

type amountJSON struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"`
}

func (a amountJSON) money() obsdk.Money {
	return obsdk.Money{Amount: obsdk.Decimal(a.Amount), Currency: a.Currency}
}

// accountRefJSON is the standard's account reference.
type accountRefJSON struct {
	IBAN      string `json:"iban"`
	BBAN      string `json:"bban"`
	PAN       string `json:"pan"`
	MaskedPAN string `json:"maskedPan"`
	MSISDN    string `json:"msisdn"`
	Other     *struct {
		Identification string `json:"identification"`
		SchemeName     string `json:"schemeNameCode"`
	} `json:"other"`
	Currency string `json:"currency"`
}

func (a *accountRefJSON) identifiers() []obsdk.Identifier {
	if a == nil {
		return nil
	}
	var out []obsdk.Identifier
	add := func(scheme, v string) {
		if v != "" {
			out = append(out, obsdk.Identifier{Scheme: scheme, Value: v})
		}
	}
	add(obsdk.SchemeIBAN, a.IBAN)
	add(obsdk.SchemeBBAN, a.BBAN)
	add("MASKED_PAN", a.MaskedPAN)
	add("MSISDN", a.MSISDN)
	if a.Other != nil {
		add(firstNonEmpty(a.Other.SchemeName, "OTHER"), a.Other.Identification)
	}
	return out
}

type balanceJSON struct {
	Type          string     `json:"balanceType"`
	Amount        amountJSON `json:"balanceAmount"`
	ReferenceDate string     `json:"referenceDate"`
}

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
	return obsdk.Balance{Kind: kind, BankType: b.Type, Amount: b.Amount.money(), ReferenceDate: b.ReferenceDate}
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

// ---- accounts ----

type accountJSON struct {
	ResourceID      string        `json:"resourceId"`
	IBAN            string        `json:"iban"`
	BBAN            string        `json:"bban"`
	MSISDN          string        `json:"msisdn"`
	MaskedPAN       string        `json:"maskedPan"`
	Currency        string        `json:"currency"`
	OwnerName       string        `json:"ownerName"`
	Name            string        `json:"name"`
	DisplayName     string        `json:"displayName"`
	Product         string        `json:"product"`
	CashAccountType string        `json:"cashAccountType"`
	BIC             string        `json:"bic"`
	Usage           string        `json:"usage"`
	Balances        []balanceJSON `json:"balances"`
}

func toAccount(raw json.RawMessage) (obsdk.Account, error) {
	var a accountJSON
	if err := json.Unmarshal(raw, &a); err != nil {
		return obsdk.Account{}, fmt.Errorf("berlingroup: unreadable account: %w", err)
	}
	ref := accountRefJSON{IBAN: a.IBAN, BBAN: a.BBAN, MSISDN: a.MSISDN, MaskedPAN: a.MaskedPAN}
	acc := obsdk.Account{ID: a.ResourceID, Identifiers: ref.identifiers(), Name: firstNonEmpty(a.Name, a.DisplayName),
		OwnerName: a.OwnerName, Currency: a.Currency, Product: a.Product, Type: a.CashAccountType, Usage: a.Usage,
		BIC: a.BIC, Balances: toBalances(a.Balances), Raw: raw}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
}

func (c *client) listAccounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, *resp, error) {
	r := req{op: opAccounts, path: "/v1/accounts"}
	if c.p.Info.Has(obsdk.CapBalances) && !c.p.NoWithBalance {
		r.query = url.Values{"withBalance": {"true"}}
	}
	res, err := c.aisCall(ctx, s, psu, r)
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Accounts []json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, res, fmt.Errorf("berlingroup: unreadable accounts response: %w", err)
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
		return nil, fmt.Errorf("berlingroup: unreadable balances response: %w", err)
	}
	out := toBalances(body.Balances)
	if out == nil {
		out = []obsdk.Balance{}
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body, Meta: meta(res.header)}, nil
}

// ---- transactions ----

// remittanceStructured is a string before version 1.3.8 and an object
// {reference, referenceType, referenceIssuer} from then on.
type remittanceStructured struct{ Reference string }

func (r *remittanceStructured) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		r.Reference = s
		return nil
	}
	var o struct {
		Reference string `json:"reference"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	r.Reference = o.Reference
	return nil
}

type txJSON struct {
	TransactionID         string                 `json:"transactionId"`
	EntryReference        string                 `json:"entryReference"`
	EndToEndID            string                 `json:"endToEndId"`
	BookingDate           string                 `json:"bookingDate"`
	ValueDate             string                 `json:"valueDate"`
	TransactionDate       string                 `json:"transactionDate"`
	Amount                amountJSON             `json:"transactionAmount"`
	CreditDebitIndicator  string                 `json:"creditDebitIndicator"`
	CreditorName          string                 `json:"creditorName"`
	CreditorAccount       *accountRefJSON        `json:"creditorAccount"`
	DebtorName            string                 `json:"debtorName"`
	DebtorAccount         *accountRefJSON        `json:"debtorAccount"`
	Unstructured          string                 `json:"remittanceInformationUnstructured"`
	UnstructuredArray     []string               `json:"remittanceInformationUnstructuredArray"`
	Structured            *remittanceStructured  `json:"remittanceInformationStructured"`
	StructuredArray       []remittanceStructured `json:"remittanceInformationStructuredArray"`
	BankTransactionCode   string                 `json:"bankTransactionCode"`
	ProprietaryCode       string                 `json:"proprietaryBankTransactionCode"`
	AdditionalInformation string                 `json:"additionalInformation"`
	MerchantCategoryCode  string                 `json:"merchantCategoryCode"`
	BalanceAfter          *balanceJSON           `json:"balanceAfterTransaction"`
}

func partyOf(name string, a *accountRefJSON) obsdk.Party {
	return obsdk.Party{Name: name, Identifiers: a.identifiers()}
}

// own is the queried account's IBAN, when the response names it.
func toTransaction(raw json.RawMessage, status obsdk.TxStatus, own string) (obsdk.Transaction, error) {
	var t txJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	tx := obsdk.Transaction{
		ID: t.TransactionID, EntryReference: t.EntryReference, EndToEndID: t.EndToEndID, Status: status,
		Amount: t.Amount.money(), BookingDate: t.BookingDate, ValueDate: t.ValueDate, TransactionDate: t.TransactionDate,
		BankCode: firstNonEmpty(t.BankTransactionCode, t.ProprietaryCode), MerchantCategory: t.MerchantCategoryCode, Raw: raw,
	}
	if t.BankTransactionCode != "" && t.ProprietaryCode != "" && t.ProprietaryCode != t.BankTransactionCode {
		tx.BankCodeText = t.ProprietaryCode
	}
	if t.EndToEndID == "NOTPROVIDED" {
		tx.EndToEndID = ""
	}
	// Amounts are signed (negative leaves the account). A debit indicator on
	// an unsigned amount, which some banks send, makes it negative.
	debit := strings.HasPrefix(t.Amount.Amount, "-")
	if !debit && t.Amount.Amount != "" && (t.CreditDebitIndicator == "DBIT" || t.CreditDebitIndicator == "" && sentFrom(t, own)) {
		debit, tx.Amount.Amount = true, obsdk.Decimal("-"+t.Amount.Amount)
	}
	if debit {
		tx.Direction, tx.Counterparty = obsdk.Debit, partyOf(t.CreditorName, t.CreditorAccount)
	} else {
		tx.Direction, tx.Counterparty = obsdk.Credit, partyOf(t.DebtorName, t.DebtorAccount)
	}
	seen := map[string]bool{}
	for _, l := range append([]string{t.Unstructured}, t.UnstructuredArray...) {
		if l = strings.TrimSpace(l); l != "" && !seen[l] {
			seen[l] = true
			tx.Remittance = append(tx.Remittance, l)
		}
	}
	if t.Structured != nil && t.Structured.Reference != "" {
		tx.ReferenceNumber = t.Structured.Reference
	} else if len(t.StructuredArray) > 0 {
		tx.ReferenceNumber = t.StructuredArray[0].Reference
	}
	if b := t.BalanceAfter; b != nil && b.Amount.Amount != "" {
		m := b.Amount.money()
		tx.BalanceAfter = &m
	}
	return tx, nil
}

// sentFrom tells whether an unsigned transaction without an indicator left
// the account: the account is its debtor and not also its creditor (Samlink
// reports pending payments that way).
func sentFrom(t txJSON, own string) bool {
	if own == "" || t.DebtorAccount == nil || !strings.EqualFold(t.DebtorAccount.IBAN, own) {
		return false
	}
	return t.CreditorAccount == nil || !strings.EqualFold(t.CreditorAccount.IBAN, own)
}

func parseTransactions(body []byte) (obsdk.TxPage, error) {
	var b struct {
		Account      accountRefJSON `json:"account"`
		Transactions struct {
			Booked  []json.RawMessage `json:"booked"`
			Pending []json.RawMessage `json:"pending"`
			Links   links             `json:"_links"`
		} `json:"transactions"`
		Links links `json:"_links"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, fmt.Errorf("berlingroup: unreadable transactions response: %w", err)
	}
	next := b.Transactions.Links["next"]
	if next == "" {
		next = b.Links["next"]
	}
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: body, NextCursor: string(next)}
	for _, group := range []struct {
		raws   []json.RawMessage
		status obsdk.TxStatus
	}{{b.Transactions.Booked, obsdk.TxBooked}, {b.Transactions.Pending, obsdk.TxPending}} {
		for _, r := range group.raws {
			t, err := toTransaction(r, group.status, b.Account.IBAN)
			if err != nil {
				return page, fmt.Errorf("berlingroup: unreadable transaction: %w", err)
			}
			page.Transactions = append(page.Transactions, t)
		}
	}
	return page, nil
}

// bookingStatus maps the requested statuses to the bookingStatus parameter.
func (c *client) bookingStatus(st []obsdk.TxStatus) (string, error) {
	booked, pending := len(st) == 0, false
	for _, s := range st {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	switch {
	case booked && pending && c.p.bookingStatus("both"):
		return "both", nil
	case booked && pending && !c.p.bookingStatus("pending"):
		// The bank has no pending transactions to report.
		return "booked", nil
	case booked && pending:
		return "", fmt.Errorf("%w: %s reports booked and pending transactions only separately; ask for one status at a time", obsdk.ErrUnsupported, c.p.Info.Name)
	case pending && !c.p.bookingStatus("pending"):
		return "", fmt.Errorf("%w: %s only reports booked transactions", obsdk.ErrUnsupported, c.p.Info.Name)
	case pending:
		return "pending", nil
	}
	return "booked", nil
}

// relevantEntryReference reads the entry reference a booked page continues
// from (Samlink: relevantEntryReference, spelled relevantEntryreference in its
// documentation); empty or null when there is no more.
func relevantEntryReference(body []byte) string {
	var b struct {
		A *string `json:"relevantEntryReference"`
		B *string `json:"relevantEntryreference"`
	}
	if json.Unmarshal(body, &b) != nil {
		return ""
	}
	for _, v := range []*string{b.A, b.B} {
		if v != nil && *v != "" {
			return *v
		}
	}
	return ""
}

// cursorRequest turns a next link back into a request, accepting only links
// to the queried account's transactions.
func cursorRequest(accountPath, cursor string, versions ...string) (req, error) {
	p, err := apiPath(cursor, versions...)
	if err != nil || !strings.HasPrefix(p, accountPath+"/transactions") {
		return req{}, fmt.Errorf("%w: cursor is not a next link of this account's transactions", obsdk.ErrInvalidRequest)
	}
	return req{op: opTransactions, path: p}, nil
}

// Transactions returns a page of transactions; the cursor is the bank's next
// link.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	p, err := accountPath(q.AccountID)
	if err != nil {
		return nil, err
	}
	var r req
	if q.Cursor != "" {
		if r, err = cursorRequest(p, q.Cursor, c.p.linkVersions()...); err != nil {
			return nil, err
		}
	} else {
		bs, err := c.bookingStatus(q.Status)
		if err != nil {
			return nil, err
		}
		from := q.From
		if from.IsZero() {
			from = c.now().AddDate(0, 0, -defaultHistoryDays)
		}
		r = req{op: opTransactions, path: p + "/transactions",
			query: url.Values{"bookingStatus": {bs}, "dateFrom": {from.Format("2006-01-02")}}}
		to := q.To
		if to.IsZero() && c.p.EntryReferencePaging {
			// Samlink reads a date range only when both ends are given.
			to = c.now()
		}
		if !to.IsZero() {
			r.query.Set("dateTo", to.Format("2006-01-02"))
		}
		if c.p.EntryReferencePaging && bs == "pending" {
			// Pending transactions come in one page, without date filtering.
			r.query.Del("dateFrom")
			r.query.Del("dateTo")
		}
	}
	if c.p.XMLTransactions {
		r.header = map[string]string{"Accept": "application/xml"}
	}
	res, err := c.aisCall(ctx, s, q.Options.PSU, r)
	if err != nil {
		return nil, err
	}
	var page obsdk.TxPage
	if isXML(res) {
		page, err = parseCamt(res.body)
	} else {
		page, err = parseTransactions(res.body)
	}
	if err != nil {
		return nil, err
	}
	if c.p.EntryReferencePaging && page.NextCursor == "" && len(page.Transactions) > 0 &&
		(r.query.Get("bookingStatus") == "booked" || strings.Contains(r.path, "bookingStatus=booked")) {
		if ref := relevantEntryReference(res.body); ref != "" {
			page.NextCursor = p + "/transactions?" + url.Values{"bookingStatus": {"booked"}, "entryReferenceFrom": {ref}}.Encode()
		}
	}
	if page.NextCursor != "" && page.NextCursor == q.Cursor {
		// A next link pointing at the page just read would loop forever.
		page.NextCursor = ""
	}
	return &obsdk.TxResult{TxPage: page, Meta: meta(res.header)}, nil
}
