// Package cbs holds the data model of the Czech Banking Association's open
// banking standard (ČBS / ČOBS), which Czech banks implement with their own
// login, headers and payment signing: the account, balance and transaction
// resources, their pagination, payment status codes and error bodies.
//
// A bank package keeps its transport, OAuth2 login and payment flow, and
// uses this package to read the resources. See docs/komercnibanka.md and
// docs/ceskasporitelna.md for what each bank does differently.
package cbs

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/bgstatus"
)

// Amount turns a ČBS amount (a JSON number, unsigned) and its
// creditDebitIndicator into a signed decimal. The number's text is kept as
// sent, so no precision is lost.
func Amount(n json.Number, indicator string) (obsdk.Decimal, obsdk.Direction) {
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

// Page is the pagination envelope of the account and transaction lists.
// Pages count from 0. nextPage may be 0 (not absent) on the last page, so a
// next page exists only when it moves forward.
type Page struct {
	PageNumber int  `json:"pageNumber"`
	PageCount  int  `json:"pageCount"`
	NextPage   *int `json:"nextPage"`
}

// Next returns the next page number, if there is one.
func (p Page) Next() (int, bool) {
	if p.NextPage == nil || *p.NextPage <= p.PageNumber {
		return 0, false
	}
	return *p.NextPage, true
}

// DateOnly returns the first of the values that is set, cut to YYYY-MM-DD.
func DateOnly(vs ...string) string {
	for _, v := range vs {
		if len(v) >= 10 {
			return v[:10]
		}
	}
	return ""
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

// AccountList is one page of GET /my/accounts.
type AccountList struct {
	Page
	Accounts []json.RawMessage `json:"accounts"`
}

// ToAccount reads one entry of the account list.
func ToAccount(raw json.RawMessage) (obsdk.Account, error) {
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
		// The domestic account number as the bank writes it (KB: without
		// the bank code, ČS: "number/bank code").
		acc.Identifiers = append(acc.Identifiers, obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: a.Identification.Other})
	}
	acc.StableID = obsdk.StableAccountID(acc.Identifiers, a.Currency)
	return acc, nil
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

// balanceKinds maps the standard's balance types. KB calls PRCD (in ISO
// 20022 "previously closed booked") the current balance and dates it now, so
// it is read as the booked balance of the moment. CLBD is the closing booked
// balance (ČS).
var balanceKinds = map[string]obsdk.BalanceKind{
	"CLAV": obsdk.BalanceInterimAvailable,
	"PRCD": obsdk.BalanceInterimBooked,
	"CLBD": obsdk.BalanceClosingBooked,
}

// ToBalances reads the body of GET /my/accounts/{id}/balance.
func ToBalances(body []byte) ([]obsdk.Balance, error) {
	var b struct {
		Balances []balanceJSON `json:"balances"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, err
	}
	out := []obsdk.Balance{}
	for _, x := range b.Balances {
		code := x.Type.CodeOrProprietary.Code
		kind, ok := balanceKinds[code]
		if !ok {
			kind = obsdk.BalanceOther
		}
		amt, _ := Amount(x.Amount.Value, x.CreditDebitIndicator)
		bal := obsdk.Balance{Kind: kind, BankType: code, Amount: obsdk.Money{Amount: amt, Currency: x.Amount.Currency}}
		bal.ReferenceDate = DateOnly(x.Date.Date, x.Date.DateTime)
		out = append(out, bal)
	}
	return out, nil
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

// TransactionList is one page of GET /my/accounts/{id}/transactions.
type TransactionList struct {
	Page
	Transactions []json.RawMessage `json:"transactions"`
}

// VariableSymbol returns the VS among the payment symbols ("VS:123"),
// unless it is empty or zero (KB fills missing symbols with 0).
func VariableSymbol(refs []string) string {
	for _, r := range refs {
		v, ok := strings.CutPrefix(strings.TrimSpace(r), "VS:")
		if ok && strings.Trim(v, "0 ") != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// bankCode writes the bank transaction code as an integer. The standard's
// code is a number; ČS sends it as a float (1.0000101E10).
func bankCode(n json.Number) string {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		return s
	}
	if r, ok := new(big.Rat).SetString(s); ok && r.IsInt() {
		return r.Num().String()
	}
	return s
}

// ToTransaction reads one entry of the transaction history. BOOK is booked;
// PDNG (KB: card holds and other items not yet booked) is pending. Other
// statuses (ČS's INFO: entries that do not move the balance) are kept as
// booked, with the bank's status in Raw.
func ToTransaction(raw json.RawMessage) (obsdk.Transaction, error) {
	var t transactionJSON
	if err := json.Unmarshal(raw, &t); err != nil {
		return obsdk.Transaction{}, err
	}
	amt, dir := Amount(t.Amount.Value, t.CreditDebitIndicator)
	d := t.EntryDetails.TransactionDetails
	tx := obsdk.Transaction{
		ID: t.EntryReference, EntryReference: t.EntryReference, Status: obsdk.TxBooked, Direction: dir,
		Amount:      obsdk.Money{Amount: amt, Currency: t.Amount.Currency},
		BookingDate: DateOnly(t.BookingDate.Date), ValueDate: DateOnly(t.ValueDate.Date),
		BankCode: bankCode(t.BankTransactionCode.Proprietary.Code), BankCodeText: d.AdditionalTransactionInformation,
		EndToEndID: d.References.EndToEndIdentification, ReferenceNumber: VariableSymbol(d.RemittanceInformation.Structured.CreditorReferenceInformation.Reference),
		Raw: raw,
	}
	if t.Status == "PDNG" {
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

// WantStatus says which of booked and pending items a query asked for.
func WantStatus(st []obsdk.TxStatus) (booked, pending bool) {
	for _, s := range st {
		booked = booked || s == obsdk.TxBooked
		pending = pending || s == obsdk.TxPending
	}
	if !booked && !pending {
		booked = true
	}
	return booked, pending
}

// TxQuery returns the query of a transactions request. The cursor is the
// query of the next request (the bank's next page number plus the date
// filters and page size, which it wants repeated); bank names the bank in
// the error for a cursor that is not one.
func TxQuery(q obsdk.TxQuery, bank string) (url.Values, error) {
	if q.Cursor != "" {
		query, err := url.ParseQuery(q.Cursor)
		if err != nil || query.Get("page") == "" {
			return nil, fmt.Errorf("%w: cursor is not a %s transactions cursor", obsdk.ErrInvalidRequest, bank)
		}
		return query, nil
	}
	query := url.Values{}
	if !q.From.IsZero() {
		query.Set("fromDate", q.From.Format(time.DateOnly))
	}
	if !q.To.IsZero() {
		query.Set("toDate", q.To.Format(time.DateOnly))
	}
	if q.PageSize > 0 {
		query.Set("size", strconv.Itoa(q.PageSize))
	}
	return query, nil
}

// TxPage reads a page of the transaction history into a TxPage, dropping
// items of a status the query did not ask for (the standard lists booked
// and pending items together and has no filter), and sets the cursor of the
// next page from the request's query.
func TxPage(body []byte, query url.Values, status []obsdk.TxStatus) (obsdk.TxPage, error) {
	var b TransactionList
	if err := json.Unmarshal(body, &b); err != nil {
		return obsdk.TxPage{}, err
	}
	booked, pending := WantStatus(status)
	pg := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: body}
	for _, r := range b.Transactions {
		t, err := ToTransaction(r)
		if err != nil {
			return obsdk.TxPage{}, err
		}
		if (t.Status == obsdk.TxBooked && booked) || (t.Status == obsdk.TxPending && pending) {
			pg.Transactions = append(pg.Transactions, t)
		}
	}
	if n, ok := b.Next(); ok {
		nq := url.Values{}
		for k, v := range query {
			nq[k] = v
		}
		nq.Set("page", strconv.Itoa(n))
		pg.NextCursor = nq.Encode()
	}
	return pg, nil
}

// ---- payments ----

// PaymentStatus maps a payment's instructionStatus. ACTC is a payment the
// bank checked and stored that waits for the user's signature, so it counts
// as received. RJCR (refused at the signature) is not ISO 20022.
func PaymentStatus(code string) (obsdk.PaymentStatus, bool) {
	switch code {
	case "ACTC":
		return obsdk.PaymentReceived, false
	case "RJCR":
		return obsdk.PaymentRejected, true
	}
	return bgstatus.Payment(code)
}

// ---- errors ----

// errorBody covers the standard's errors: {"errors": [...]}, each with
// "error" or "code" (banks use both, sometimes for the same kind of
// problem), "scope" (the offending field) and "message". OAuth endpoints may
// answer the RFC 6749 form.
type errorBody struct {
	Errors []struct {
		Error   string `json:"error"`
		Code    string `json:"code"`
		Scope   string `json:"scope"`
		Message string `json:"message"`
	} `json:"errors"`
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
	// ČS's gateway: {"errorCode":"bad_request","errorText":"..."}.
	ErrorCode string `json:"errorCode"`
	ErrorText string `json:"errorText"`
}

// ParseError returns the bank's code and a readable text of an error body.
func ParseError(b []byte) (code, text string) {
	var e errorBody
	if json.Unmarshal(b, &e) != nil {
		return "", strings.TrimSpace(string(b[:min(len(b), 200)]))
	}
	switch {
	case len(e.Errors) > 0:
		first := e.Errors[0]
		code = first.Code
		if code == "" {
			code = first.Error
		}
		var parts []string
		for _, x := range e.Errors {
			p := x.Message
			if x.Scope != "" {
				p = strings.TrimSpace(x.Scope + ": " + p + " " + x.Error)
			}
			if p != "" {
				parts = append(parts, p)
			}
		}
		return code, strings.Join(parts, "; ")
	case e.Error != "":
		return e.Error, e.ErrorDesc
	case e.ErrorCode != "":
		return e.ErrorCode, e.ErrorText
	}
	return "", ""
}
