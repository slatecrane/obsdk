package cbs

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

func TestAmount(t *testing.T) {
	for _, tc := range []struct {
		n, ind, want string
		dir          obsdk.Direction
	}{
		{"443.95", "CRDT", "443.95", obsdk.Credit},
		{"0.59", "DBIT", "-0.59", obsdk.Debit},
		{"250", "DBIT", "-250", obsdk.Debit},
		{"-2.5", "", "-2.5", obsdk.Debit},
		{"1E+2", "CRDT", "100.00", obsdk.Credit},
	} {
		got, dir := Amount(json.Number(tc.n), tc.ind)
		if string(got) != tc.want || dir != tc.dir {
			t.Errorf("Amount(%s, %s) = %s %s, want %s %s", tc.n, tc.ind, got, dir, tc.want, tc.dir)
		}
	}
}

func TestPageNext(t *testing.T) {
	n := func(i int) *int { return &i }
	for _, tc := range []struct {
		p    Page
		want int
		ok   bool
	}{
		{Page{PageNumber: 0, PageCount: 1, NextPage: n(0)}, 0, false}, // KB's last page of the account list
		{Page{PageNumber: 0, PageCount: 0}, 0, false},
		{Page{PageNumber: 5, PageCount: 7, NextPage: n(6)}, 6, true},
	} {
		got, ok := tc.p.Next()
		if got != tc.want || ok != tc.ok {
			t.Errorf("%+v: got %d %t", tc.p, got, ok)
		}
	}
}

// From KB's AIS manual (domestic payment, debit), with a variable symbol added.
const domesticTx = `{"entryReference":"357-12032019 1602 602033 935171","amount":{"value":1.23,"currency":"CZK"},
"creditDebitIndicator":"DBIT","status":"BOOK","bookingDate":{"date":"2019-03-12"},"valueDate":{"date":"2019-03-12"},
"bankTransactionCode":{"proprietary":{"code":10000101008,"issuer":"CBA"}},
"entryDetails":{"transactionDetails":{"references":{"accountServicerReference":"ZU000005UO8"},
"relatedParties":{"creditorAccount":{"identification":{"iban":"CZ3203000000000001111132"}}},
"relatedAgents":{"creditorAgent":{"financialInstitutionIdentification":{"bic":"CEKOCZPPXXX"}}},
"remittanceInformation":{"unstructured":"Poznámka pro příjemce","structured":{"creditorReferenceInformation":{"reference":["VS:3451859072","KS:0","SS:0"]}}},
"additionalTransactionInformation":"Platba na vrub vašeho účtu"}}}`

func TestToTransaction(t *testing.T) {
	tx, err := ToTransaction(json.RawMessage(domesticTx))
	if err != nil {
		t.Fatal(err)
	}
	if tx.Amount.Amount != "-1.23" || tx.Direction != obsdk.Debit || tx.Status != obsdk.TxBooked || tx.BookingDate != "2019-03-12" ||
		tx.BankCode != "10000101008" || tx.BankCodeText != "Platba na vrub vašeho účtu" || tx.ReferenceNumber != "3451859072" ||
		tx.ID != "357-12032019 1602 602033 935171" || len(tx.Remittance) != 1 ||
		len(tx.Counterparty.Identifiers) != 1 || tx.Counterparty.Identifiers[0].Value != "CZ3203000000000001111132" {
		t.Fatalf("got %+v", tx)
	}
	if VariableSymbol([]string{"VS:0", "KS:0"}) != "" {
		t.Fatal("a zero VS is no VS")
	}
}

// From ČS's sandbox: a credit with the counterparty's domestic number only
// and the bank transaction code as a float.
const csasCredit = `{"entryReference":"RB-1","amount":{"value":250.5,"currency":"CZK"},"creditDebitIndicator":"CRDT","status":"BOOK",
"bookingDate":{"date":"2017-01-31"},"valueDate":{"date":"2017-01-31"},
"bankTransactionCode":{"proprietary":{"code":10000101000.0,"issuer":"Czech Banking Association"}},
"entryDetails":{"transactionDetails":{"references":{"accountServicerReference":"0622510833568"},
"relatedParties":{"debtor":{"name":"Spokojený Jiří "},"debtorAccount":{"identification":{"other":{"identification":"000000-259459101/0800"}}}},
"remittanceInformation":{"unstructured":"faktura 12345","structured":{"creditorReferenceInformation":{"reference":["VS:123456","SS:879213546","KS:456789"]}}},
"additionalTransactionInformation":"Domácí platba - S24/IB"}}}`

func TestToTransactionCSAS(t *testing.T) {
	tx, err := ToTransaction(json.RawMessage(csasCredit))
	if err != nil {
		t.Fatal(err)
	}
	if tx.Amount.Amount != "250.5" || tx.Direction != obsdk.Credit || tx.BankCode != "10000101000" || tx.ReferenceNumber != "123456" ||
		tx.Counterparty.Name != "Spokojený Jiří" || len(tx.Counterparty.Identifiers) != 1 ||
		tx.Counterparty.Identifiers[0] != (obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "000000-259459101/0800"}) {
		t.Fatalf("got %+v", tx)
	}
	if bankCode("1.0000101E10") != "10000101000" || bankCode("12.5") != "12.5" || bankCode("7") != "7" {
		t.Fatal("bankCode writes integral codes as integers and keeps the rest")
	}
}

func TestToBalances(t *testing.T) {
	got, err := ToBalances([]byte(`{"balances":[{"type":{"codeOrProprietary":{"code":"CLAV"}},"amount":{"value":48923.15,"currency":"CZK"},
"creditDebitIndicator":"DBIT","date":{"dateTime":"2017-02-17T12:32:41.0Z"}},{"type":{"codeOrProprietary":{"code":"CLBD"}},
"amount":{"value":10,"currency":"CZK"},"creditDebitIndicator":"CRDT","date":{"date":"2017-02-16"}},
{"type":{"codeOrProprietary":{"code":"XPCD"}},"amount":{"value":1,"currency":"CZK"},"creditDebitIndicator":"CRDT","date":{}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Kind != obsdk.BalanceInterimAvailable || got[0].Amount.Amount != "-48923.15" || got[0].ReferenceDate != "2017-02-17" ||
		got[1].Kind != obsdk.BalanceClosingBooked || got[1].ReferenceDate != "2017-02-16" || got[2].Kind != obsdk.BalanceOther || got[2].BankType != "XPCD" {
		t.Fatalf("got %+v", got)
	}
}

func TestToAccount(t *testing.T) {
	a, err := ToAccount(json.RawMessage(`{"id":"AA19","identification":{"iban":"CZ1208000000000259459101","other":"0259459101/0800"},
"currency":"CZK","servicer":{"bankCode":"0800","countryCode":"CZ","bic":"GIBACZPX"},"nameI18N":"Jiří Spokojený",
"productI18N":"Osobní účet ČS II","ownersNames":["Jiří Spokojený"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "AA19" || a.BIC != "GIBACZPX" || a.OwnerName != "Jiří Spokojený" || len(a.Identifiers) != 2 || a.StableID == "" ||
		a.Identifiers[1] != (obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "0259459101/0800"}) {
		t.Fatalf("got %+v", a)
	}
}

func TestTxQueryAndPage(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	q, err := TxQuery(obsdk.TxQuery{From: from, PageSize: 50}, "Test bank")
	if err != nil || q.Get("fromDate") != "2026-09-01" || q.Get("size") != "50" || q.Has("toDate") {
		t.Fatalf("query %v %v", q, err)
	}
	if _, err := TxQuery(obsdk.TxQuery{Cursor: "fromDate=x"}, "Test bank"); err == nil || !strings.Contains(err.Error(), "Test bank") {
		t.Fatalf("bad cursor: %v", err)
	}
	pending := strings.Replace(domesticTx, `"BOOK"`, `"PDNG"`, 1)
	body := []byte(`{"pageNumber":0,"pageCount":2,"pageSize":2,"nextPage":1,"transactions":[` + domesticTx + `,` + pending + `]}`)
	pg, err := TxPage(body, q, nil)
	if err != nil || len(pg.Transactions) != 1 {
		t.Fatalf("booked only: %+v %v", pg.Transactions, err)
	}
	nq, _ := url.ParseQuery(pg.NextCursor)
	if nq.Get("page") != "1" || nq.Get("fromDate") != "2026-09-01" || q.Has("page") {
		t.Fatalf("cursor %q (request query %v)", pg.NextCursor, q)
	}
	pg, _ = TxPage(body, q, []obsdk.TxStatus{obsdk.TxPending})
	if len(pg.Transactions) != 1 || pg.Transactions[0].Status != obsdk.TxPending {
		t.Fatalf("pending only: %+v", pg.Transactions)
	}
}

func TestPaymentStatus(t *testing.T) {
	for code, want := range map[string]obsdk.PaymentStatus{
		"ACTC": obsdk.PaymentReceived, "RJCR": obsdk.PaymentRejected, "ACSP": obsdk.PaymentInProgress, "ACSC": obsdk.PaymentCompleted,
	} {
		if got, _ := PaymentStatus(code); got != want {
			t.Errorf("%s: got %s, want %s", code, got, want)
		}
	}
}

func TestParseError(t *testing.T) {
	for _, tc := range []struct{ body, code, text string }{
		{`{"errors":[{"code":"RR10","scope":"paymentIdentification.instructionIdentification","message":"Invalid charset"}]}`,
			"RR10", "paymentIdentification.instructionIdentification: Invalid charset"},
		{`{"status":403,"errors":[{"error":"TOKEN_MISSING"}]}`, "TOKEN_MISSING", ""},
		{`{"error":"request_error","error_description":"Parameter 'code' is invalid."}`, "request_error", "Parameter 'code' is invalid."},
		{`{"errorCode":"bad_request","errorText":"x"}`, "bad_request", "x"},
		{`<html>`, "", "<html>"},
	} {
		code, text := ParseError([]byte(tc.body))
		if code != tc.code || text != tc.text {
			t.Errorf("%s: got %q %q", tc.body, code, text)
		}
	}
}

func TestToStandingOrder(t *testing.T) {
	// ČS's list example: other as an object, maxIterations as a string.
	cs := `{"standingOrder":{"alias":"Rent","execution":{"mode":"UNTIL_DATE","modeDue":"DUE_DAY_OF_MONTH","interval":"MONTHLY","intervalDue":20},
"validity":{"lastExecutionDate":"2020-11-05T00:00:00.000Z"}},"standingOrderIdentification":{"transactionIdentification":"5408ee"},
"amount":{"instructedAmount":{"value":10050.15,"currency":"CZK"}},"requestedExecutionDate":"2020-04-20T00:00:00.000Z",
"debtorAccount":{"identification":{"iban":"CZ0827000000002108589434","other":{"identification":"000000-2108589434/0800"}},"currency":"CZK"},
"creditorAccount":{"identification":{"other":{"identification":"19-2000145399/0800"}}},
"remittanceInformation":{"structured":{"creditorReferenceInformation":{"reference":["VS:501","KS:9","SS:1005"]}},"unstructured":"Rent"}}`
	o, err := ToStandingOrder(json.RawMessage(cs))
	if err != nil {
		t.Fatal(err)
	}
	want := obsdk.Schedule{Frequency: obsdk.FrequencyMonthly, StartDate: "2020-04-20", EndDate: "2020-11-05"}
	if o.ID != "5408ee" || o.Name != "Rent" || o.Amount.Amount != "10050.15" || o.Amount.Currency != "CZK" || o.Schedule != want ||
		o.Interval != "MONTHLY" || o.Debtor == nil || o.Debtor.Value != "CZ0827000000002108589434" ||
		o.Creditor.Account != (obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "19-2000145399/0800"}) ||
		o.Reference == nil || o.Reference.Value != "501" || len(o.Remittance) != 1 {
		t.Fatalf("ČS: %+v", o)
	}

	// KB's shape: other as a string, maxIterations as a number, the account id.
	kb := `{"standingOrderIdentification":{"transactionIdentification":"SO1"},"amount":{"instructedAmount":{"value":250,"currency":"CZK"}},
"requestedExecutionDate":"2026-11-30","standingOrder":{"execution":{"mode":"AFTER_MAX_ITERATION_EXCEEDED","modeDue":"DUE_OR_NEXT_DAY_OF_MONTH","interval":"BI_WEEKLY"},
"validity":{"maxIterations":6}},"debtorAccount":{"id":"ACC1","identification":{"iban":"CZ6508000000192000145399"}},
"creditorAccount":{"identification":{"other":"123-456/0100"}}}`
	if o, err = ToStandingOrder(json.RawMessage(kb)); err != nil {
		t.Fatal(err)
	}
	want = obsdk.Schedule{Frequency: obsdk.FrequencyEveryTwoWeeks, StartDate: "2026-11-30", Count: 6, NonBusinessDay: obsdk.ScheduleFollowing}
	if o.Schedule != want || o.AccountID != "ACC1" || o.Creditor.Account.Value != "123-456/0100" || o.Reference != nil {
		t.Fatalf("KB: %+v", o)
	}

	// IRREGULAR has no Frequency; the bank's code stays in Interval.
	if o, _ = ToStandingOrder(json.RawMessage(`{"standingOrder":{"execution":{"mode":"UNTIL_CANCELLATION","modeDue":"DUE_LAST_DAY_OF_MONTH","interval":"IRREGULAR"}}}`)); o.Schedule.Frequency != "" || o.Interval != "IRREGULAR" || !o.Schedule.EndOfMonth {
		t.Fatalf("irregular: %+v", o)
	}
}

func TestStandingOrderPageCursor(t *testing.T) {
	body := []byte(`{"pageNumber":0,"pageCount":2,"nextPage":1,"standingOrders":[{"standingOrderIdentification":{"transactionIdentification":"A"}}]}`)
	q, _ := StandingOrderQuery(obsdk.StandingOrderQuery{PageSize: 5}, "X")
	pg, err := StandingOrderPage(body, q)
	if err != nil || len(pg.StandingOrders) != 1 || pg.NextCursor != "page=1&size=5" {
		t.Fatalf("%+v %v", pg, err)
	}
	if q, err = StandingOrderQuery(obsdk.StandingOrderQuery{Cursor: pg.NextCursor}, "X"); err != nil || q.Get("page") != "1" {
		t.Fatalf("cursor: %v %v", q, err)
	}
	if _, err := StandingOrderQuery(obsdk.StandingOrderQuery{Cursor: "garbage"}, "X"); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("bad cursor: %v", err)
	}
	last, _ := StandingOrderPage([]byte(`{"pageNumber":1,"pageCount":2,"nextPage":0,"standingOrders":[]}`), q)
	if last.NextCursor != "" {
		t.Fatalf("last page cursor %q", last.NextCursor)
	}
}

func TestPageNextWithoutNextPage(t *testing.T) {
	one := 1
	for _, tc := range []struct {
		p    Page
		want int
		ok   bool
	}{
		{Page{PageNumber: 0, PageCount: 5}, 1, true},                      // ČS's standing orders: no nextPage
		{Page{PageNumber: 4, PageCount: 5}, 0, false},                     // last page
		{Page{PageNumber: 0, NextPage: &one}, 1, true},                    // nextPage wins
		{Page{PageNumber: 1, PageCount: 3, NextPage: new(int)}, 0, false}, // nextPage 0 on the last page
	} {
		if n, ok := tc.p.Next(); n != tc.want || ok != tc.ok {
			t.Errorf("%+v: got %d %v", tc.p, n, ok)
		}
	}
}
