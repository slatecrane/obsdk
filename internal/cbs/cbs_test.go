package cbs

import (
	"encoding/json"
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
