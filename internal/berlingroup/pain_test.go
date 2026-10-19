package berlingroup

import (
	"errors"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

func painClient() *client {
	c := testClient(Profile{PaymentXML: true})
	n := 0
	c.cfg.NewID = func(string) string { n++; return "0b1e8a52-6d7c-4e1f-9a3b-00000000000" + string(rune('0'+n)) }
	c.cfg.Now = func() time.Time { return time.Date(2026, 10, 19, 22, 30, 0, 0, time.UTC) }
	return c
}

func painRequest(t obsdk.PaymentType) obsdk.PaymentRequest {
	return obsdk.PaymentRequest{Type: t,
		Debtor: &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE39499999600000005111"}},
		Transfers: []obsdk.Transfer{{
			Amount:     obsdk.Money{Amount: "12.30", Currency: "EUR"},
			Creditor:   obsdk.Creditor{Name: "Müller & Söhne", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "DE89370400440532013000"}},
			Remittance: []string{"Invoice <42>"},
		}}}
}

func TestBuildPain001(t *testing.T) {
	b, err := painClient().buildPain001(painRequest(obsdk.PaymentSEPA))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09"><CstmrCdtTrfInitn><GrpHdr><MsgId>0b1e8a526d7c4e1f9a3b000000000001</MsgId>`,
		`<CreDtTm>2026-10-19T22:30:00Z</CreDtTm><NbOfTxs>1</NbOfTxs><CtrlSum>12.30</CtrlSum><InitgPty><Nm>NOTPROVIDED</Nm></InitgPty>`,
		`<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl></PmtTpInf>`,
		// 22:30 UTC is already the next day in Berlin (summer time).
		`<ReqdExctnDt><Dt>2026-10-20</Dt></ReqdExctnDt>`,
		`<Dbtr><Nm>NOTPROVIDED</Nm></Dbtr><DbtrAcct><Id><IBAN>DE39499999600000005111</IBAN></Id></DbtrAcct>`,
		`<DbtrAgt><FinInstnId><Othr><Id>NOTPROVIDED</Id></Othr></FinInstnId></DbtrAgt><ChrgBr>SLEV</ChrgBr>`,
		`<PmtId><EndToEndId>NOTPROVIDED</EndToEndId></PmtId><Amt><InstdAmt Ccy="EUR">12.30</InstdAmt></Amt>`,
		`<Cdtr><Nm>Müller &amp; Söhne</Nm></Cdtr>`,
		`<RmtInf><Ustrd>Invoice &lt;42&gt;</Ustrd></RmtInf>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("pain.001 lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "LclInstrm") {
		t.Error("a SEPA credit transfer is marked instant")
	}
}

func TestBuildPain001Instant(t *testing.T) {
	r := painRequest(obsdk.PaymentSEPAInstant)
	r.Transfers[0].Remittance = nil
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}
	r.Transfers[0].Creditor.Agent = &obsdk.Agent{BIC: "COBADEFFXXX"}
	b, err := painClient().buildPain001(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl><LclInstrm><Cd>INST</Cd></LclInstrm></PmtTpInf>`,
		`<CdtrAgt><FinInstnId><BICFI>COBADEFFXXX</BICFI></FinInstnId></CdtrAgt>`,
		`<RmtInf><Strd><CdtrRefInf><Tp><CdOrPrtry><Cd>SCOR</Cd></CdOrPrtry><Issr>ISO</Issr></Tp><Ref>RF18539007547034</Ref></CdtrRefInf></Strd></RmtInf>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("pain.001 lacks %s:\n%s", want, got)
		}
	}
}

func TestBuildPain001NeedsDebtor(t *testing.T) {
	r := painRequest(obsdk.PaymentSEPA)
	r.Debtor = nil
	var ve *obsdk.PaymentValidationError
	if _, err := painClient().buildPain001(r); !errors.As(err, &ve) {
		t.Errorf("err = %v, want a PaymentValidationError", err)
	}
}

func TestCETDate(t *testing.T) {
	for in, want := range map[string]string{
		"2026-01-15T23:30:00Z": "2026-01-16", // CET: +1
		"2026-01-15T22:30:00Z": "2026-01-15",
		"2026-07-01T22:30:00Z": "2026-07-02", // CEST: +2
		"2026-03-29T00:59:00Z": "2026-03-29", // summer time starts 01:00 UTC on the last Sunday of March
		"2026-03-28T23:30:00Z": "2026-03-29",
		"2026-10-24T22:30:00Z": "2026-10-25", // still CEST on the Saturday night before it ends
		"2026-10-25T22:30:00Z": "2026-10-25", // CET again
	} {
		tm, _ := time.Parse(time.RFC3339, in)
		if got := cetDate(tm); got != want {
			t.Errorf("cetDate(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestParsePain002(t *testing.T) {
	cases := []struct{ body, status, reason string }{
		{`<?xml version="1.0"?><Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.002.001.10"><CstmrPmtStsRpt><GrpHdr><MsgId>1</MsgId></GrpHdr>
			<OrgnlGrpInfAndSts><OrgnlMsgId>x</OrgnlMsgId><GrpSts>ACSP</GrpSts></OrgnlGrpInfAndSts></CstmrPmtStsRpt></Document>`, "ACSP", ""},
		{`<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.002.001.03"><CstmrPmtStsRpt><OrgnlGrpInfAndSts><GrpSts>ACCP</GrpSts></OrgnlGrpInfAndSts>
			<OrgnlPmtInfAndSts><PmtInfSts>ACCT</PmtInfSts><TxInfAndSts><TxSts>RJCT</TxSts><StsRsnInf><Rsn><Cd>AM04</Cd></Rsn><AddtlInf>Insufficient funds</AddtlInf></StsRsnInf></TxInfAndSts></OrgnlPmtInfAndSts></CstmrPmtStsRpt></Document>`, "RJCT", "Insufficient funds"},
		{`<Document><CstmrPmtStsRpt><OrgnlGrpInfAndSts><GrpSts>RJCT</GrpSts><StsRsnInf><Rsn><Cd>AC04</Cd></Rsn></StsRsnInf></OrgnlGrpInfAndSts></CstmrPmtStsRpt></Document>`, "RJCT", "AC04"},
	}
	for _, c := range cases {
		st, rsn, err := parsePain002([]byte(c.body))
		if err != nil || st != c.status || rsn != c.reason {
			t.Errorf("parsePain002 = %q, %q, %v; want %q, %q", st, rsn, err, c.status, c.reason)
		}
	}
	if _, _, err := parsePain002([]byte(`<Document><CstmrPmtStsRpt/></Document>`)); err == nil {
		t.Error("a report without a status was accepted")
	}
}

func TestIntegrationChecksPainProducts(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a JSON payment product was accepted for pain.001 bodies")
		}
	}()
	Integration(Profile{ID: "x", BaseURL: func(obsdk.Env, obsdk.Target, string) string { return "https://x" }, PaymentXML: true,
		Products: map[obsdk.PaymentType]string{obsdk.PaymentSEPA: "sepa-credit-transfers"},
		Info:     obsdk.Info{Bank: "x", Payments: []obsdk.PaymentSpec{{Type: obsdk.PaymentSEPA}}}})
}
