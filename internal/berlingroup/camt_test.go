package berlingroup

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	obsdk "github.com/slatecrane/obsdk"
)

// camt052v02 is a camt.052.001.02 report as German banks send it: ISO and
// proprietary (GVC) bank transaction codes, the name directly under Dbtr,
// a single-code Sts, a batch entry and an information entry.
const camt052v02 = `<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.052.001.02">
 <BkToCstmrAcctRpt>
  <GrpHdr><MsgId>052D2026-10-18</MsgId><CreDtTm>2026-10-18T08:00:00</CreDtTm></GrpHdr>
  <Rpt>
   <Id>1</Id>
   <Acct><Id><IBAN>DE86999999990000001000</IBAN></Id></Acct>
   <Ntry>
    <Amt Ccy="EUR">1250.00</Amt>
    <CdtDbtInd>CRDT</CdtDbtInd>
    <Sts>BOOK</Sts>
    <BookgDt><Dt>2026-10-16</Dt></BookgDt>
    <ValDt><Dt>2026-10-16</Dt></ValDt>
    <AcctSvcrRef>2026101612345</AcctSvcrRef>
    <BkTxCd>
     <Domn><Cd>PMNT</Cd><Fmly><Cd>RCDT</Cd><SubFmlyCd>ESCT</SubFmlyCd></Fmly></Domn>
     <Prtry><Cd>NTRF+166+9310</Cd><Issr>DK</Issr></Prtry>
    </BkTxCd>
    <NtryDtls><TxDtls>
     <Refs><EndToEndId>SALARY-2026-10</EndToEndId></Refs>
     <RltdPties>
      <Dbtr><Nm>Muster GmbH</Nm></Dbtr>
      <DbtrAcct><Id><IBAN>DE02120300000000202051</IBAN></Id></DbtrAcct>
      <Cdtr><Nm>Erika Mustermann</Nm></Cdtr>
     </RltdPties>
     <RmtInf><Ustrd>Gehalt Oktober</Ustrd><Ustrd>Personalnummer 4711</Ustrd></RmtInf>
    </TxDtls></NtryDtls>
    <AddtlNtryInf>GUTSCHR. UEBERWEISUNG</AddtlNtryInf>
   </Ntry>
   <Ntry>
    <Amt Ccy="EUR">42.50</Amt>
    <CdtDbtInd>DBIT</CdtDbtInd>
    <Sts>BOOK</Sts>
    <BookgDt><Dt>2026-10-17</Dt></BookgDt>
    <ValDt><Dt>2026-10-17</Dt></ValDt>
    <BkTxCd><Prtry><Cd>NDDT+105+9932</Cd></Prtry></BkTxCd>
    <NtryDtls><TxDtls>
     <Refs><EndToEndId>NOTPROVIDED</EndToEndId></Refs>
     <RltdPties>
      <Cdtr><Nm>Stadtwerke Musterstadt</Nm></Cdtr>
      <CdtrAcct><Id><IBAN>DE89370400440532013000</IBAN></Id></CdtrAcct>
     </RltdPties>
     <RmtInf><Strd><CdtrRefInf><Ref>RF18539007547034</Ref></CdtrRefInf></Strd></RmtInf>
    </TxDtls></NtryDtls>
    <AddtlNtryInf>FOLGELASTSCHRIFT</AddtlNtryInf>
   </Ntry>
   <Ntry>
    <Amt Ccy="EUR">300.00</Amt>
    <CdtDbtInd>DBIT</CdtDbtInd>
    <Sts>BOOK</Sts>
    <BookgDt><Dt>2026-10-17</Dt></BookgDt>
    <NtryDtls>
     <TxDtls><RmtInf><Ustrd>one</Ustrd></RmtInf></TxDtls>
     <TxDtls><RmtInf><Ustrd>two</Ustrd></RmtInf></TxDtls>
    </NtryDtls>
    <AddtlNtryInf>SAMMLER</AddtlNtryInf>
   </Ntry>
   <Ntry><Amt Ccy="EUR">1.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts>INFO</Sts></Ntry>
  </Rpt>
 </BkToCstmrAcctRpt>
</Document>`

// camt052v08 uses the version 08 shapes: Sts/Cd, Pty/Nm and a booking
// timestamp, for a pending card payment.
const camt052v08 = `<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.052.001.08"><BkToCstmrAcctRpt><Rpt>
 <Ntry><Amt Ccy="EUR">9.99</Amt><CdtDbtInd>DBIT</CdtDbtInd><Sts><Cd>PDNG</Cd></Sts>
  <BookgDt><DtTm>2026-10-18T07:30:00+02:00</DtTm></BookgDt>
  <NtryDtls><TxDtls><RltdPties><Cdtr><Pty><Nm>Bäckerei Krume</Nm></Pty></Cdtr></RltdPties></TxDtls></NtryDtls>
 </Ntry>
</Rpt></BkToCstmrAcctRpt></Document>`

func TestParseCamt(t *testing.T) {
	page, err := parseCamt([]byte(camt052v02))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Transactions) != 3 || page.NextCursor != "" {
		t.Fatalf("got %d transactions, cursor %q; want 3 and none (the INFO entry is left out)", len(page.Transactions), page.NextCursor)
	}
	in, out, batch := page.Transactions[0], page.Transactions[1], page.Transactions[2]

	if in.Amount != (obsdk.Money{Amount: "1250.00", Currency: "EUR"}) || in.Direction != obsdk.Credit || in.Status != obsdk.TxBooked {
		t.Errorf("credit: %+v", in)
	}
	if in.ID != "2026101612345" || in.EndToEndID != "SALARY-2026-10" || in.BookingDate != "2026-10-16" || in.ValueDate != "2026-10-16" {
		t.Errorf("credit references/dates: %+v", in)
	}
	if in.Counterparty.Name != "Muster GmbH" || len(in.Counterparty.Identifiers) != 1 || in.Counterparty.Identifiers[0].Value != "DE02120300000000202051" {
		t.Errorf("credit counterparty is the debtor: %+v", in.Counterparty)
	}
	if strings.Join(in.Remittance, "|") != "Gehalt Oktober|Personalnummer 4711" {
		t.Errorf("remittance lines: %q", in.Remittance)
	}
	if in.BankCode != "PMNT-RCDT-ESCT" || in.BankCodeText != "GUTSCHR. UEBERWEISUNG" {
		t.Errorf("bank code: %q / %q", in.BankCode, in.BankCodeText)
	}

	if out.Amount.Amount != "-42.50" || out.Direction != obsdk.Debit || out.EndToEndID != "" {
		t.Errorf("debit: amount %s, direction %s, e2e %q", out.Amount.Amount, out.Direction, out.EndToEndID)
	}
	if out.Counterparty.Name != "Stadtwerke Musterstadt" || out.ReferenceNumber != "RF18539007547034" || out.BankCode != "NDDT+105+9932" {
		t.Errorf("debit counterparty/reference/code: %+v", out)
	}

	if batch.Amount.Amount != "-300.00" || batch.Counterparty.Name != "" || batch.Remittance != nil || batch.BankCodeText != "SAMMLER" {
		t.Errorf("a batch entry keeps only entry-level data: %+v", batch)
	}

	var raw string
	if err := json.Unmarshal(in.Raw, &raw); err != nil || !strings.HasPrefix(raw, "<Ntry>") || !strings.HasSuffix(raw, "</Ntry>") {
		t.Errorf("Raw holds the entry's XML as a JSON string, got %s (%v)", in.Raw, err)
	}
	if err := json.Unmarshal(page.Raw, &raw); err != nil || !strings.Contains(raw, "BkToCstmrAcctRpt") {
		t.Errorf("page Raw holds the whole body as a JSON string")
	}
}

func TestParseCamtV08AndConcatenated(t *testing.T) {
	page, err := parseCamt([]byte(camt052v08 + "\n" + camt052v08))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Transactions) != 2 {
		t.Fatalf("concatenated documents: got %d transactions, want 2", len(page.Transactions))
	}
	tx := page.Transactions[0]
	if tx.Status != obsdk.TxPending || tx.BookingDate != "2026-10-18" || tx.Counterparty.Name != "Bäckerei Krume" || tx.Amount.Amount != "-9.99" {
		t.Errorf("v08 entry: %+v", tx)
	}
}

func TestParseCamtRefusesOtherXML(t *testing.T) {
	if _, err := parseCamt([]byte(`<html><body>maintenance</body></html>`)); err == nil {
		t.Error("an XML page that is not a camt report was accepted")
	}
	if _, err := parseCamt([]byte(`<Document><BkToCstmrAcctRpt><Ntry>`)); err == nil {
		t.Error("a truncated report was accepted")
	}
}

func TestIsXML(t *testing.T) {
	for _, c := range []struct {
		ct, body string
		want     bool
	}{
		{"application/xml;charset=UTF-8", `{}`, true},
		{"application/json", `<x/>`, false},
		{"", "\xef\xbb\xbf <?xml version=\"1.0\"?><Document/>", true},
		{"", `{"transactions":{}}`, false},
	} {
		r := &resp{header: http.Header{"Content-Type": {c.ct}}, body: []byte(c.body)}
		if got := isXML(r); got != c.want {
			t.Errorf("isXML(%q, %q) = %v", c.ct, c.body, got)
		}
	}
}
