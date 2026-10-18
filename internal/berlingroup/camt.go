package berlingroup

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
)

// Transactions in ISO 20022 camt.052 (camt.053 and camt.054 share the entry
// structure), which banks such as the Sparkassen send instead of JSON. Every
// Ntry element in the body becomes one transaction, whatever wraps it: one
// document, several concatenated ones, any message version. Element names are
// matched without namespaces, so camt.052.001.02 to .08 read the same.

// isXML tells an XML transactions body from a JSON one, by the content type
// or, without a usable one, by the first character.
func isXML(r *resp) bool {
	ct := strings.ToLower(r.header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "xml"):
		return true
	case strings.Contains(ct, "json"):
		return false
	}
	b := bytes.TrimLeft(bytes.TrimPrefix(r.body, []byte("\xef\xbb\xbf")), " \t\r\n")
	return len(b) > 0 && b[0] == '<'
}

type camtAmount struct {
	Currency string `xml:"Ccy,attr"`
	Value    string `xml:",chardata"`
}

// camtStatus is a plain code up to version 07 (<Sts>BOOK</Sts>) and a
// choice from version 08 on (<Sts><Cd>BOOK</Cd></Sts>).
type camtStatus struct {
	Text  string `xml:",chardata"`
	Code  string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

func (s camtStatus) code() string {
	return strings.TrimSpace(firstNonEmpty(s.Code, s.Prtry, s.Text))
}

type camtDate struct {
	Date     string `xml:"Dt"`
	DateTime string `xml:"DtTm"`
}

func (d camtDate) day() string {
	v := strings.TrimSpace(firstNonEmpty(d.Date, d.DateTime))
	if len(v) > 10 {
		v = v[:10]
	}
	return v
}

type camtBankTxCode struct {
	Domain struct {
		Code   string `xml:"Cd"`
		Family struct {
			Code    string `xml:"Cd"`
			SubCode string `xml:"SubFmlyCd"`
		} `xml:"Fmly"`
	} `xml:"Domn"`
	Prtry struct {
		Code string `xml:"Cd"`
	} `xml:"Prtry"`
}

// code is DOMAIN-FAMILY-SUBFAMILY (e.g. PMNT-RCDT-ESCT), or the proprietary
// code (in Germany e.g. NTRF+166+9310) when there is no ISO one.
func (b camtBankTxCode) code() string {
	if d := b.Domain; d.Code != "" {
		parts := []string{d.Code}
		for _, p := range []string{d.Family.Code, d.Family.SubCode} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		return strings.Join(parts, "-")
	}
	return strings.TrimSpace(b.Prtry.Code)
}

// camtParty has the name directly up to version 07 and under Pty from 08 on.
type camtParty struct {
	Name  string `xml:"Nm"`
	Party struct {
		Name string `xml:"Nm"`
	} `xml:"Pty"`
}

func (p camtParty) name() string { return strings.TrimSpace(firstNonEmpty(p.Name, p.Party.Name)) }

type camtAccount struct {
	ID struct {
		IBAN  string `xml:"IBAN"`
		Other struct {
			ID string `xml:"Id"`
		} `xml:"Othr"`
	} `xml:"Id"`
}

func (a camtAccount) identifiers() []obsdk.Identifier {
	switch {
	case a.ID.IBAN != "":
		return []obsdk.Identifier{{Scheme: obsdk.SchemeIBAN, Value: strings.TrimSpace(a.ID.IBAN)}}
	case a.ID.Other.ID != "":
		return []obsdk.Identifier{{Scheme: obsdk.SchemeBBAN, Value: strings.TrimSpace(a.ID.Other.ID)}}
	}
	return nil
}

type camtTxDetails struct {
	Refs struct {
		AcctSvcrRef string `xml:"AcctSvcrRef"`
		EndToEndID  string `xml:"EndToEndId"`
		TxID        string `xml:"TxId"`
	} `xml:"Refs"`
	Parties struct {
		Debtor          camtParty   `xml:"Dbtr"`
		DebtorAccount   camtAccount `xml:"DbtrAcct"`
		Creditor        camtParty   `xml:"Cdtr"`
		CreditorAccount camtAccount `xml:"CdtrAcct"`
	} `xml:"RltdPties"`
	Remittance struct {
		Unstructured []string `xml:"Ustrd"`
		Structured   []struct {
			Ref string `xml:"CdtrRefInf>Ref"`
		} `xml:"Strd"`
	} `xml:"RmtInf"`
	BankTxCode camtBankTxCode `xml:"BkTxCd"`
	AddtlInfo  string         `xml:"AddtlTxInf"`
}

type camtEntry struct {
	EntryRef    string          `xml:"NtryRef"`
	Amount      camtAmount      `xml:"Amt"`
	CdtDbtInd   string          `xml:"CdtDbtInd"`
	Status      camtStatus      `xml:"Sts"`
	BookingDate camtDate        `xml:"BookgDt"`
	ValueDate   camtDate        `xml:"ValDt"`
	AcctSvcrRef string          `xml:"AcctSvcrRef"`
	BankTxCode  camtBankTxCode  `xml:"BkTxCd"`
	AddtlInfo   string          `xml:"AddtlNtryInf"`
	Details     []camtTxDetails `xml:"NtryDtls>TxDtls"`
}

// parseCamt reads every entry of a camt body. There is no continuation in
// camt, so the page never has a next cursor.
func parseCamt(body []byte) (obsdk.TxPage, error) {
	rawBody, _ := json.Marshal(string(body))
	page := obsdk.TxPage{Transactions: []obsdk.Transaction{}, Raw: rawBody}
	d := xml.NewDecoder(bytes.NewReader(body))
	d.CharsetReader = func(charset string, in io.Reader) (io.Reader, error) {
		// camt is UTF-8 by definition; a mislabelled header must not stop it.
		return in, nil
	}
	found := false
	for {
		start := d.InputOffset()
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return page, fmt.Errorf("berlingroup: unreadable camt transactions: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "BkToCstmrAcctRpt", "BkToCstmrStmt", "BkToCstmrDbtCdtNtfctn":
			found = true
			continue
		case "Ntry":
		default:
			continue
		}
		var e camtEntry
		if err := d.DecodeElement(&e, &se); err != nil {
			return page, fmt.Errorf("berlingroup: unreadable camt entry: %w", err)
		}
		tx, keep := camtTransaction(e)
		if !keep {
			continue
		}
		tx.Raw, _ = json.Marshal(string(body[start:d.InputOffset()]))
		page.Transactions = append(page.Transactions, tx)
	}
	if !found {
		return page, fmt.Errorf("berlingroup: the transactions response is XML but not a camt.052, camt.053 or camt.054 report")
	}
	return page, nil
}

// camtTransaction maps an entry. Information-only entries (INFO) are left
// out. With one transaction in the entry, its details fill the counterparty
// and references; a batch entry keeps only what the entry itself says.
func camtTransaction(e camtEntry) (obsdk.Transaction, bool) {
	tx := obsdk.Transaction{
		ID: strings.TrimSpace(e.AcctSvcrRef), EntryReference: strings.TrimSpace(e.EntryRef), Status: obsdk.TxBooked,
		Amount:      obsdk.Money{Amount: obsdk.Decimal(strings.TrimSpace(e.Amount.Value)), Currency: e.Amount.Currency},
		BookingDate: e.BookingDate.day(), ValueDate: e.ValueDate.day(),
		BankCode: e.BankTxCode.code(), BankCodeText: strings.TrimSpace(e.AddtlInfo),
	}
	switch strings.ToUpper(e.Status.code()) {
	case "PDNG":
		tx.Status = obsdk.TxPending
	case "INFO":
		return tx, false
	}
	// camt amounts are unsigned; the indicator gives the direction.
	tx.Direction = obsdk.Credit
	if strings.TrimSpace(e.CdtDbtInd) == "DBIT" {
		tx.Direction = obsdk.Debit
		if tx.Amount.Amount != "" && !strings.HasPrefix(string(tx.Amount.Amount), "-") {
			tx.Amount.Amount = "-" + tx.Amount.Amount
		}
	}
	if len(e.Details) != 1 {
		return tx, true
	}
	t := e.Details[0]
	tx.ID = firstNonEmpty(tx.ID, strings.TrimSpace(t.Refs.AcctSvcrRef), strings.TrimSpace(t.Refs.TxID))
	if id := strings.TrimSpace(t.Refs.EndToEndID); id != "NOTPROVIDED" {
		tx.EndToEndID = id
	}
	if tx.Direction == obsdk.Debit {
		tx.Counterparty = obsdk.Party{Name: t.Parties.Creditor.name(), Identifiers: t.Parties.CreditorAccount.identifiers()}
	} else {
		tx.Counterparty = obsdk.Party{Name: t.Parties.Debtor.name(), Identifiers: t.Parties.DebtorAccount.identifiers()}
	}
	for _, l := range t.Remittance.Unstructured {
		if l = strings.TrimSpace(l); l != "" {
			tx.Remittance = append(tx.Remittance, l)
		}
	}
	for _, s := range t.Remittance.Structured {
		if r := strings.TrimSpace(s.Ref); r != "" {
			tx.ReferenceNumber = r
			break
		}
	}
	if tx.BankCode == "" {
		tx.BankCode = t.BankTxCode.code()
	}
	if tx.BankCodeText == "" {
		tx.BankCodeText = strings.TrimSpace(t.AddtlInfo)
	}
	return tx, true
}
