package berlingroup

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

// pain.001 payment bodies (Profile.PaymentXML) and pain.002 status reports,
// for banks whose payment products are "pain.001-…" only. The message is
// pain.001.001.09 as the German banking industry profiles it (DFÜ-Abkommen
// Anlage 3, GBIC_5): one payment information block with one transaction;
// fields the user doesn't give are "NOTPROVIDED", as that profile allows.

const pain001NS = "urn:iso:std:iso:20022:tech:xsd:pain.001.001.09"

// notProvided fills mandatory names and ids the request doesn't give.
const notProvided = "NOTPROVIDED"

type painDocument struct {
	XMLName xml.Name    `xml:"Document"`
	NS      string      `xml:"xmlns,attr"`
	Init    painInitiat `xml:"CstmrCdtTrfInitn"`
}

type painInitiat struct {
	GrpHdr struct {
		MsgID    string    `xml:"MsgId"`
		CreDtTm  string    `xml:"CreDtTm"`
		NbOfTxs  int       `xml:"NbOfTxs"`
		CtrlSum  string    `xml:"CtrlSum"`
		InitgPty painParty `xml:"InitgPty"`
	} `xml:"GrpHdr"`
	PmtInf painPmtInf `xml:"PmtInf"`
}

type painPmtInf struct {
	PmtInfID string `xml:"PmtInfId"`
	PmtMtd   string `xml:"PmtMtd"`
	NbOfTxs  int    `xml:"NbOfTxs"`
	CtrlSum  string `xml:"CtrlSum"`
	PmtTpInf struct {
		SvcLvl  painCode  `xml:"SvcLvl"`
		LclInst *painCode `xml:"LclInstrm,omitempty"`
	} `xml:"PmtTpInf"`
	ReqdExctnDt struct {
		Dt string `xml:"Dt"`
	} `xml:"ReqdExctnDt"`
	Dbtr     painParty   `xml:"Dbtr"`
	DbtrAcct painAccount `xml:"DbtrAcct"`
	DbtrAgt  painAgent   `xml:"DbtrAgt"`
	ChrgBr   string      `xml:"ChrgBr"`
	Tx       painTx      `xml:"CdtTrfTxInf"`
}

type painCode struct {
	Cd string `xml:"Cd"`
}

type painParty struct {
	Nm     string       `xml:"Nm"`
	PstlAd *painAddress `xml:"PstlAdr,omitempty"`
}

type painAddress struct {
	StrtNm  string   `xml:"StrtNm,omitempty"`
	BldgNb  string   `xml:"BldgNb,omitempty"`
	PstCd   string   `xml:"PstCd,omitempty"`
	TwnNm   string   `xml:"TwnNm,omitempty"`
	Ctry    string   `xml:"Ctry"`
	AdrLine []string `xml:"AdrLine,omitempty"`
}

type painAccount struct {
	IBAN string `xml:"Id>IBAN"`
	Ccy  string `xml:"Ccy,omitempty"`
}

// painAgent is a bank: by BIC, or "NOTPROVIDED" (IBAN-only payments).
type painAgent struct {
	BICFI string     `xml:"FinInstnId>BICFI,omitempty"`
	Othr  *painOther `xml:"FinInstnId>Othr,omitempty"`
}

type painOther struct {
	ID string `xml:"Id"`
}

type painTx struct {
	PmtID struct {
		InstrID    string `xml:"InstrId,omitempty"`
		EndToEndID string `xml:"EndToEndId"`
	} `xml:"PmtId"`
	Amt struct {
		InstdAmt struct {
			Ccy   string `xml:"Ccy,attr"`
			Value string `xml:",chardata"`
		} `xml:"InstdAmt"`
	} `xml:"Amt"`
	CdtrAgt  *painAgent      `xml:"CdtrAgt,omitempty"`
	Cdtr     painParty       `xml:"Cdtr"`
	CdtrAcct painAccount     `xml:"CdtrAcct"`
	RmtInf   *painRemittance `xml:"RmtInf,omitempty"`
}

type painRemittance struct {
	Ustrd string          `xml:"Ustrd,omitempty"`
	Strd  *painStructured `xml:"Strd,omitempty"`
}

type painStructured struct {
	Tp  *painRefType `xml:"CdtrRefInf>Tp,omitempty"`
	Ref string       `xml:"CdtrRefInf>Ref"`
}

type painRefType struct {
	Cd   string `xml:"CdOrPrtry>Cd"`
	Issr string `xml:"Issr"`
}

// painID turns a generated id into a pain.001 identifier: at most 35
// characters of the SEPA character set (a UUID without its dashes).
func painID(id string) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > 35 {
		id = id[:35]
	}
	return id
}

// cetDate is the calendar date in Central European (Summer) Time, the time
// zone of the banks that take pain.001 bodies, without needing tzdata: summer
// time runs from the last Sunday of March to the last Sunday of October, 01:00
// UTC each.
func cetDate(t time.Time) string {
	t = t.UTC()
	lastSunday := func(m time.Month) time.Time {
		d := time.Date(t.Year(), m+1, 1, 1, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
		return d.AddDate(0, 0, -int(d.Weekday()))
	}
	off := time.Hour
	if !t.Before(lastSunday(time.March)) && t.Before(lastSunday(time.October)) {
		off = 2 * time.Hour
	}
	return t.Add(off).Format("2006-01-02")
}

// buildPain001 builds the pain.001 body of a single credit transfer.
func (c *client) buildPain001(r obsdk.PaymentRequest) ([]byte, error) {
	t := r.Transfers[0]
	if r.Debtor == nil || r.Debtor.Account == nil || r.Debtor.Account.Value == "" {
		return nil, invalid(obsdk.FieldDebtorAccount, c.p.Info.Name+" needs the account to pay from")
	}
	amount := string(t.Amount.Amount)
	now := c.now()
	d := painDocument{NS: pain001NS}
	g := &d.Init.GrpHdr
	g.MsgID = painID(c.cfg.ID(obsdk.IDRequest))
	g.CreDtTm = now.UTC().Format("2006-01-02T15:04:05Z")
	g.NbOfTxs, g.CtrlSum = 1, amount
	g.InitgPty.Nm = firstNonEmpty(r.Debtor.Name, notProvided)

	p := &d.Init.PmtInf
	p.PmtInfID = painID(c.cfg.ID(obsdk.IDRequest))
	p.PmtMtd, p.NbOfTxs, p.CtrlSum = "TRF", 1, amount
	p.PmtTpInf.SvcLvl.Cd = "SEPA"
	if r.Type == obsdk.PaymentSEPAInstant {
		p.PmtTpInf.LclInst = &painCode{Cd: "INST"}
	}
	p.ReqdExctnDt.Dt = firstNonEmpty(r.ExecutionDate, cetDate(now))
	p.Dbtr.Nm = firstNonEmpty(r.Debtor.Name, notProvided)
	p.DbtrAcct = painAccount{IBAN: r.Debtor.Account.Value}
	if r.Debtor.Currency != "" && r.Debtor.Currency != t.Amount.Currency {
		p.DbtrAcct.Ccy = r.Debtor.Currency
	}
	p.DbtrAgt = painAgent{Othr: &painOther{ID: notProvided}}
	p.ChrgBr = "SLEV"

	x := &p.Tx
	x.PmtID.InstrID = t.InstructionID
	x.PmtID.EndToEndID = firstNonEmpty(t.EndToEndID, notProvided)
	x.Amt.InstdAmt.Ccy, x.Amt.InstdAmt.Value = t.Amount.Currency, amount
	if ag := t.Creditor.Agent; ag != nil && ag.BIC != "" {
		x.CdtrAgt = &painAgent{BICFI: ag.BIC}
	}
	x.Cdtr.Nm = t.Creditor.Name
	if a := t.Creditor.Address; a != nil && (a.Country != "" || len(a.Lines) > 0 || a.Town != "") {
		if a.Country == "" {
			return nil, invalid(obsdk.FieldCreditorAddress, "the payee's address needs a country")
		}
		x.Cdtr.PstlAd = &painAddress{StrtNm: a.Street, BldgNb: a.BuildingNumber, PstCd: a.PostCode, TwnNm: a.Town,
			Ctry: a.Country, AdrLine: a.Lines}
	}
	if t.Creditor.Account.Scheme == obsdk.SchemeBBAN {
		return nil, invalid(obsdk.FieldCreditorAccount, c.p.Info.Name+" needs the payee's IBAN")
	}
	x.CdtrAcct = painAccount{IBAN: t.Creditor.Account.Value}
	ustrd := strings.Join(t.Remittance, " ")
	ref := t.Reference
	if ustrd != "" || ref != nil && ref.Value != "" {
		x.RmtInf = &painRemittance{}
		switch {
		case ref != nil && ref.Value != "" && ustrd != "":
			// One or the other in SEPA (EPC rulebook).
			return nil, invalid(obsdk.FieldReference, c.p.Info.Name+" takes either a description or a payment reference, not both")
		case ref != nil && ref.Value != "":
			x.RmtInf.Strd = &painStructured{Ref: ref.Value}
			if ref.Scheme == obsdk.ReferenceRF {
				x.RmtInf.Strd.Tp = &painRefType{Cd: "SCOR", Issr: "ISO"}
			}
		default:
			x.RmtInf.Ustrd = ustrd
		}
	}

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	if err := enc.Encode(d); err != nil {
		return nil, fmt.Errorf("berlingroup: build pain.001: %w", err)
	}
	return buf.Bytes(), nil
}

// ---- pain.002 ----

type painReason struct {
	Cd       string   `xml:"Rsn>Cd"`
	Prtry    string   `xml:"Rsn>Prtry"`
	AddtlInf []string `xml:"AddtlInf"`
}

type pain002 struct {
	Grp struct {
		Sts string       `xml:"GrpSts"`
		Rsn []painReason `xml:"StsRsnInf"`
	} `xml:"CstmrPmtStsRpt>OrgnlGrpInfAndSts"`
	Pmt []struct {
		Sts string       `xml:"PmtInfSts"`
		Rsn []painReason `xml:"StsRsnInf"`
		Tx  []struct {
			Sts string       `xml:"TxSts"`
			Rsn []painReason `xml:"StsRsnInf"`
		} `xml:"TxInfAndSts"`
	} `xml:"CstmrPmtStsRpt>OrgnlPmtInfAndSts"`
}

// parsePain002 reads a payment status report: the most specific status given
// (transaction, then payment information, then group) and its reason.
func parsePain002(b []byte) (status, reason string, err error) {
	var d pain002
	if err := xml.Unmarshal(b, &d); err != nil {
		return "", "", fmt.Errorf("berlingroup: unreadable pain.002 status report: %w", err)
	}
	status, rsn := d.Grp.Sts, d.Grp.Rsn
	for _, p := range d.Pmt {
		if p.Sts != "" {
			status, rsn = p.Sts, p.Rsn
		}
		for _, t := range p.Tx {
			if t.Sts != "" {
				status, rsn = t.Sts, t.Rsn
			}
		}
	}
	if status == "" {
		return "", "", fmt.Errorf("berlingroup: pain.002 status report without a status")
	}
	for _, r := range rsn {
		if s := strings.Join(r.AddtlInf, " "); s != "" {
			return status, strings.TrimSpace(s), nil
		}
		if s := firstNonEmpty(r.Cd, r.Prtry); s != "" {
			return status, s, nil
		}
	}
	return status, "", nil
}
