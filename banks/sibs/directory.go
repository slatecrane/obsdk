package sibs

import (
	"fmt"
	"strings"

	obsdk "github.com/slatecrane/obsdk"
)

// Institution is one bank on SIBS API Market.
type Institution struct {
	Code     string // ASPSP code, the path segment that picks the bank
	BIC      string
	BankCode string // the bank's code in its IBANs (PT: positions 5-8)
	Name     string
}

// institutions is SIBS's List of Banks (GET /v1/available-aspsp on the
// sandbox, 2026-10-19). CGD France and BIG España hold French and Spanish
// accounts. The live list can differ; codes not listed here are accepted.
var institutions = []Institution{
	{Code: "BBPI", BIC: "BBPIPTPL", BankCode: "0010", Name: "BANCO BPI, SA"},
	{Code: "BST", BIC: "TOTAPTPL", BankCode: "0018", Name: "BANCO SANTANDER TOTTA, SA"},
	{Code: "ABPT", BIC: "ACTVPTPLXXX", BankCode: "0023", Name: "BANCO ACTIVOBANK, SA"},
	{Code: "BCPPT", BIC: "BCOMPTPL", BankCode: "0033", Name: "BANCO COMERCIAL PORTUGUES, SA"},
	{Code: "CGDPT", BIC: "CGDIPTPL", BankCode: "0035", Name: "CAIXA GERAL DE DEPOSITOS, SA"},
	{Code: "CEMG", BIC: "MPIOPTPLXXX", BankCode: "0036", Name: "CAIXA ECONOMICA MONTEPIO GERAL"},
	{Code: "GCA", BIC: "CCCMPTPL", BankCode: "0045", Name: "CAIXA CENTRAL - CAIXA CENTRAL DE CREDITO AGRICOLA MUTUO, CRL"},
	{Code: "CEMAH", BIC: "CEMAPTP2XXX", BankCode: "0059", Name: "CAIXA ECONOMICA DA MISERICORDIA DE ANGRA DO HEROISMO"},
	{Code: "BIG", BIC: "BDIGPTPLXXX", BankCode: "0061", Name: "BANCO DE INVESTIMENTO GLOBAL, SA"},
	{Code: "BPG", BIC: "BPGPPTPLXXX", BankCode: "0064", Name: "BANCO PORTUGUES DE GESTAO, SA"},
	{Code: "BIC", BIC: "BPNPPTPLXXX", BankCode: "0079", Name: "BANCO BIC PORTUGUES, SA"},
	{Code: "ATLEU", BIC: "BAPAPTPLXXX", BankCode: "0189", Name: "BANCO ATLANTICO EUROPA, SA"},
	{Code: "BCTT", BIC: "CTTVPTPLXXX", BankCode: "0193", Name: "BANCO CTT, SA"},
	{Code: "BNKI", BIC: "BKBKPTPLXXX", BankCode: "0269", Name: "BANKINTER, SA - SUCURSAL EM PORTUGAL"},
	{Code: "CCAML", BIC: "CDCTPTP2XXX", BankCode: "5180", Name: "CAIXA DE CREDITO AGRICOLA MUTUO DE LEIRIA, CRL"},
	{Code: "CGDFR", BIC: "CGDIFRPPXXX", BankCode: "8226", Name: "CAIXA GERAL DE DEPOSITOS FRANCE"},
	{Code: "NVB", BIC: "BESCPTPL", BankCode: "0007", Name: "NOVO BANCO, SA"},
	{Code: "NVBA", BIC: "BESAPTPAXXX", BankCode: "0160", Name: "NOVO BANCO DOS ACORES, SA"},
	{Code: "UNICR", BIC: "UIFCPTP1XXX", BankCode: "0698", Name: "Unicre - Instituição Financeira de Crédito S.A"},
	{Code: "COF", BIC: "CFFIPTP1XXX", BankCode: "0921", Name: "COFIDIS"},
	{Code: "CATV", BIC: "CTIUPTP1XXX", BankCode: "5340", Name: "Caixa De Credito Agricola Mutuo De Torres Vedras,c.r.l"},
	{Code: "CABOM", BIC: "CERTPTP1XXX", BankCode: "0098", Name: "Caixa De Credito Agricola Mutuo De Bombarral Crl"},
	{Code: "CACHM", BIC: "CCCHPTP1XXX", BankCode: "0097", Name: "Caixa De Credito Agricola Mutuo Da Chamusca, C.r.l"},
	{Code: "CAMAF", BIC: "CDOTPTP1XXX", BankCode: "5200", Name: "Caixa De Credito Agricola Mutuo De Mafra, C.R.L."},
	{Code: "BIGES", BIC: "IGSEESMMXXX", BankCode: "8350", Name: "BANCO DE INVESTIMENTO GLOBAL ESPANHA, SA"},
}

// Institutions lists the banks SIBS API Market listed on 2026-10-19.
func Institutions() []Institution { return append([]Institution(nil), institutions...) }

// Lookup returns a listed bank by its ASPSP code.
func Lookup(code string) (Institution, bool) {
	for _, in := range institutions {
		if in.Code == code {
			return in, true
		}
	}
	return Institution{}, false
}

// ASPSPCode normalizes the bank parameter: an ASPSP code (letters and
// digits, e.g. BST, case-insensitive), the BIC of a listed bank, or a
// Portuguese IBAN of one, from which its bank code is taken.
func ASPSPCode(s string) (string, error) {
	v := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if strings.HasPrefix(v, "PT") && len(v) == 25 {
		if err := obsdk.ValidateIdentifier(obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: v}); err != nil {
			return "", fmt.Errorf("%q is not a Portuguese IBAN", s)
		}
		for _, in := range institutions {
			if in.BankCode == v[4:8] {
				return in.Code, nil
			}
		}
		return "", fmt.Errorf("bank code %s (of IBAN %s) is not a bank on SIBS API Market", v[4:8], s)
	}
	for _, in := range institutions {
		if in.Code == v || in.BIC == v || strings.TrimSuffix(in.BIC, "XXX") == strings.TrimSuffix(v, "XXX") {
			return in.Code, nil
		}
	}
	if len(v) < 2 || len(v) > 12 || strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
		return "", fmt.Errorf("%q is not a SIBS ASPSP code (letters and digits, e.g. BST), BIC or Portuguese IBAN", s)
	}
	return v, nil
}
