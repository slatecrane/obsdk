package obsdk

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// Scheme formats. Values are checked as sent to the bank: no spaces, upper
// case. Bankgiro and Plusgiro may carry the dash before the check digit.
var (
	ibanRE     = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)
	bankgiroRE = regexp.MustCompile(`^[0-9]{3,4}-?[0-9]{4}$`)
	plusgiroRE = regexp.MustCompile(`^[0-9]{1,7}-?[0-9]$`)
	sortCodeRE = regexp.MustCompile(`^[0-9]{14}$`)
	ocrRE      = regexp.MustCompile(`^[0-9]{2,25}$`)
	rfRE       = regexp.MustCompile(`^RF[0-9]{2}[A-Z0-9]{1,21}$`)
)

// ValidateIdentifier checks a value against the format and check digits of
// its scheme, the rules every bank applies. Schemes without a fixed format
// (BBAN and bank-specific ones) always pass.
func ValidateIdentifier(id Identifier) error {
	switch id.Scheme {
	case SchemeIBAN:
		return checkMod97(id.Value, ibanRE, "IBAN")
	case SchemeBankgiro:
		return checkLuhn(id.Value, bankgiroRE, "Bankgiro number", "7 or 8 digits")
	case SchemePlusgiro:
		return checkLuhn(id.Value, plusgiroRE, "Plusgiro number", "2 to 8 digits")
	case SchemeSortCodeAccount:
		if !sortCodeRE.MatchString(id.Value) {
			return fmt.Errorf("sort code and account number must be 14 digits")
		}
	}
	return nil
}

// ValidateReference checks a payment reference against its scheme.
func ValidateReference(r Reference) error {
	switch r.Scheme {
	case ReferenceOCR:
		return checkLuhn(r.Value, ocrRE, "OCR number", "2 to 25 digits")
	case ReferenceRF:
		return checkMod97(r.Value, rfRE, "RF reference")
	}
	return nil
}

// checkMod97 is the ISO 7064 MOD 97-10 check of IBAN and ISO 11649 (RF):
// the first four characters move to the end, letters become 10..35, and the
// number must leave remainder 1.
func checkMod97(s string, re *regexp.Regexp, name string) error {
	if !re.MatchString(s) {
		return fmt.Errorf("is not a valid %s (upper case, no spaces)", name)
	}
	if mod97(s[4:]+s[:4]) != 1 {
		return fmt.Errorf("%s check digits do not match", name)
	}
	return nil
}

func mod97(s string) int64 {
	var b strings.Builder
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			fmt.Fprintf(&b, "%d", c-'A'+10)
		} else {
			b.WriteRune(c)
		}
	}
	n, _ := new(big.Int).SetString(b.String(), 10)
	return new(big.Int).Mod(n, big.NewInt(97)).Int64()
}

// checkLuhn is the mod-10 check digit used by Bankgiro, Plusgiro and OCR.
func checkLuhn(s string, re *regexp.Regexp, name, format string) error {
	if !re.MatchString(s) {
		return fmt.Errorf("%s must be %s", name, format)
	}
	sum, double := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '-' {
			continue
		}
		d := int(s[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum, double = sum+d, !double
	}
	if sum%10 != 0 {
		return fmt.Errorf("%s check digit does not match", name)
	}
	return nil
}
