// Package all registers every bank integration. Import it for its side effects:
//
//	import _ "github.com/slatecrane/obsdk/banks/all"
package all

import (
	_ "github.com/slatecrane/obsdk/banks/bunq"
	_ "github.com/slatecrane/obsdk/banks/hsbc"
	_ "github.com/slatecrane/obsdk/banks/ing"
	_ "github.com/slatecrane/obsdk/banks/nordea"
	_ "github.com/slatecrane/obsdk/banks/rabobank"
	_ "github.com/slatecrane/obsdk/banks/revolut"
	_ "github.com/slatecrane/obsdk/banks/swedbank"
)
