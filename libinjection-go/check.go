package libinjection

import (
	"github.com/corazawaf/libinjection-go"
)

func IsXSS(input string) bool {
	return libinjection.IsXSS(input)
}
func IsSQLiNotReturnPrint(input string) bool {
	result, _ := libinjection.IsSQLi(input)
	return result
}
