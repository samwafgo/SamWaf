package wafhttpcore

import (
	"SamWaf/libinjection-go"
	"fmt"
	"net/url"
	"testing"
)

func TestSql(t *testing.T) {
	payload := "id=1+and+1=2+union+select+1"
	decodedValue, err := url.QueryUnescape(payload)

	payLoadReturnPrint := libinjection.IsSQLiNotReturnPrint(payload)
	fmt.Println(fmt.Sprintf("payload=%v   Result:%v", payload, payLoadReturnPrint))

	decodepayLoadReturnPrint := libinjection.IsSQLiNotReturnPrint(decodedValue)
	if err != nil {
		fmt.Println(fmt.Sprintf("decodePayload=%v   Result:%v  QueryUnescapeErr:%v", decodedValue, decodepayLoadReturnPrint, err))
	} else {
		fmt.Println(fmt.Sprintf("decodePayload=%v   Result:%v ", decodedValue, decodepayLoadReturnPrint))

	}
}
