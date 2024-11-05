package wafhttpcore

import (
	"SamWaf/libinjection-go"
	"net/url"
	"testing"
)

func TestWafHttpCoreUrlEncode(t *testing.T) {
	srcUrl := "/vulnerabilities/xss_r/?name=javascript%3A%2F*--%3E%3C%2Ftitle%3E%3C%2Fstyle%3E%3C%2Ftextarea%3E%3C%2Fscript%3E%3C%2Fxmp%3E%3Cdetails%2Fopen%2Fontoggle%3D%27%2B%2F%60%2F%2B%2F%22%2F%2B%2Fonmouseover%3D1%2F%2B%2F%5B*%2F%5B%5D%2F%2Balert%28%2F%40PortSwiggerRes%2F%29%2F%2F%27%3E"
	t.Log(srcUrl)
	en := WafHttpCoreUrlEncode(srcUrl, 100)
	t.Log(en)
	en2, ok := url.QueryUnescape(srcUrl)
	if ok != nil {
		t.Error(ok)
	}
	t.Log(en2)
	srcCheckResult := libinjection.IsSQLiNotReturnPrint(srcUrl)
	t.Log(srcCheckResult)
	targetCheckResult := libinjection.IsSQLiNotReturnPrint(en)
	t.Log(targetCheckResult)
	targetCheckResult = libinjection.IsXSS(en)
	t.Log(targetCheckResult)
}
