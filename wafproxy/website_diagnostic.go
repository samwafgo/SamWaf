package wafproxy

import (
	"net/http"
	"net/url"

	"golang.org/x/net/http/httpguts"
)

// BuildDiagnosticRequest 复用 Director 和逐跳头处理，仅构造独立请求副本。
func BuildDiagnosticRequest(req *http.Request, target *url.URL, customHeaders, customConfig map[string]string) *http.Request {
	out := req.Clone(req.Context())
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	NewSingleHostReverseProxyCustomHeader(target, customHeaders, customConfig).Director(out)
	out.Close = false
	upgrade := upgradeType(out.Header)
	removeConnectionHeaders(out.Header)
	for _, name := range hopHeaders {
		out.Header.Del(name)
	}
	if httpguts.HeaderValuesContainsToken(req.Header["Te"], "trailers") {
		out.Header.Set("Te", "trailers")
	}
	if upgrade != "" {
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", upgrade)
	}
	out.Header.Del("X-Waf-Custom-XFF-Control")
	return out
}
