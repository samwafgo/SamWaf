package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/model/wafenginmodel"
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

func renderUnmatchedHostPage(content, host string) ([]byte, error) {
	tmpl, err := template.New("unmatchedHost").Delims("[[", "]]").Parse(content)
	if err != nil {
		return nil, err
	}
	var result bytes.Buffer
	err = tmpl.Execute(&result, map[string]string{"SAMWAF_HOST": host})
	return result.Bytes(), err
}

// writeUnmatchedHostResponse 使用全局网站的专用模板，状态码固定为 403。
func writeUnmatchedHostResponse(w http.ResponseWriter, r *http.Request, globalHost *wafenginmodel.HostSafe) []byte {
	content := global.GLOBAL_DEFAULT_NOT_MATCH_WEBSITE
	var customHeaders string
	if globalHost != nil {
		if page, ok := globalHost.BlockingPage["not_match_website"]; ok && page.BlockingType == "not_match_website" && strings.TrimSpace(page.ResponseContent) != "" {
			content = page.ResponseContent
			customHeaders = page.ResponseHeader
		}
	}
	body, err := renderUnmatchedHostPage(content, r.Host)
	if err != nil {
		body, _ = renderUnmatchedHostPage(global.GLOBAL_DEFAULT_NOT_MATCH_WEBSITE, r.Host)
		customHeaders = ""
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var headers []map[string]string
	if json.Unmarshal([]byte(customHeaders), &headers) == nil {
		for _, header := range headers {
			name, value := header["name"], header["value"]
			switch strings.ToLower(name) {
			case "content-length", "content-encoding", "transfer-encoding", "connection", "trailer", "upgrade", "te":
				continue
			}
			if httpguts.ValidHeaderFieldName(name) && httpguts.ValidHeaderFieldValue(value) {
				w.Header().Set(name, value)
			}
		}
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
	return body
}
