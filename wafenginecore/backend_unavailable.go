package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"bytes"
	"net/http"
	"strconv"
	"strings"
)

func (waf *WafEngine) writeBackendUnavailableResponse(w http.ResponseWriter, r *http.Request, host string, statusCode int) error {
	body := []byte(global.GLOBAL_DEFAULT_BACKEND_UNAVAILABLE)
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")

	if globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]; globalHost != nil {
		page := globalHost.BlockingPage[model.BlockingPageTypeBackendUnavailable]
		content := page.ResponseContent
		if page.BlockingType == model.BlockingPageTypeBackendUnavailable && len(content) <= utils.BackendUnavailablePageMaxBytes && strings.TrimSpace(content) != "" {
			if tmpl, err := utils.ParseBackendUnavailablePage(content); err == nil {
				if len(host) > 261 {
					host = ""
				}
				var rendered bytes.Buffer
				if err := tmpl.Execute(&rendered, utils.BackendUnavailablePageData{SAMWAF_HOST: host, SAMWAF_STATUS_CODE: strconv.Itoa(statusCode)}); err == nil {
					body = rendered.Bytes()
					applySpecialPageHeaders(header, page.ResponseHeader)
				}
			}
		}
	}

	w.WriteHeader(statusCode)
	if r.Method == http.MethodHead {
		return nil
	}
	_, err := w.Write(body)
	return err
}
