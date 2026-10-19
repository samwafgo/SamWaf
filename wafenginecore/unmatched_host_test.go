package wafenginecore

import (
	"SamWaf/common/queue"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"html"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnmatchedHostServeHTTP(t *testing.T) {
	oldQueue := global.GQEQUE_LOG_DB
	global.GQEQUE_LOG_DB = queue.NewQueue()
	t.Cleanup(func() { global.GQEQUE_LOG_DB = oldQueue })
	waf := &WafEngine{}
	waf.InitRouting()
	for _, custom := range []bool{false, true} {
		if custom {
			waf.withWriteTable(func(rt *routingTable) {
				rt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
					BlockingPage: map[string]model.BlockingPage{
						"not_match_website": {BlockingType: "not_match_website", ResponseContent: `<h1>自定义 [[.SAMWAF_HOST]]</h1>`, ResponseCode: "500"},
					},
				}
			})
		}
		r := httptest.NewRequest("GET", "http://unconfigured.example:9112/", nil)
		w := httptest.NewRecorder()
		waf.ServeHTTP(w, r)
		if w.Code != 403 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("unexpected response: %d %v", w.Code, w.Header())
		}
		if !strings.Contains(w.Body.String(), r.Host) {
			t.Fatal("response missing original host")
		}
		if custom && !strings.Contains(w.Body.String(), "自定义") {
			t.Fatal("global unmatched page was not used")
		}
		if !custom && (!strings.Contains(w.Body.String(), "网站防护") || !strings.Contains(w.Body.String(), "新建")) {
			t.Fatal("default response missing setup instructions")
		}
		entry, ok := global.GQEQUE_LOG_DB.Dequeue()
		if !ok {
			t.Fatal("request log missing")
		}
		log := entry.(*innerbean.WebLog)
		if log.STATUS_CODE != w.Code || log.RES_BODY != w.Body.String() || log.HOST_CODE != "" {
			t.Fatal("request log differs from unmatched response")
		}
	}
}

func TestUnmatchedHostPageTypeIsolation(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	w := httptest.NewRecorder()
	writeUnmatchedHostResponse(w, r, &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{
		"not_match_website": {BlockingType: "other_block", ResponseContent: "ordinary page", ResponseCode: "not_match_website"},
	}})
	if !strings.Contains(w.Body.String(), "网站尚未接入") {
		t.Fatal("ordinary page selected as unmatched website response")
	}
}

func TestUnmatchedHostPageFallbackAndEscaping(t *testing.T) {
	for _, content := range []string{"", "   ", `[[if]]`, `<a href="[[if .SAMWAF_HOST]]">broken context</a>`} {
		host := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{
			"403":               {ResponseContent: "ordinary global 403"},
			"not_match_website": {BlockingType: "not_match_website", ResponseContent: content},
		}}
		r := httptest.NewRequest("GET", "http://example.test/", nil)
		r.Host = `<b>example</b>:80`
		w := httptest.NewRecorder()
		writeUnmatchedHostResponse(w, r, host)
		if !strings.Contains(w.Body.String(), "网站尚未接入") || !strings.Contains(w.Body.String(), html.EscapeString(r.Host)) || strings.Contains(w.Body.String(), r.Host) {
			t.Fatalf("fallback or host escaping failed for %q: %s", content, w.Body.String())
		}
	}
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.Host = `<b>example</b>:80`
	w := httptest.NewRecorder()
	writeUnmatchedHostResponse(w, r, &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{
		"not_match_website": {
			BlockingType:    "not_match_website",
			ResponseContent: `<p>[[.SAMWAF_HOST]]</p>`,
			ResponseHeader:  `[{"name":"X-Page","value":"custom"},{"name":"Content-Length","value":"1"},{"name":"Content-Encoding","value":"gzip"},{"name":"X-Bad","value":"a\r\nb"}]`,
		},
	}})
	if w.Body.String() != "<p>"+html.EscapeString(r.Host)+"</p>" || w.Header().Get("X-Page") != "custom" {
		t.Fatal("custom template escaping or headers failed")
	}
	if w.Header().Get("Content-Length") != "" || w.Header().Get("Content-Encoding") != "" || w.Header().Get("X-Bad") != "" {
		t.Fatal("unexpected response headers")
	}
}
