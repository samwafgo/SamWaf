package static

import (
	"SamWaf/global"
	"SamWaf/wafconfig"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAdminTitlesNoRouteBootstrap(t *testing.T) {
	priorHTML := global.GWAF_LOCAL_INDEX_HTML
	priorEnable, priorPath := global.GWAF_SECURITY_ENTRY_ENABLE, global.GWAF_SECURITY_ENTRY_PATH
	t.Cleanup(func() {
		global.GWAF_LOCAL_INDEX_HTML = priorHTML
		global.GWAF_SECURITY_ENTRY_ENABLE, global.GWAF_SECURITY_ENTRY_PATH = priorEnable, priorPath
	})
	r := gin.New()
	Static(r, r.NoRoute)
	global.GWAF_LOCAL_INDEX_HTML = `<html><head><script src="/assets/app.js"></script><link href="/assets/app.css"></head></html>`
	for _, enabled := range []bool{false, true} {
		global.GWAF_SECURITY_ENTRY_ENABLE, global.GWAF_SECURITY_ENTRY_PATH = enabled, "entry"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
		body := w.Body.String()
		if w.Code != 200 || strings.Count(body, `id="samwaf-ui-config"`) != 1 {
			t.Fatalf("bootstrap missing: %d %s", w.Code, body)
		}
		if enabled {
			if !strings.Contains(body, `src="/entry/assets/app.js"`) || !strings.Contains(body, `href="/entry/assets/app.css"`) || !strings.Contains(body, `window.__SAMWAF_SECURITY_PATH__='/entry'`) {
				t.Fatalf("security path rewriting changed: %s", body)
			}
		} else if !strings.Contains(body, `src="/assets/app.js"`) || strings.Contains(body, "__SAMWAF_SECURITY_PATH__") {
			t.Fatalf("unexpected security path rewriting: %s", body)
		}
	}
}

func TestInjectAdminTitles(t *testing.T) {
	const marker = `<script id="samwaf-ui-config" type="application/json">`
	for _, html := range []string{
		`<html><head><title>SamWaf</title></head><body></body></html>`,
		`<html><body>fallback</body></html>`,
	} {
		for _, titles := range []wafconfig.AdminTitles{
			{},
			{AdminTitle: `</script><script>alert("x")</script>` + "<>&  中文"},
		} {
			got := injectAdminTitles(html, titles)
			if strings.Count(got, marker) != 1 || strings.Count(got, "</script>") != 1 {
				t.Fatalf("unexpected script boundaries: %s", got)
			}
			data := strings.SplitN(strings.SplitN(got, marker, 2)[1], "</script>", 2)[0]
			if strings.ContainsAny(data, "<>&") {
				t.Fatalf("JSON HTML characters were not escaped: %s", data)
			}
			var decoded map[string]string
			if err := json.Unmarshal([]byte(data), &decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded) != 1 || decoded["admin_title"] != titles.AdminTitle {
				t.Fatalf("unexpected bootstrap: %s", data)
			}
			if strings.Contains(html, "</head>") && !strings.Contains(got, "</script></head>") {
				t.Fatal("bootstrap must be inserted in head")
			}
		}
	}
}
