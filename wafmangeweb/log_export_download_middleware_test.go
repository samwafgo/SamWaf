package wafmangeweb

import (
	"SamWaf/cache"
	"SamWaf/global"
	"SamWaf/middleware"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestLogExportDownloadMiddlewareAcceptsReplayQueryAndRewindsBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store, err := cache.NewCacheStore("memory", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldCache, oldReplay := global.GCACHE_WAFCACHE, global.GCONFIG_ENABLE_REPLAY_PROTECT
	oldIP, oldDomain := global.GWAF_IP_WHITELIST, global.GWAF_DOMAIN_WHITELIST
	defer func() {
		global.GCACHE_WAFCACHE, global.GCONFIG_ENABLE_REPLAY_PROTECT = oldCache, oldReplay
		global.GWAF_IP_WHITELIST, global.GWAF_DOMAIN_WHITELIST = oldIP, oldDomain
	}()
	global.GCACHE_WAFCACHE = store
	global.GCONFIG_ENABLE_REPLAY_PROTECT = 1
	global.GWAF_IP_WHITELIST = "0.0.0.0/0,::/0"
	global.GWAF_DOMAIN_WHITELIST = ""

	r := gin.New()
	group := r.Group("")
	group.Use(middleware.SecApi(), middleware.ReplayProtect(), middleware.IPWhitelist(), middleware.DomainWhitelist(), middleware.GinGlobalExceptionMiddleWare())
	group.GET("/api/v1/waflog/exports/:id/download", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		c.JSON(http.StatusOK, gin.H{"ok": true, "body": string(body)})
	})

	now := strconv.FormatInt(time.Now().Unix(), 10)
	url := "/api/v1/waflog/exports/task-1/download?ticket=ticket-value&X-Request-Time=" + now + "&X-Request-Id=nonce-download-123456"
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, url, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("合法票据下载链应通过共有中间件，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"ok":true`) {
		t.Fatalf("下载处理器未执行: %s", recorder.Body.String())
	}

	// 同一 nonce 再次请求应被防重放拒绝，且不能进入下载处理器。
	recorder = httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, url, nil))
	if strings.Contains(recorder.Body.String(), `"ok":true`) {
		t.Fatalf("重复 nonce 不应进入下载处理器: %s", recorder.Body.String())
	}

	// 非下载路径不能借查询串绕过请求头校验。
	recorder = httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/waflog/exports/task-1?X-Request-Time="+now+"&X-Request-Id=nonce-other-123456", nil))
	if strings.Contains(recorder.Body.String(), `"ok":true`) {
		t.Fatalf("非下载路径不应接受查询串防重放参数: %s", recorder.Body.String())
	}
}
