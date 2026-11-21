package wafenginecore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/wafwebcache"
)

// TestTieredCacheProxyAndPasswordGate 经真实 HTTP 回源验证冷到热链路，并确认密码门先于缓存查询。
func TestTieredCacheProxyAndPasswordGate(t *testing.T) {
	newNotifyClassificationQueues(t)
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body := "public cache object"
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(body))
	}))
	defer origin.Close()
	cfg := model.CacheConfig{IsEnableCache: 1, CacheLocation: "tiered", CacheDir: t.TempDir(), L1CapacityMB: 1, L2CapacityMB: 8, HeatThreshold: 3}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	waf := newNotifyClassificationEngine(t, model.HostsDefense{})
	waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
		h.PathRules = nil
		h.TargetHost = origin.URL
		h.Host.IsEnableResponseBuffering = 1
		h.Host.CacheJSON = string(encoded)
		h.CacheRule = []model.CacheRule{{RuleType: 2, RuleContent: "/public/", ParamType: 1, CacheTime: 60, RequestMethod: "GET;HEAD"}}
	})
	for i, want := range []string{"origin", "l2", "l2", "l1"} {
		r := httptest.NewRequest("GET", "http://notify.test/public/asset", nil)
		r.RequestURI = r.URL.RequestURI()
		rec := httptest.NewRecorder()
		waf.ServeHTTP(rec, r)
		if rec.Code != 200 || rec.Body.String() != "public cache object" || rec.Header().Get("X-Cache-Layer") != want {
			t.Fatalf("request %d: status=%d layer=%q body=%q", i, rec.Code, rec.Header().Get("X-Cache-Layer"), rec.Body.String())
		}
		if len(rec.Header().Values("X-Cache")) != 1 {
			t.Fatal("duplicate cache diagnostics")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("origin reads=%d", calls.Load())
	}
	waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
		h.Host.IsEnableHttpAuthBase = 1
		h.Host.HttpAuthBaseType = "authorization"
		h.HttpAuthBases = []model.HttpAuthBase{{UserName: "synthetic", Password: "synthetic"}}
	})
	before := wafwebcache.Snapshot()["bypasses"]
	r := httptest.NewRequest("GET", "http://notify.test/public/asset", nil)
	rec := httptest.NewRecorder()
	waf.ServeHTTP(rec, r)
	if rec.Code != 401 || rec.Header().Get("X-Cache") != "" || calls.Load() != 1 {
		t.Fatalf("password gate: status=%d cache=%q origin=%d", rec.Code, rec.Header().Get("X-Cache"), calls.Load())
	}
	if wafwebcache.Snapshot()["bypasses"] != before {
		t.Fatal("cache was consulted before password authentication")
	}
}

// TestTieredCacheProxyRevalidates304 覆盖响应钩子的 defer 顺序：真实 304 应返回旧正文、保留诊断并续为 HIT。
func TestTieredCacheProxyRevalidates304(t *testing.T) {
	newNotifyClassificationQueues(t)
	var calls atomic.Int64
	const body = "revalidated-body"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write([]byte(body))
	}))
	defer origin.Close()
	cfg := model.CacheConfig{IsEnableCache: 1, CacheLocation: "tiered", CacheDir: t.TempDir()}
	encoded, _ := json.Marshal(cfg)
	waf := newNotifyClassificationEngine(t, model.HostsDefense{})
	waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
		h.PathRules = nil
		h.TargetHost = origin.URL
		h.Host.CacheJSON = string(encoded)
		h.Host.IsEnableResponseBuffering = 1
		h.CacheRule = []model.CacheRule{{RuleType: 2, RuleContent: "/", ParamType: 1, CacheTime: 2, RequestMethod: "GET;HEAD"}}
	})
	for i, want := range []string{"MISS", "REVALIDATED", "HIT"} {
		if i == 1 {
			time.Sleep(2100 * time.Millisecond)
		}
		r := httptest.NewRequest("GET", "http://notify.test/object", nil)
		r.RequestURI = r.URL.RequestURI()
		rec := httptest.NewRecorder()
		waf.ServeHTTP(rec, r)
		if rec.Code != 200 || rec.Body.String() != body || rec.Header().Get("X-Cache") != want || len(rec.Header().Values("X-Cache")) != 1 {
			t.Fatalf("step %d status=%d body=%q cache=%v", i, rec.Code, rec.Body.String(), rec.Header().Values("X-Cache"))
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("origin requests=%d", calls.Load())
	}
}

// TestTieredCacheDoesNotCachePOSTOrTruncateForwardedUpload 确认开启缓存不改变上传正文，POST 始终绕过缓存。
func TestTieredCacheDoesNotCachePOSTOrTruncateForwardedUpload(t *testing.T) {
	newNotifyClassificationQueues(t)
	previousDesensitize := global.GCONFIG_RECORD_LOG_DESENSITIZE
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 0
	t.Cleanup(func() { global.GCONFIG_RECORD_LOG_DESENSITIZE = previousDesensitize })
	payload := strings.Repeat("upload", 400000)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil || string(b) != payload {
			t.Error("upload changed before origin")
		}
		w.Header().Set("Content-Length", "2")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("ok"))
	}))
	defer origin.Close()
	cfg := model.CacheConfig{IsEnableCache: 1, CacheLocation: "tiered", CacheDir: t.TempDir()}
	encoded, _ := json.Marshal(cfg)
	waf := newNotifyClassificationEngine(t, model.HostsDefense{})
	waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
		h.PathRules = nil
		h.TargetHost = origin.URL
		h.Host.IsEnableResponseBuffering = 1
		h.Host.CacheJSON = string(encoded)
		h.CacheRule = []model.CacheRule{{RuleType: 2, RuleContent: "/", ParamType: 1, CacheTime: 60}}
	})
	r := httptest.NewRequest("POST", "http://notify.test/upload", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	waf.ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Body.String() != "ok" || rec.Header().Get("X-Cache") != "BYPASS" {
		t.Fatalf("upload status=%d cache=%q body=%q", rec.Code, rec.Header().Get("X-Cache"), rec.Body.String())
	}
}
