package wafwebcache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
)

// tierEnv 创建隔离的站点和磁盘目录，结束时撤销注册表引用，避免后台管理重建已清理目录。
func tierEnv(t *testing.T) (*wafenginmodel.HostSafe, model.CacheConfig) {
	t.Helper()
	h := &wafenginmodel.HostSafe{Host: model.Hosts{Code: t.Name(), Host: "site.test", IsEnableResponseBuffering: 1}, CacheRule: []model.CacheRule{{RuleName: "public", RuleType: 2, RuleContent: "/", ParamType: 1, CacheTime: 60, RequestMethod: "GET;HEAD"}}}
	c := model.CacheConfig{IsEnableCache: 1, CacheLocation: "tiered", CacheDir: t.TempDir(), L1CapacityMB: 1, L2CapacityMB: 8, MaxMemorySizeMB: 0.25, MaxFileSizeMB: 2, HeatThreshold: 3}
	t.Cleanup(func() {
		registry.Lock()
		for k, v := range registry.views {
			if k.host.Host.Code == h.Host.Code {
				delete(registry.views, k)
				delete(registry.stores, v.scope)
			}
		}
		registry.Unlock()
	})
	return h, c
}

// tierRequest 使用真实服务端形式的 RequestURI，避免 httptest 的绝对目标影响缓存身份测试。
func tierRequest(path string) *http.Request {
	r := httptest.NewRequest("GET", "http://site.test"+path, nil)
	r.RequestURI = r.URL.RequestURI()
	return r
}

// tierResponse 构造已知长度响应并复制头，确保用例不会因共用 Header 误改彼此的源站策略。
func tierResponse(r *http.Request, status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	} else {
		header = header.Clone()
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r}
}

// exchange 串起入口、响应填充、完整读体和收尾，模拟代理对缓存接口的生命周期约定。
func exchange(t *testing.T, h *wafenginmodel.HostSafe, c model.CacheConfig, r *http.Request, origin func(*http.Request) *http.Response) (string, http.Header, int) {
	t.Helper()
	defer FinishRequest(r)
	w := httptest.NewRecorder()
	resp := LoadWebDataFormCache(w, r, h, c, &innerbean.WebLog{})
	if resp == nil {
		resp = origin(r)
		StoreWebDataCache(resp, h, c, &innerbean.WebLog{})
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Cache") == "" {
		for k, v := range w.Header() {
			resp.Header[k] = v
		}
	}
	return string(body), resp.Header, resp.StatusCode
}

// TestTierColdL2ThenHotL1AndRestart 验证先提交 L2、按热度晋升及重启恢复，晋升不能改变绝对到期。
func TestTierColdL2ThenHotL1AndRestart(t *testing.T) {
	h, c := tierEnv(t)
	hits := 0
	origin := func(r *http.Request) *http.Response {
		hits++
		return tierResponse(r, 200, "public-data", http.Header{"Cache-Control": {"max-age=60"}})
	}
	layers := []string{"origin", "l2", "l2", "l1"}
	var deadline int64
	for i, want := range layers {
		body, head, status := exchange(t, h, c, tierRequest("/asset"), origin)
		if body != "public-data" || status != 200 || head.Get("X-Cache-Layer") != want {
			t.Fatalf("request %d: body=%q status=%d layer=%q want=%q", i, body, status, head.Get("X-Cache-Layer"), want)
		}
		v := viewFor(h, c)
		base := baseKey(tierRequest("/asset"), v.revision)
		e, f, _ := v.disk.lookup(base, nil)
		if f == nil {
			t.Fatal("L2 missing")
		}
		f.Close()
		if deadline == 0 {
			deadline = e.meta.Expires
		} else if deadline != e.meta.Expires {
			t.Fatal("promotion renewed TTL")
		}
	}
	if hits != 1 {
		t.Fatalf("origin reads=%d", hits)
	}
	v := viewFor(h, c)
	cold := newDiskCache(v.disk.root)
	base := baseKey(tierRequest("/asset"), v.revision)
	e, f, offset := cold.lookup(base, nil)
	if f == nil {
		t.Fatal("restart could not reload L2")
	}
	defer f.Close()
	b, err := io.ReadAll(io.NewSectionReader(f, offset, e.meta.Size))
	if err != nil || string(b) != "public-data" || e.meta.Expires != deadline {
		t.Fatalf("restart data=%q err=%v", b, err)
	}
}

// TestTierVaryAndQueryIsolation 交错查询串和语言，验证变体互不串用且重复请求不多次回源。
func TestTierVaryAndQueryIsolation(t *testing.T) {
	h, c := tierEnv(t)
	hits := 0
	origin := func(r *http.Request) *http.Response {
		hits++
		return tierResponse(r, 200, r.URL.RawQuery+"/"+r.Header.Get("Accept-Language"), http.Header{"Vary": {"Accept-Language"}})
	}
	for _, query := range []string{"v=1", "v=2"} {
		for _, language := range []string{"en", "zh"} {
			for i := 0; i < 2; i++ {
				r := tierRequest("/asset?" + query)
				r.Header.Set("Accept-Language", language)
				body, _, _ := exchange(t, h, c, r, origin)
				if body != query+"/"+language {
					t.Fatalf("variant mixed: %q", body)
				}
			}
		}
	}
	if hits != 4 {
		t.Fatalf("origin reads=%d, want 4", hits)
	}
}

// TestTierPrivateAndUnsafeRequestsBypassWarmObject 先预热匿名对象，再确认带凭据/正文请求仍真实回源。
func TestTierPrivateAndUnsafeRequestsBypassWarmObject(t *testing.T) {
	h, c := tierEnv(t)
	hits := 0
	origin := func(r *http.Request) *http.Response { hits++; return tierResponse(r, 200, fmt.Sprint(hits), nil) }
	exchange(t, h, c, tierRequest("/asset"), origin)
	for _, header := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-API-Key", "Api-Key", "Upgrade", "Range", "If-Range", "X-SamWaf-Access-User"} {
		r := tierRequest("/asset")
		r.Header[header] = []string{"synthetic"}
		_, head, _ := exchange(t, h, c, r, origin)
		if head.Get("X-Cache") != "BYPASS" {
			t.Fatalf("%s did not bypass", header)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		r := tierRequest("/asset")
		r.Method = method
		r.Body = io.NopCloser(strings.NewReader("synthetic"))
		r.ContentLength = 9
		_, head, _ := exchange(t, h, c, r, origin)
		if head.Get("X-Cache") != "BYPASS" {
			t.Fatalf("%s did not bypass", method)
		}
	}
	if hits != 14 {
		t.Fatalf("origin reads=%d", hits)
	}
}

// TestTierUncacheableResponsesNeverPublish 验证私有头、流式类型和不可隔离的表示不能成为后续 HIT。
func TestTierUncacheableResponsesNeverPublish(t *testing.T) {
	for _, headers := range []http.Header{
		{"Cache-Control": {"private"}}, {"Cache-Control": {"no-store"}}, {"Cache-Control": {"public", "no-cache"}}, {"Set-Cookie": {"synthetic=value"}}, {"Vary": {"*"}}, {"Content-Range": {"bytes 0-1/10"}}, {"Content-Type": {"text/event-stream"}}, {"Cache-Control": {"max-age=0"}},
	} {
		t.Run(fmt.Sprint(headers), func(t *testing.T) {
			h, c := tierEnv(t)
			hits := 0
			origin := func(r *http.Request) *http.Response { hits++; return tierResponse(r, 200, "x", headers) }
			exchange(t, h, c, tierRequest("/"), origin)
			exchange(t, h, c, tierRequest("/"), origin)
			if hits != 2 {
				t.Fatal("private/unsupported response was cached")
			}
		})
	}
}

// TestTierRuleZeroAndConfigurationRevision 防止零 TTL 被当作长期缓存，以及配置改变继续读取旧对象。
func TestTierRuleZeroAndConfigurationRevision(t *testing.T) {
	h, c := tierEnv(t)
	hits := 0
	origin := func(r *http.Request) *http.Response { hits++; return tierResponse(r, 200, fmt.Sprint(hits), nil) }
	exchange(t, h, c, tierRequest("/"), origin)
	updated := *h
	updated.CacheRule = append([]model.CacheRule(nil), h.CacheRule...)
	updated.CacheRule[0].CacheTime = 0
	_, head, _ := exchange(t, &updated, c, tierRequest("/"), origin)
	if head.Get("X-Cache") != "BYPASS" {
		t.Fatal("zero TTL did not bypass")
	}
	updated.CacheRule = append([]model.CacheRule(nil), h.CacheRule...)
	updated.CacheRule[0].CacheTime = 30
	body, _, _ := exchange(t, &updated, c, tierRequest("/"), origin)
	if body != "3" {
		t.Fatalf("old configuration object reused: %q", body)
	}
	c.MaxMemorySizeMB = 0.01
	body, _, _ = exchange(t, h, c, tierRequest("/"), origin)
	if body != "4" {
		t.Fatalf("changed limits reused old namespace: %q", body)
	}
}

// countedBody 观察实际读取量，用于区分「只安装流式填充」和「缓存入口提前抽干正文」。
type countedBody struct {
	r io.Reader
	n int
}

// Read 保留底层 Reader 的短读和错误行为，只额外累计被消费的字节数。
func (b *countedBody) Read(p []byte) (int, error) { n, e := b.r.Read(p); b.n += n; return n, e }

// Close 不额外消费正文，以便测试提前关闭是否确实回滚。
func (b *countedBody) Close() error { return nil }

// TestTierStreamingAdmissionAndIncompleteBodies 验证准入不提前读体，超限、未知长度、截断和取消不发布。
func TestTierStreamingAdmissionAndIncompleteBodies(t *testing.T) {
	for _, mode := range []string{"large", "unknown", "partial", "cancelled", "closed"} {
		t.Run(mode, func(t *testing.T) {
			h, c := tierEnv(t)
			c.MaxFileSizeMB = 0.01
			r := tierRequest("/")
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			if got := LoadWebDataFormCache(nil, r, h, c, &innerbean.WebLog{}); got != nil {
				t.Fatal("unexpected hit")
			}
			defer FinishRequest(r)
			body := &countedBody{r: strings.NewReader(strings.Repeat("x", 4096))}
			resp := tierResponse(r, 200, "", nil)
			resp.Body = body
			resp.ContentLength = 4096
			switch mode {
			case "large":
				resp.ContentLength = 1 << 20
			case "unknown":
				resp.ContentLength = -1
			case "partial":
				resp.ContentLength = 8192
			}
			StoreWebDataCache(resp, h, c, &innerbean.WebLog{})
			if body.n != 0 {
				t.Fatal("cache eagerly drained upstream response")
			}
			if mode == "cancelled" {
				cancel()
			}
			if mode != "closed" {
				_, _ = io.Copy(io.Discard, resp.Body)
			}
			resp.Body.Close()
			v := viewFor(h, c)
			e, f, _ := v.disk.lookup(baseKey(r, v.revision), r.Header)
			if f != nil {
				f.Close()
			}
			if e != nil {
				t.Fatal("incomplete/unsupported object published")
			}
		})
	}
}

// TestTierConcurrentFillCoalesces 同时请求同一冷对象，确认等待者复查已发布副本而非重复回源。
func TestTierConcurrentFillCoalesces(t *testing.T) {
	h, c := tierEnv(t)
	var hits atomic.Int64
	origin := func(r *http.Request) *http.Response {
		hits.Add(1)
		time.Sleep(20 * time.Millisecond)
		return tierResponse(r, 200, "once", nil)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _, _ := exchange(t, h, c, tierRequest("/shared"), origin)
			if body != "once" {
				t.Errorf("body=%q", body)
			}
		}()
	}
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("origin reads=%d", hits.Load())
	}
}

// TestTierHeadConditionalAndRevalidation 覆盖 HEAD/客户端 304 与真实源站 304 的不同正文、句柄和续期行为。
func TestTierHeadConditionalAndRevalidation(t *testing.T) {
	h, c := tierEnv(t)
	calls := 0
	origin := func(r *http.Request) *http.Response {
		calls++
		if r.Header.Get("If-None-Match") == `"v1"` {
			return tierResponse(r, 304, "", nil)
		}
		return tierResponse(r, 200, "version one", http.Header{"ETag": {`"v1"`}})
	}
	exchange(t, h, c, tierRequest("/"), origin)
	r := tierRequest("/")
	r.Method = "HEAD"
	body, head, status := exchange(t, h, c, r, origin)
	if body != "" || status != 200 || head.Get("Content-Length") != "11" {
		t.Fatal("HEAD did not share GET metadata")
	}
	r = tierRequest("/")
	r.Header.Set("If-None-Match", `"v1"`)
	body, _, status = exchange(t, h, c, r, origin)
	if body != "" || status != 304 {
		t.Fatal("conditional cache hit did not return 304")
	}
	v := viewFor(h, c)
	base := baseKey(r, v.revision)
	v.disk.mu.Lock()
	e := v.disk.entries[variantKey(base, nil, nil)]
	e.meta.Expires = time.Now().Add(-time.Second).UnixNano()
	e.meta.Stored = time.Now().Add(-time.Minute).UnixNano()
	m := e.meta
	v.disk.mu.Unlock()
	// Replace the complete file through the normal atomic writer, then expire
	// it on disk without sleeping for an entire configured TTL.
	m.Expires = time.Now().Add(100 * time.Millisecond).UnixNano()
	m.Stored = time.Now().Add(-time.Minute).UnixNano()
	w, err := v.disk.begin(context.Background(), m, v.settings)
	if err != nil {
		t.Fatal(err)
	}
	w.file.Write([]byte("version one"))
	w.finish(true)
	processMemory.purge(base)
	time.Sleep(120 * time.Millisecond)
	body, head, status = exchange(t, h, c, tierRequest("/"), origin)
	if status != 200 || body != "version one" || head.Get("X-Cache") != "REVALIDATED" {
		t.Fatalf("304 conversion status=%d body=%q headers=%v", status, body, head)
	}
	exchange(t, h, c, tierRequest("/"), origin)
	if calls != 2 {
		t.Fatalf("304 renewal did not become a fresh hit: calls=%d", calls)
	}
}

// TestTierMemoryAndDiskQuotas 校验带条目开销的 L1 预算及包含临时预留的 L2 字节预算。
func TestTierMemoryAndDiskQuotas(t *testing.T) {
	memory := newMemoryCache(6000)
	now := time.Now()
	body := bytes.Repeat([]byte("x"), 2000)
	for i := 0; i < 5; i++ {
		base := hashFields(fmt.Sprint(i))
		m := metadata{Base: base, Key: variantKey(base, nil, nil), Header: make(http.Header), Size: 2000, Stored: now.UnixNano(), Expires: now.Add(time.Minute).UnixNano()}
		memory.put("site", 5000, m, body)
	}
	used, count := memory.usage()
	if used > 5000 || count != 2 {
		t.Fatalf("L1 used=%d count=%d", used, count)
	}
	h, c := tierEnv(t)
	c.L2CapacityMB = 0.01
	c.MaxFileSizeMB = 0.005
	for i := 0; i < 8; i++ {
		exchange(t, h, c, tierRequest(fmt.Sprintf("/%d", i)), func(r *http.Request) *http.Response { return tierResponse(r, 200, strings.Repeat("x", 2000), nil) })
	}
	v := viewFor(h, c)
	v.disk.mu.Lock()
	used = v.disk.used + v.disk.temps
	v.disk.mu.Unlock()
	if used > normalize(c).L2Bytes {
		t.Fatalf("L2 over quota: %d", used)
	}
}

// TestTierCorruptDiskObjectRejected 截断已发布文件，确认长度校验会拒绝把损坏对象返回给客户端。
func TestTierCorruptDiskObjectRejected(t *testing.T) {
	h, c := tierEnv(t)
	origin := func(r *http.Request) *http.Response { return tierResponse(r, 200, "body", nil) }
	exchange(t, h, c, tierRequest("/"), origin)
	v := viewFor(h, c)
	base := baseKey(tierRequest("/"), v.revision)
	e, f, _ := v.disk.lookup(base, nil)
	f.Close()
	if err := os.Truncate(e.path, 15); err != nil {
		t.Fatal(err)
	}
	e, f, _ = v.disk.lookup(base, nil)
	if f != nil {
		f.Close()
	}
	if e != nil {
		t.Fatal("truncated file was served")
	}
}

// TestTierFreshnessUpperBounds 校验源站头只能缩短规则 TTL，并扣除源站年龄和已过期 Expires。
func TestTierFreshnessUpperBounds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		header http.Header
		max    time.Duration
		ok     bool
	}{
		{http.Header{"Cache-Control": {"max-age=600"}}, 30 * time.Second, true},
		{http.Header{"Cache-Control": {"s-maxage=5, max-age=600"}}, 5 * time.Second, true},
		{http.Header{"Cache-Control": {"max-age=10"}, "Age": {"9"}}, time.Second, true},
		{http.Header{"Cache-Control": {"max-age=10"}, "Age": {"11"}}, 0, false},
		{http.Header{"Expires": {now.Add(-time.Second).Format(http.TimeFormat)}}, 0, false},
	} {
		expiry, ok := freshUntil(tc.header, 30, now)
		if ok != tc.ok || ok && expiry.Sub(now) > tc.max {
			t.Fatalf("headers=%v expiry=%v ok=%v", tc.header, expiry, ok)
		}
	}
}
