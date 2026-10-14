package wafenginecore

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"SamWaf/cache"
	"SamWaf/common/queue"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
)

// 本文件是 CC 封禁拦截链路的 HTTP 级用例：真实走 ServeHTTP 全链路
// （路由解析 → 流量计量 → CC 封禁命中 → 拦截页渲染 → 窄行入队 → 提醒节流），
// 验证「拦截页展示的识别码/IP 与落库窄行一一对应」这一 #1001 修复的核心承诺。

var ccBanPageUUIDRe = regexp.MustCompile(`访问识别码：([0-9a-fA-F-]{36})`)

// hijackRecorder 让 httptest 记录器具备 Hijack 能力，用于覆盖 444 关闭连接分支。
type hijackRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	h.conn = server
	go func() { _, _ = bufio.NewReader(client).ReadString(0) }()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

// setupCCBanEngine 搭一套可跑 ServeHTTP 的最小引擎：站点 + 全局网站 + 封禁键 + 空队列。
// 返回的清理函数恢复被替换的全局对象。
func setupCCBanEngine(t *testing.T, banIP string, mutateSite func(h *wafenginmodel.HostSafe)) (*WafEngine, func()) {
	t.Helper()

	waf := &WafEngine{}
	waf.InitRouting()
	waf.ServerOnline = wafenginmodel.NewSafeServerMap()

	site := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Code:         "ccb-code",
			Host:         "ccb-test.com",
			Port:         80,
			GUARD_STATUS: 1,
			IPSourceMode: "nic",
		},
		BlockingPage:       map[string]model.BlockingPage{},
		RuleData:           []model.Rules{},
		IPBlockLists:       []model.IPBlockList{},
		LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{},
	}
	if mutateSite != nil {
		mutateSite(site)
	}
	globalHost := &wafenginmodel.HostSafe{
		Host:               model.Hosts{Code: global.GWAF_GLOBAL_HOST_CODE},
		BlockingPage:       map[string]model.BlockingPage{},
		RuleData:           []model.Rules{},
		IPBlockLists:       []model.IPBlockList{},
		LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{},
	}
	waf.withWriteTable(func(nt *routingTable) {
		nt.HostTarget["ccb-test.com:80"] = site
		nt.HostCode["ccb-code"] = "ccb-test.com:80"
		nt.HostTarget["global:80"] = globalHost
		nt.HostCode[global.GWAF_GLOBAL_HOST_CODE] = "global:80"
	})

	oldCache, oldLogQ, oldMsgQ := global.GCACHE_WAFCACHE, global.GQEQUE_LOG_DB, global.GQEQUE_MESSAGE_DB
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	global.GQEQUE_LOG_DB = queue.NewQueue()
	global.GQEQUE_MESSAGE_DB = queue.NewQueue()

	banKey := model.BuildCCBanKey(model.CCBanScopeHost, "ccb-code", banIP)
	global.GCACHE_WAFCACHE.SetWithTTl(banKey, 300, 10*time.Minute)

	return waf, func() {
		global.GCACHE_WAFCACHE = oldCache
		global.GQEQUE_LOG_DB = oldLogQ
		global.GQEQUE_MESSAGE_DB = oldMsgQ
	}
}

func doCCBanRequest(waf *WafEngine, w http.ResponseWriter, path string) *http.Request {
	req := httptest.NewRequest("GET", "http://ccb-test.com"+path, nil)
	req.RemoteAddr = "10.1.2.3:40001"
	waf.ServeHTTP(w, req)
	return req
}

// 封禁期每次请求：拦截页给新的识别码且展示访客 IP，每个识别码对应一条窄行落库。
// 这正是 #1001 的验收口径——页面上看到的识别码必须能在日志里查到。
func TestCCBanServeHTTP_PageIdMatchesNarrowLog(t *testing.T) {
	waf, cleanup := setupCCBanEngine(t, "10.1.2.3", nil)
	defer cleanup()

	const n = 3
	pageUUIDs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		doCCBanRequest(waf, rec, fmt.Sprintf("/ccban?page=%d", i))
		if rec.Code != 403 {
			t.Fatalf("第 %d 次请求应返回 403，实际 %d", i, rec.Code)
		}
		body := rec.Body.String()
		m := ccBanPageUUIDRe.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("拦截页缺少访问识别码：%s", body[:min(200, len(body))])
		}
		if body != "" && !containsAll(body, "您的 IP：10.1.2.3") {
			t.Fatalf("拦截页应展示访客 IP 10.1.2.3")
		}
		pageUUIDs = append(pageUUIDs, m[1])
	}
	for i := 1; i < n; i++ {
		if pageUUIDs[i] == pageUUIDs[0] {
			t.Fatalf("每次请求的识别码应独立生成，第 %d 次与第 0 次相同", i)
		}
	}

	if got := global.GQEQUE_LOG_DB.Size(); got != n {
		t.Fatalf("应入队 %d 条窄行，实际 %d", n, got)
	}
	for i := 0; i < n; i++ {
		v, ok := global.GQEQUE_LOG_DB.Dequeue()
		if !ok {
			t.Fatalf("第 %d 条窄行取不到", i)
		}
		lg, ok := v.(*innerbean.WebLog)
		if !ok {
			t.Fatalf("入队对象类型不对: %T", v)
		}
		if lg.REQ_UUID != pageUUIDs[i] {
			t.Fatalf("第 %d 条窄行识别码 %s 与页面展示的 %s 不一致", i, lg.REQ_UUID, pageUUIDs[i])
		}
		if lg.RULE != "CC封禁" || lg.ACTION != "阻止" || lg.STATUS != "阻止访问" || lg.STATUS_CODE != 403 {
			t.Fatalf("第 %d 条窄行归因不对: rule=%q action=%q status=%q code=%d", i, lg.RULE, lg.ACTION, lg.STATUS, lg.STATUS_CODE)
		}
		if !lg.SkipPayloadStore {
			t.Fatalf("第 %d 条窄行应标记跳过重报文留存", i)
		}
		if lg.HEADER != "" || lg.BODY != "" || lg.COOKIES != "" || lg.SrcByteBody != nil || lg.SrcURL != nil {
			t.Fatalf("第 %d 条窄行应只留元数据，实际 HEADER=%d 字节 BODY=%d 字节", i, len(lg.HEADER), len(lg.BODY))
		}
		if lg.SRC_IP != "10.1.2.3" {
			t.Fatalf("第 %d 条窄行来源 IP 应为 10.1.2.3，实际 %q", i, lg.SRC_IP)
		}
	}
}

// 站点给 cc_attack 配了自定义拦截页时：响应码以页面配置为准，窄行记录实际下发的码。
// 444（关闭连接）在可劫持的真实连接上生效，且窄行状态写明「连接关闭」。
func TestCCBanServeHTTP_CustomStatusAnd444(t *testing.T) {
	mkPage := func(code string) func(h *wafenginmodel.HostSafe) {
		return func(h *wafenginmodel.HostSafe) {
			h.BlockingPage = map[string]model.BlockingPage{
				"cc_attack": {AttackType: "cc_attack", ResponseCode: code, ResponseContent: "CC BANNED [[.SAMWAF_REQ_UUID]] [[.SAMWAF_IP]]"},
			}
		}
	}
	// 两个子场景各建一套引擎；任一 t.Fatalf 都要把全局替换恢复掉，不能泄漏给同包后续用例
	cleanups := []func(){}
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()
	setup := func(ip string, mutate func(h *wafenginmodel.HostSafe)) *WafEngine {
		waf, cleanup := setupCCBanEngine(t, ip, mutate)
		cleanups = append(cleanups, cleanup)
		return waf
	}
	dequeueLog := func(tag string) *innerbean.WebLog {
		v, ok := global.GQEQUE_LOG_DB.Dequeue()
		if !ok {
			t.Fatalf("%s 应有一条窄行入队", tag)
		}
		lg, ok := v.(*innerbean.WebLog)
		if !ok {
			t.Fatalf("%s 入队对象类型不对: %T", tag, v)
		}
		return lg
	}

	// 429 自定义码
	waf := setup("10.1.2.3", mkPage("429"))
	rec := httptest.NewRecorder()
	doCCBanRequest(waf, rec, "/ccban")
	if rec.Code != 429 {
		t.Fatalf("自定义拦截页 429 应原样下发，实际 %d", rec.Code)
	}
	if !containsAll(rec.Body.String(), "CC BANNED", "10.1.2.3") {
		t.Fatalf("自定义拦截页应渲染识别码与 IP 变量: %s", rec.Body.String())
	}
	lg := dequeueLog("429")
	if lg.STATUS_CODE != 429 || lg.RULE != "CC封禁" {
		t.Fatalf("窄行应记录实际下发的 429，实际 code=%d rule=%q", lg.STATUS_CODE, lg.RULE)
	}

	// 444 关闭连接（用可劫持的记录器模拟真实连接）
	waf = setup("10.1.2.3", mkPage("444"))
	hj := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	doCCBanRequest(waf, hj, "/ccban")
	if hj.Body.Len() != 0 {
		t.Fatalf("444 分支不应写出任何响应体，实际 %d 字节", hj.Body.Len())
	}
	lg = dequeueLog("444")
	if lg.STATUS_CODE != 444 || lg.STATUS != "连接关闭" {
		t.Fatalf("444 窄行应写明连接关闭，实际 code=%d status=%q", lg.STATUS_CODE, lg.STATUS)
	}
}

// 封禁期内持续重试不会刷爆提醒队列：同一封禁键只推一条。
func TestCCBanServeHTTP_NotifyThrottled(t *testing.T) {
	waf, cleanup := setupCCBanEngine(t, "10.1.2.3", nil)
	defer cleanup()

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		doCCBanRequest(waf, rec, "/ccban")
	}
	if got := global.GQEQUE_MESSAGE_DB.Size(); got != 1 {
		t.Fatalf("同一封禁键 5 次请求应只推 1 条提醒，实际 %d", got)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !regexp.MustCompile(regexp.QuoteMeta(sub)).MatchString(s) {
			return false
		}
	}
	return true
}
