package wafenginecore

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/cache"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafenginecore/ipset"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestHttpAuthPathScope 「网站密码访问」按路径开启的引擎级判定。
//
// 覆盖：include/exclude 命中与未命中、路径穿越与大小写变体、免密IP组、
// custom 登录页可达性、include 空清单 fail-closed、非法 scope 回落整站、空 JSON 回归。
//
// 正确凭证的会话记账链路（TouchBasicSession 建行）不在本文件覆盖：
// GWAF_LOCAL_DB 指向未建 session 表的库，Create 报错走「记账失败不连累访问」分支，
// 恰好验证放行；完整会话行为由 Python 验证脚本对真实实例验收。
func TestHttpAuthPathScope(t *testing.T) {
	zlog.InitZLog(false, "console")

	oldCache := global.GCACHE_WAFCACHE
	oldLogDB, oldCoreDB := global.GWAF_LOCAL_LOG_DB, global.GWAF_LOCAL_DB
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() {
		global.GCACHE_WAFCACHE = oldCache
		global.GWAF_LOCAL_LOG_DB = oldLogDB
		global.GWAF_LOCAL_DB = oldCoreDB
	}()

	// log 库：迁移审计表，被拦路径的节流审计要落这里
	// core 库：刻意不迁移，session 建行必然失败 → 走「不连累访问」分支
	dialect.Register(&dialect.SQLiteDialect{})
	dir := t.TempDir()
	open := func(name string) *gorm.DB {
		dsn := filepath.Join(dir, name) + "?_db_key=" + url.QueryEscape("ktest")
		db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatalf("sqlite 打开 %s 失败: %v", name, err)
		}
		// Windows 下不关句柄，TempDir 的 RemoveAll 会因文件占用失败
		t.Cleanup(func() {
			if s, e := db.DB(); e == nil {
				_ = s.Close()
			}
		})
		return db
	}
	logDB := open("log.db")
	if err := logDB.AutoMigrate(&model.SecurityAuditLog{}); err != nil {
		t.Fatalf("迁移审计表失败: %v", err)
	}
	global.GWAF_LOCAL_LOG_DB = logDB
	global.GWAF_LOCAL_DB = open("core-nomigrate.db")

	// 免密IP组：注册一个含 10.1.1.1 的组，组不存在/被删的场景用未注册 code 表达
	ipset.UpsertGroupMatcher("g_test", "测试组", ipset.BuildMatchSet([]string{"10.1.1.1"}))
	defer ipset.SetGroupSnapshot(nil)

	waf := &WafEngine{}
	newHost := func(authJSON, authType string) *wafenginmodel.HostSafe {
		h := &wafenginmodel.HostSafe{}
		h.Host.Code = "hs_scope_host"
		h.Host.Host = "test.example.com"
		h.Host.IsEnableHttpAuthBase = 1
		h.Host.HttpAuthBaseType = authType
		h.Host.HttpAuthJSON = authJSON
		h.HttpAuthBases = []model.HttpAuthBase{{UserName: "u", Password: "p"}}
		return h
	}
	// run 发一个请求并返回 (是否被这道门接住, 响应记录器)
	run := func(host *wafenginmodel.HostSafe, target string, clientIP string, hdr map[string]string) (bool, *httptest.ResponseRecorder) {
		r := httptest.NewRequest(http.MethodGet, "http://test.example.com"+target, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		res := waf.DoHttpAuthBase(host, w, r, clientIP)
		return res.Blocked, w
	}
	basic := func(u, p string) map[string]string {
		return map[string]string{"Authorization": "Basic " + b64(u+":"+p)}
	}

	cases := []struct {
		name    string
		json    string
		authTyp string
		target  string
		clientIP string
		hdr     map[string]string
		blocked bool
	}{
		// —— 回归：空 JSON / 缺省 scope 一律整站 ——
		{"空JSON整站拦", ``, "", "/anything", "8.8.8.8", nil, true},
		{"显式all整站拦", `{"path_scope":"all"}`, "", "/anything", "8.8.8.8", nil, true},
		{"非法scope回落整站拦", `{"path_scope":"only"}`, "", "/anything", "8.8.8.8", nil, true},

		// —— include：仅命中清单的路径要密码 ——
		{"include命中拦", `{"path_scope":"include","paths":"/admin"}`, "", "/admin", "8.8.8.8", nil, true},
		{"include子路径拦", `{"path_scope":"include","paths":"/admin"}`, "", "/admin/login", "8.8.8.8", nil, true},
		{"include范围外直通", `{"path_scope":"include","paths":"/admin"}`, "", "/public/index", "8.8.8.8", nil, false},
		{"include段边界不误伤", `{"path_scope":"include","paths":"/admin"}`, "", "/adminconsole", "8.8.8.8", nil, false},
		{"include通配命中拦", `{"path_scope":"include","paths":"*.php"}`, "", "/dir/a.php", "8.8.8.8", nil, true},
		{"include通配未命中直通", `{"path_scope":"include","paths":"*.php"}`, "", "/dir/a.html", "8.8.8.8", nil, false},
		{"include多行逗号混合", `{"path_scope":"include","paths":"/a,/b\n/c"}`, "", "/c/x", "8.8.8.8", nil, true},

		// —— 安全核心：归一化防穿越 ——
		{"穿越变体必须拦", `{"path_scope":"include","paths":"/admin"}`, "", "/x/../admin", "8.8.8.8", nil, true},
		{"点号段进子路径必须拦", `{"path_scope":"include","paths":"/admin"}`, "", "/admin/../admin/panel", "8.8.8.8", nil, true},
		{"编码变体必须拦", `{"path_scope":"include","paths":"/admin"}`, "", "/%41dmin", "8.8.8.8", nil, true},
		{"大写路径必须拦", `{"path_scope":"include","paths":"/admin"}`, "", "/ADMIN/console", "8.8.8.8", nil, true},
		{"双斜杠变体必须拦", `{"path_scope":"include","paths":"/admin"}`, "", "//admin", "8.8.8.8", nil, true},
		{"点号尾巴必须拦", `{"path_scope":"include","paths":"/admin"}`, "", "/admin/.", "8.8.8.8", nil, true},
		{"归一到根则不拦", `{"path_scope":"include","paths":"/admin"}`, "", "/x/..", "8.8.8.8", nil, false},

		// —— exclude：除清单外全站要密码 ——
		{"exclude命中放行", `{"path_scope":"exclude","paths":"/public"}`, "", "/public/x", "8.8.8.8", nil, false},
		{"exclude未命中拦", `{"path_scope":"exclude","paths":"/public"}`, "", "/admin", "8.8.8.8", nil, true},
		{"exclude空清单=整站", `{"path_scope":"exclude","paths":""}`, "", "/anything", "8.8.8.8", nil, true},

		// —— fail-closed：include 空清单按整站 ——
		{"include空清单按整站拦", `{"path_scope":"include","paths":""}`, "", "/anything", "8.8.8.8", nil, true},

		// —— 免密IP组 ——
		{"免密组命中直通", `{"path_scope":"all","bypass_ip_group":"g_test"}`, "", "/admin", "10.1.1.1", nil, false},
		{"免密组未命中仍拦", `{"path_scope":"all","bypass_ip_group":"g_test"}`, "", "/admin", "10.2.2.2", nil, true},
		{"免密组不存在回落拦", `{"path_scope":"all","bypass_ip_group":"g_missing"}`, "", "/admin", "10.1.1.1", nil, true},

		// —— 凭证与范围的组合 ——
		{"include外带错凭证也直通(不验凭证)", `{"path_scope":"include","paths":"/admin"}`, "", "/public", "8.8.8.8", basic("u", "wrong"), false},
		{"include内对凭证放行", `{"path_scope":"include","paths":"/admin"}`, "", "/admin", "8.8.8.8", basic("u", "p"), false},

		// —— custom 模式：登录页端点无条件可达 ——
		{"custom+include登录页可达", `{"path_scope":"include","paths":"/admin"}`, model.HttpAuthTypeCustom, "/samwaf_httpauth/validate", "8.8.8.8", nil, true},
		{"custom+include受保护路径拦", `{"path_scope":"include","paths":"/admin"}`, model.HttpAuthTypeCustom, "/admin", "8.8.8.8", nil, true},
		{"custom+include范围外直通", `{"path_scope":"include","paths":"/admin"}`, model.HttpAuthTypeCustom, "/public", "8.8.8.8", nil, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host := newHost(c.json, c.authTyp)
			blocked, rec := run(host, c.target, c.clientIP, c.hdr)
			if blocked != c.blocked {
				t.Fatalf("blocked = %v, 期望 %v (status=%d body=%.120s)", blocked, c.blocked, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestHttpAuthLogAttribution 这道门拦下请求时，得同时交出「哪道门」和「回了什么状态码」。
//
// 访问日志的「触发规则」与「状态码」两列都取自这里：规则名用于按规则筛，
// 状态码必须与实际下发给客户端的一致（登录页 200 与 未登录 401 在日志里要能分开）。
//
// 反向验证：把 httpAuthRuleName 改回空串、或让 DoHttpAuthBase 不再回传状态码，本用例会红。
func TestHttpAuthLogAttribution(t *testing.T) {
	zlog.InitZLog(false, "console")

	oldCache := global.GCACHE_WAFCACHE
	oldLogDB, oldCoreDB := global.GWAF_LOCAL_LOG_DB, global.GWAF_LOCAL_DB
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() {
		global.GCACHE_WAFCACHE = oldCache
		global.GWAF_LOCAL_LOG_DB = oldLogDB
		global.GWAF_LOCAL_DB = oldCoreDB
	}()

	dialect.Register(&dialect.SQLiteDialect{})
	dir := t.TempDir()
	open := func(name string) *gorm.DB {
		dsn := filepath.Join(dir, name) + "?_db_key=" + url.QueryEscape("ktest")
		db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatalf("sqlite 打开 %s 失败: %v", name, err)
		}
		t.Cleanup(func() {
			if s, e := db.DB(); e == nil {
				_ = s.Close()
			}
		})
		return db
	}
	logDB := open("log.db")
	if err := logDB.AutoMigrate(&model.SecurityAuditLog{}); err != nil {
		t.Fatalf("迁移审计表失败: %v", err)
	}
	global.GWAF_LOCAL_LOG_DB = logDB
	global.GWAF_LOCAL_DB = open("core-nomigrate.db")

	waf := &WafEngine{}
	newHost := func(authType string) *wafenginmodel.HostSafe {
		h := &wafenginmodel.HostSafe{}
		h.Host.Code = "hs_log_host"
		h.Host.Host = "test.example.com"
		h.Host.IsEnableHttpAuthBase = 1
		h.Host.HttpAuthBaseType = authType
		h.Host.HttpAuthJSON = `{"path_scope":"all"}`
		h.HttpAuthBases = []model.HttpAuthBase{{UserName: "u", Password: "p"}}
		return h
	}
	do := func(host *wafenginmodel.HostSafe, method, target, body string) (httpAuthResult, *httptest.ResponseRecorder) {
		r := httptest.NewRequest(method, "http://test.example.com"+target, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		res := waf.DoHttpAuthBase(host, w, r, "8.8.8.8")
		return res, w
	}

	// Basic 模式：无凭证 → 拦，401，规则名「网站密码访问」
	basicHost := newHost("")
	res, rec := do(basicHost, http.MethodGet, "/anything", "")
	if !res.Blocked || res.Status != http.StatusUnauthorized || res.SelfServe {
		t.Fatalf("Basic 未带凭证：期望 拦截/401/非自服务，实际 %+v (status=%d)", res, rec.Code)
	}
	if res.Status != rec.Code {
		t.Fatalf("回传的状态码 %d 与实际下发的 %d 不一致：日志里的状态码必须与客户端收到的一致", res.Status, rec.Code)
	}
	if got := httpAuthRuleName(basicHost.Host); got == "" {
		t.Fatal("Basic 模式的规则名不能为空：动作列光有「禁止」是筛不出是哪道门的")
	} else if got != "网站密码访问" {
		t.Fatalf("Basic 规则名 = %q，期望 网站密码访问", got)
	}

	// Basic 模式：Authorization 头格式错 → 400
	r2 := httptest.NewRequest(http.MethodGet, "http://test.example.com/anything", nil)
	r2.Header.Set("Authorization", "Basic !!!notbase64")
	w2 := httptest.NewRecorder()
	res2 := waf.DoHttpAuthBase(basicHost, w2, r2, "8.8.8.8")
	if !res2.Blocked || res2.Status != http.StatusBadRequest {
		t.Fatalf("Basic 头部格式错：期望 拦截/400，实际 %+v (status=%d)", res2, w2.Code)
	}

	// Custom 模式：未认证访问业务路径 → 回登录页（200），不是 401
	customHost := newHost(model.HttpAuthTypeCustom)
	res3, rec3 := do(customHost, http.MethodGet, "/admin", "")
	if !res3.Blocked || res3.SelfServe {
		t.Fatalf("Custom 未认证：期望 拦截/非自服务，实际 %+v (status=%d)", res3, rec3.Code)
	}
	if res3.Status != rec3.Code {
		t.Fatalf("回传的状态码 %d 与实际下发的 %d 不一致", res3.Status, rec3.Code)
	}
	if res3.Status == http.StatusUnauthorized {
		t.Fatal("Custom 未认证时回的是登录页，状态码不该是 401：日志里记 401 会让「登录页能打开」看起来像故障")
	}
	if got := httpAuthRuleName(customHost.Host); got != "网站密码访问(自定义登录页)" {
		t.Fatalf("Custom 规则名 = %q，期望 网站密码访问(自定义登录页)", got)
	}

	// Custom 模式：登录校验端点 → 属认证网关自己的端点，不能算拦截
	res4, _ := do(customHost, http.MethodPost, "/samwaf_httpauth/validate", `{"username":"u","password":"wrong"}`)
	if !res4.Blocked {
		t.Fatal("登录校验端点也应当由这道门接住（不往后端放行）")
	}
	if !res4.SelfServe {
		t.Fatal("登录校验端点必须标成自服务：否则它会按拦截记账，动作列显示成「禁止」")
	}
	if res4.Status != http.StatusUnauthorized {
		t.Fatalf("密码错误的登录校验状态码 = %d，期望 401", res4.Status)
	}
}

// TestHttpAuthPathScopeUnit 判定函数本身的补充口径（不碰 DB/审计链路）。
func TestHttpAuthPathScopeUnit(t *testing.T) {
	zlog.InitZLog(false, "console") // include 空清单的节流告警要走 zlog

	// 自定义前缀也能当自服务路径
	h := model.Hosts{HttpAuthBaseType: model.HttpAuthTypeCustom, HttpAuthPathPrefix: "/My_Auth/"}
	if got := httpAuthLoginPrefix(h); got != "/my_auth" {
		t.Fatalf("httpAuthLoginPrefix = %q, 期望 /my_auth", got)
	}
	if got := httpAuthLoginPrefix(model.Hosts{HttpAuthBaseType: ""}); got != "" {
		t.Fatalf("非 custom 模式应返回空串, 实际 %q", got)
	}
	// include 清单全是空白条目 = 空清单，必须按整站保护
	if !httpAuthPathInScope(model.HttpAuthConfig{PathScope: model.HttpAuthScopeInclude, Paths: "  ,,\n "}, "/x") {
		t.Fatal("include 空白清单必须按整站保护")
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
