package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafenginecore/accessgate"
	"SamWaf/wafenginecore/ipset"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"
)

// access_gate.go 是「统一访问认证(Access 模式)」的请求侧入口，对标 Cloudflare Access。
//
// 与已有的「网站密码访问」(DoHttpAuthBase，wafworker.go:558) 的区别：
//   - 那个是按站点的：账号挂在站点下、Cookie 受同源限制，访问第二个站点还要再登一次
//   - 这个是租户级的：一套账号 + 一次登录，可放行所有受保护站点（配了认证中心时）
//
// 两者可以并存，互不干扰；同时开启时先过 Access。

type accessGateAction int

const (
	accessPass    accessGateAction = iota // 放行，ServeHTTP 继续往下走
	accessHandled                         // 已自行写完响应，ServeHTTP 必须立刻 return
)

var (
	accessSessionService = waf_service.WafAccessSessionServiceApp
	accessAccountService = waf_service.WafAccessAccountServiceApp
	accessTicketService  = waf_service.WafAccessTicketServiceApp
	accessAuditService   = waf_service.WafAccessAuditServiceApp
	accessHostService    = waf_service.WafHostServiceApp
)

// accessNoCenterWarnAt 上次「开着功能却没有认证中心」告警的时间戳（秒）。
// 这条告警发生在热路径上，不节流的话每个请求都会写一行日志。
var accessNoCenterWarnAt atomic.Int64

func warnAccessNoCenter() {
	now := time.Now().Unix()
	last := accessNoCenterWarnAt.Load()
	if now-last < 300 || !accessNoCenterWarnAt.CompareAndSwap(last, now) {
		return
	}
	zlog.Warn("统一访问认证：已开启但未配置认证中心域名，本次请求放行。" +
		"请到【统一访问认证-认证配置】指定认证中心域名，否则访问控制不会生效")
}

// DoAccessGate 是访问认证的总入口。
//
// 挂载点在 ServeHTTP 里「检测链结束之后、web 缓存之前」，这个位置是被四个约束同时钉死的：
//   - 必须早于 web 缓存与静态站点服务，否则未认证的人能直接拿到缓存正文和本地文件
//   - 必须在 GUARD_STATUS 判定之外，因为「关闭防御」指的是关闭攻击检测，不该连访问控制一起关掉
//   - 必须晚于自动跳 HTTPS，先跳到 https 再种 Cookie，Secure 属性才有意义
//   - 必须晚于 CC 封禁与环路检测，别把登录页发给已经被封的 IP
//
// 同理，本网关显式不看 LogOnlyMode：仅记录模式是给攻击检测用的，
// 把访问控制静默降级成"只记录不拦截"会让用户以为站点受保护，实际却是敞开的。
func (waf *WafEngine) DoAccessGate(w http.ResponseWriter, r *http.Request,
	hostTarget *wafenginmodel.HostSafe, weblogbean *innerbean.WebLog, clientIP string) accessGateAction {

	cfg := accessgate.Get()

	// ⓪ 客户端伪造的身份头必须无条件删除，早于一切其它判定。
	//    这两个头是本模块向后端声明"当前访客是谁"的通道，一旦让客户端能自带，
	//    任何信任它的后端就等于完全没有认证——而放行路径有 6 条之多
	//    （自救开关/站点关闭/ACME/路径白名单/免认证IP组/服务令牌），
	//    只在"验票通过"那一条上清理是不够的。
	r.Header.Del("X-SamWaf-Access-User")
	r.Header.Del("X-SamWaf-Access-Session")

	// ① 自救开关最优先短路。
	//    场景：用户把管理端也反代进了 WAF 并开启 Access，配错后连管理端都进不去。
	//    此时改 conf/config.yml 的 security.access_force_disable 或设 SAMWAF_ACCESS_DISABLE=1 重启即可。
	//    这条路径刻意保持纯粹的"什么都不做"，连 Cookie 都不动。
	if cfg.ForceDisable {
		return accessPass
	}

	hostCfg := model.ParseAccessConfig(hostTarget.Host.AccessJSON)
	// path.Clean 归一化，挡住 /samwaf_access/../whatever 这类绕过前缀判定的写法。
	// 所有路径判定都必须用 p，不能用 r.URL.Path —— 后者带着未消解的 . 和 ..，
	// 而 Go 的 http.Server 对非 ServeMux 的 Handler 不做任何路径清洗。
	p := strings.ToLower(path.Clean(r.URL.Path))

	// ② 自服务分支放在 enabled 判定之前，这是刻意的：
	//    - 关掉开关后用户仍能访问 /logout 清掉残留 Cookie
	//    - 站点从「关」切到「开」的瞬间，正在登录流程中的请求不会 404
	//    - 逻辑单一，不可能出现「登录页自己被登录页挡住」的死循环
	//    代价是即使 Access 全关，该前缀也不会透传给后端。前缀可随机化，冲突概率极低。
	//    注意它在剥 Cookie 之前——这些端点自己要读 Cookie。
	if p == cfg.PathPrefix || strings.HasPrefix(p, cfg.PathPrefix+"/") {
		waf.handleAccessRequest(w, r, hostTarget, weblogbean, cfg, hostCfg, clientIP)
		return accessHandled
	}

	// 先把令牌取出来，再剥 Cookie：剥离之后请求头里就读不到它了。
	tokenCookie := accessCookieValue(r, cfg.CookieTokenName)

	// 从这里往下，任何放行都不能把本模块的 Cookie 带给后端：
	// 会话令牌是 WAF 与浏览器之间的凭据，后端记一行 access log 就等于把它写进了明文日志。
	// 统一在此处剥离，避免逐条 return 前各写一次而漏掉某一条。
	if stripAccessCookies(r, cfg) {
		// weblogbean 的 COOKIES / HEADER 是在本网关运行之前(ServeHTTP 里)就序列化好的副本，
		// 剥离 r.Header 对它们没有任何影响。不重算的话，每一个通过认证的请求
		// 都会把一条可直接复用的会话 Cookie 明文写进 web_logs ——
		// 而 web_logs 并不在 waf_sql_query 的敏感表封禁清单里，
		// 任何拿到日志读取权的人都能捞出在线用户的令牌直接冒充。
		// 不给后端看的东西，同样不该留在我们自己的日志里。
		refreshWeblogCookies(r, weblogbean)
	}

	// ③ 全局开关 + 站点三态
	if !accessgate.IsAccessEnabled(hostCfg.Mode, cfg.GlobalEnable) {
		return accessPass
	}

	// ③' 没有认证中心就没有登录入口。
	//
	// 认证中心域名是配置页的必填项，且它所在的站点被禁止删除，所以正常情况下走不到这里。
	// 能走到只剩两种：用户先打开了总开关却还没保存过配置；或者认证中心站点被改了域名。
	//
	// 此时选择放行而不是拦截：拦了就是所有站点同时 403 且没有任何地方能登录，
	// 用户只剩去管理端翻开关这一条路；放行只是这段时间里访问控制没生效，
	// 而日志里有节流告警。「配错不能把人锁在外面」是这个功能的硬约束。
	if !cfg.IsCenterMode() {
		warnAccessNoCenter()
		return accessPass
	}

	// ④ ACME 校验路径放行，且必须排在所有配置型白名单之前。
	//    漏了这一条，HTTP-01 证书签发与续期会全线失败，而这个故障要等到续期那天才暴露。
	//
	//    用归一化后的 p 判定：若用 r.URL.Path，一个
	//    /.well-known/acme-challenge/../../admin 就能命中前缀直接放行，
	//    而点号段会被原样转发给后端，后端按 RFC 3986 归一化成 /admin —— 整个网关就废了。
	if isACMEChallengePath(p, r.URL.Path) {
		return accessPass
	}

	// ⑤ 路径白名单（全局 + 站点级），给健康检查、webhook 回调这类无法登录的调用方留口子
	if accessgate.MatchPathPrefix(p, cfg.GlobalExcludePaths) ||
		accessgate.MatchPathPrefix(p, accessgate.BuildExcludePaths(hostCfg.ExcludePaths)) {
		return accessPass
	}

	// ⑥ 免认证 IP 组（复用 ip_group，改一次组所有站点同时生效）
	if groupCode := firstNonEmpty(hostCfg.AllowIPGroupCode, cfg.BypassIPGroupCode); groupCode != "" {
		// GetGroupMatcher 两层 nil 安全，返回 nil 时 ContainsStr 也安全返回 false
		if ipset.GetGroupMatcher(groupCode).ContainsStr(clientIP) {
			return accessPass
		}
	}

	// ⑦ 服务令牌头，给机器对机器的调用方用
	if waf.matchAccessServiceToken(r, cfg) {
		return accessPass
	}

	// ⑧ 验票（用剥离前取出的令牌值）
	if tokenCookie != "" {
		fingerprint := utils.GenerateFingerprint(r)
		if st := accessSessionService.ValidateToken(tokenCookie, r.Host, clientIP, fingerprint, cfg); st != nil {
			if cfg.PassIdentityHeader {
				// 顺序要紧：⓪ 已经删过客户端可能伪造的同名头，这里才是可信写入。
				// 反过来先 Set 再 Del 等于把身份头的控制权交给客户端。
				r.Header.Set("X-SamWaf-Access-User", st.AccountName)
				r.Header.Set("X-SamWaf-Access-Session", st.SessionCode)
			}
			return accessPass
		}
	}

	// ⑨ 未认证：记 weblog（保证攻击日志/仪表盘看得到）+ 节流审计
	waf.logAccessDenied(r, hostTarget, weblogbean, clientIP)

	// ⑩ 浏览器导航 302，API/WebSocket 401 JSON
	entry := waf.buildAccessEntryURL(r, cfg)
	if waf.accessShouldReturnJSON(r, cfg, hostCfg) {
		writeAccessUnauthorizedJSON(w, entry)
	} else {
		http.Redirect(w, r, entry, http.StatusFound)
	}
	return accessHandled
}

// isACMEChallengePath 已移到 acme_challenge.go：请求侧快速通道与本网关共用同一份判定，
// 免得两处各写一份、日后只改了其中一处。

// accessCookieValue 读一个 Cookie 的值，不存在返回空串。
// 必须在 stripAccessCookies 之前调用 —— 剥离之后请求头里就没有它了。
func accessCookieValue(r *http.Request, name string) string {
	if name == "" {
		return ""
	}
	if ck, err := r.Cookie(name); err == nil {
		return ck.Value
	}
	return ""
}

// stripAccessCookies 把本模块的 Cookie 从"将要转发给后端"的请求头里摘掉，
// 返回是否真的删掉了东西。
//
// 会话令牌是 WAF 与浏览器之间的凭据，没有任何理由让业务后端看到它 ——
// 后端一旦把请求头记进 access log，就等于把可直接复用的令牌写成了明文。
//
// 两个实现细节：
//   - 必须遍历 r.Header["Cookie"] 的**全部**值。HTTP/1.1 允许客户端发多行 Cookie 头，
//     而 Header.Get 只返回第一行、Header.Set 会替换全部 —— 只处理第一行等于把其余
//     几行的业务 Cookie 悄悄吃掉。(HTTP/2 与 HTTP/3 在进 handler 前已经合并成一行，
//     所以浏览器不受影响，但自己拼多行的客户端和中间代理会中招。)
//   - 没删到东西就原样不动。本函数跑在每一个通过网关的请求上，包括 Access 关闭的站点，
//     无谓地重新序列化一遍 Cookie 头既没收益，又可能改变原始写法。
func stripAccessCookies(r *http.Request, cfg *accessgate.Config) bool {
	values := r.Header["Cookie"]
	if len(values) == 0 || cfg.CookiePrefix == "" {
		return false
	}
	prefix := strings.ToLower(cfg.CookiePrefix)
	changed := false
	kept := make([]string, 0, len(values))

	for _, raw := range values {
		parts := strings.Split(raw, ";")
		keptItems := make([]string, 0, len(parts))
		for _, part := range parts {
			item := strings.TrimSpace(part)
			if item == "" {
				continue
			}
			name := item
			if idx := strings.Index(item, "="); idx >= 0 {
				name = item[:idx]
			}
			if strings.HasPrefix(strings.ToLower(name), prefix) {
				changed = true
				continue
			}
			keptItems = append(keptItems, item)
		}
		if len(keptItems) > 0 {
			kept = append(kept, strings.Join(keptItems, "; "))
		}
	}

	if !changed {
		return false
	}
	if len(kept) == 0 {
		// 整个头删掉，而不是留一个空的 Cookie 头——某些后端框架对空头处理得很怪
		r.Header.Del("Cookie")
		return true
	}
	r.Header["Cookie"] = kept
	return true
}

// refreshWeblogCookies 用剥离后的请求头重算 weblog 里的 Cookie / Header 快照。
//
// weblogbean 是在 ServeHTTP 早期就序列化好的，此后再改 r.Header 对它没有影响，
// 所以必须显式重算一次，否则会话令牌会明文落进 web_logs。
func refreshWeblogCookies(r *http.Request, weblogbean *innerbean.WebLog) {
	if weblogbean == nil {
		return
	}
	if c, err := json.Marshal(r.Cookies()); err == nil {
		weblogbean.COOKIES = string(c)
	}
	weblogbean.HEADER = joinHeader(r.Header)
}

// matchAccessServiceToken 校验服务令牌头。
// 用 subtle.ConstantTimeCompare 而不是 ==：令牌比对是可被计时攻击的经典场景。
func (waf *WafEngine) matchAccessServiceToken(r *http.Request, cfg *accessgate.Config) bool {
	if cfg.ServiceTokenHeader == "" || len(cfg.ServiceTokenHashes) == 0 {
		return false
	}
	provided := strings.TrimSpace(r.Header.Get(cfg.ServiceTokenHeader))
	if provided == "" {
		return false
	}
	sum := sha256.Sum256([]byte(provided))
	got := hex.EncodeToString(sum[:])
	for _, want := range cfg.ServiceTokenHashes {
		if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(want))) == 1 {
			return true
		}
	}
	return false
}

// accessShouldReturnJSON 判断未认证时该回 401 JSON 还是 302。
//
// WebSocket 必须是 401：WS 客户端不跟随重定向，302 会变成一个「握手莫名其妙失败」
// 的故障，排查成本极高。API/XHR 回 401 则是让前端能弹窗提示而不是把登录页塞进 JSON 解析器。
func (waf *WafEngine) accessShouldReturnJSON(r *http.Request, cfg *accessgate.Config, hostCfg model.HostAccessConfig) bool {
	action := hostCfg.UnauthAction
	if action == "" {
		action = cfg.UnauthAction
	}
	switch action {
	case model.AccessUnauth401:
		return true
	case model.AccessUnauthRedirect:
		// 强制 302 也要给 WebSocket 开口：对它来说 302 等于直接失败
		return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	}

	// auto：按请求特征判断是不是「浏览器地址栏导航」
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && !strings.EqualFold(mode, "navigate") {
		return true
	}
	if ct := r.Header.Get("Content-Type"); strings.Contains(strings.ToLower(ct), "application/json") {
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	// 只有明确接受 HTML 的 GET 才认为是能看懂登录页的导航请求
	return !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// writeAccessUnauthorizedJSON 输出 401。
// 带上 login_url 与 X-SamWaf-Access 头，前端拿到后可以自行跳转或弹窗。
func writeAccessUnauthorizedJSON(w http.ResponseWriter, loginURL string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("X-SamWaf-Access", "required")
	w.WriteHeader(http.StatusUnauthorized)
	body, _ := json.Marshal(map[string]interface{}{
		"code":      401,
		"message":   "需要登录后访问",
		"login_url": loginURL,
	})
	_, _ = w.Write(body)
}

// logAccessDenied 双写：weblog 保证仪表盘/攻击日志有数，审计表记结构化事件。
//
// weblog 里刻意不动 GUEST_IDENTIFICATION —— 未认证访客不是攻击者，
// 把他们标成攻击会污染攻击统计，让真正的攻击淹没在噪声里。
func (waf *WafEngine) logAccessDenied(r *http.Request, hostTarget *wafenginmodel.HostSafe,
	weblogbean *innerbean.WebLog, clientIP string) {

	weblogbean.RULE = "统一访问认证"
	weblogbean.ACTION = "禁止"
	weblogbean.STATUS = "302 Found"
	weblogbean.STATUS_CODE = http.StatusFound
	weblogbean.TASK_FLAG = 1
	global.GQEQUE_LOG_DB.Enqueue(weblogbean)

	accessAuditService.WriteDenied(waf_service.AuditEntry{
		Host:      r.Host,
		HostCode:  hostTarget.Host.Code,
		URL:       r.URL.RequestURI(),
		ClientIP:  clientIP,
		Country:   weblogbean.COUNTRY,
		City:      weblogbean.CITY,
		UserAgent: r.UserAgent(),
		Message:   "未认证访问被拦截",
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
