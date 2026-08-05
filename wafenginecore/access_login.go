package wafenginecore

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafenginecore/accessgate"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// access_login.go 是统一访问认证的自服务端点（登录页、校验、OTP、注销、状态）。
//
// 这些端点在 DoAccessGate 里被优先分流，且分流发生在「开关判定之前」，
// 所以它们永远可达 —— 关掉功能后用户依然能访问 /logout 清掉残留 Cookie。

// otpStageTTL OTP 两步登录的中间态有效期。
// 用户输完密码到输完动态码，5 分钟足够；再长就等于给「已知密码但没有验证器」的攻击者留窗口。
const otpStageTTL = 5 * time.Minute

// otpStage 是密码校验通过、等待动态码的中间态。
// 它只存在于缓存里，绝不下发给浏览器——浏览器拿到的只是一个随机 stage token。
type otpStage struct {
	AccountId string `json:"account_id"`
	Rq        string `json:"rq"`
	BindHost  string `json:"bind_host"`
}

// handleAccessRequest 是自服务路径的分发器。
func (waf *WafEngine) handleAccessRequest(w http.ResponseWriter, r *http.Request,
	hostTarget *wafenginmodel.HostSafe, weblogbean *innerbean.WebLog,
	cfg *accessgate.Config, hostCfg model.HostAccessConfig, clientIP string) {

	p := strings.ToLower(path.Clean(r.URL.Path))
	sub := strings.Trim(strings.TrimPrefix(p, cfg.PathPrefix), "/")

	// 自服务端点自身不参与业务日志的"拦截"统计，标成放行即可
	weblogbean.ACTION = "放行"
	weblogbean.RULE = "统一访问认证"

	// 登录只发生在认证中心域名上：业务域名上的登录页送回认证中心，校验接口直接 404。
	// 允许就地登录会退化成「每个域名各登一次」，而统一访问认证的全部意义就是不要那样。
	//
	// 没有配认证中心时这三个端点一律 404 —— 那时根本无处可登（网关也已经整体放行），
	// 给一个登不进去的登录页只会让人困惑。**尤其不能在这里 302**：
	// buildAccessEntryURL 在无认证中心时返回的正是本路径，会转成无限重定向。
	onCenter := accessOnCenter(r, cfg)
	switch {
	case sub == "" || sub == "login":
		switch {
		case onCenter:
			waf.accessServeLoginPage(w, r, cfg, r.URL.Query().Get("rq"))
		case cfg.IsCenterMode():
			http.Redirect(w, r, waf.buildAccessEntryURL(r, cfg), http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	case sub == "validate" && r.Method == http.MethodPost:
		if !onCenter {
			http.NotFound(w, r)
			return
		}
		waf.accessHandleValidate(w, r, hostTarget, cfg, hostCfg, clientIP)
	case sub == "otp" && r.Method == http.MethodPost:
		if !onCenter {
			http.NotFound(w, r)
			return
		}
		waf.accessHandleOtp(w, r, hostTarget, cfg, clientIP)
	case sub == "authorize" && r.Method == http.MethodGet:
		waf.accessHandleAuthorize(w, r, cfg, clientIP)
	case sub == "callback" && r.Method == http.MethodGet:
		waf.accessHandleCallback(w, r, hostTarget, cfg, clientIP)
	case sub == "logout":
		waf.accessHandleLogout(w, r, hostTarget, cfg, clientIP)
	case sub == "status" && r.Method == http.MethodGet:
		waf.accessHandleStatus(w, r, cfg, clientIP)
	case sub == "ping":
		// 恒 204，给用户做健康检查白名单时有个现成的探测点
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// accessOnCenter 当前请求是不是打在认证中心域名上。
//
// 认证中心是统一访问认证的唯一入口：登录、校验、OTP、签票都只在它上面发生，
// 业务域名只负责兑票和验票。这个判定被多处复用，抽出来是为了永远只有一套写法。
func accessOnCenter(r *http.Request, cfg *accessgate.Config) bool {
	return cfg.IsCenterMode() && strings.EqualFold(r.Host, cfg.CenterHost)
}

// accessTargetHostOtpMode 取「用户真正想去的那个站点」的二次验证设置。
//
// 登录只发生在认证中心上，所以此刻手里的 hostTarget 是认证中心站点。
// 直接拿它的配置去判，管理员在某个业务站点上勾的「强制二次验证」就永远不会生效——
// 界面上明明白白开着，实际一次都不要求，这类"看着开了其实没开"的安全配置最危险。
// 目标站点只从已验签的 rq 里取，取不到就退回调用方给的默认值。
//
// 一次登录一次库读，登录是低频事件，这个代价换配置语义正确是划算的。
func (waf *WafEngine) accessTargetHostOtpMode(rq string, cfg *accessgate.Config, fallback int) int {
	payload, ok := verifyAuthReq(cfg.HmacSecret, rq)
	if !ok || payload.H == "" {
		return fallback
	}
	code, ok := waf.lookupHostCode(payload.H)
	if !ok || code == "" {
		return fallback
	}
	host := accessHostService.GetDetailByCodeApi(code)
	if host.Code == "" {
		return fallback
	}
	return model.ParseAccessConfig(host.AccessJSON).RequireOtp
}

// ─────────────────────────── 登录页 ───────────────────────────

// accessServeLoginPage 渲染登录页。
//
// 模板从 data/access/login.html 读，随发布包内嵌释放（见 cmd/samwaf/main.go 的 go:embed）。
// 替换方式沿用 serveLoginPage(wafworker.go:789) 的做法：三种引号形态的路径占位各替一次。
// 用字符串替换而不是 text/template，是为了让模板本身就是一个能直接在浏览器里打开的静态页，
// 便于用户自定义。
func (waf *WafEngine) accessServeLoginPage(w http.ResponseWriter, r *http.Request,
	cfg *accessgate.Config, rq string) {

	loginPagePath := utils.GetCurrentDir() + "/data/access/login.html"
	content, err := os.ReadFile(loginPagePath)
	if err != nil {
		zlog.Warn("统一访问认证：登录页模板不可读", "path", loginPagePath, "error", err.Error())
		// 模板缺失不能让站点彻底不可用，给一个最小可用的内置回退页
		content = []byte(accessFallbackLoginHTML)
	}

	html := string(content)
	html = strings.ReplaceAll(html, "/samwaf_access/", cfg.PathPrefix+"/")
	html = strings.ReplaceAll(html, "'/samwaf_access'", "'"+cfg.PathPrefix+"'")
	html = strings.ReplaceAll(html, "\"/samwaf_access\"", "\""+cfg.PathPrefix+"\"")
	// rq 会被前端原样回填进隐藏域再 POST 回来。它已经是 base64url + 点号，
	// 不含 HTML 特殊字符，但仍然做一次转义，避免模板被改造后出现注入点。
	html = strings.ReplaceAll(html, "__SAMWAF_RQ__", htmlAttrEscape(rq))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// htmlAttrEscape 属性值转义。只处理会破坏属性边界的字符。
func htmlAttrEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(s)
}

// ─────────────────────────── 密码校验 ───────────────────────────

type accessLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Rq       string `json:"rq"`
}

type accessOtpReq struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

func (waf *WafEngine) accessHandleValidate(w http.ResponseWriter, r *http.Request,
	hostTarget *wafenginmodel.HostSafe, cfg *accessgate.Config,
	hostCfg model.HostAccessConfig, clientIP string) {

	var req accessLoginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil {
		writeAccessJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false, "message": "请求格式错误",
		})
		return
	}
	username := strings.TrimSpace(req.Username)

	// 锁定检查放在密码校验之前：被锁定期间连 bcrypt 都不该跑，
	// 否则攻击者仍能靠"锁定期间响应变快"推断出一些信息，也白白消耗 CPU。
	if locked, msg := waf.accessCheckLock(clientIP, username, cfg); locked {
		// 走节流写入：被锁定的攻击者会继续猛打这个端点，每次都同步写一行审计
		// 等于给了对方一个把审计表刷爆、顺带放大写库压力的入口。
		accessAuditService.WriteThrottled(waf_service.AuditEntry{
			Event: model.AccessEventLocked, AccountName: username, Host: r.Host,
			HostCode: hostTarget.Host.Code, ClientIP: clientIP, UserAgent: r.UserAgent(),
			Result: model.AccessAuditFail, Message: msg,
		})
		writeAccessJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"success": false, "message": msg,
		})
		return
	}

	acct, err := accessAccountService.VerifyCredential(username, req.Password)
	if err != nil {
		remain := waf.accessRecordFail(clientIP, username, cfg)
		accessAuditService.Write(waf_service.AuditEntry{
			Event: model.AccessEventLoginFail, AccountName: username, Host: r.Host,
			HostCode: hostTarget.Host.Code, ClientIP: clientIP, UserAgent: r.UserAgent(),
			Fingerprint: utils.GenerateFingerprint(r), Result: model.AccessAuditFail,
			Message: err.Error(),
		})
		writeAccessJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("%s，剩余尝试次数：%d", err.Error(), remain),
		})
		return
	}

	// 这里刻意不查「账号能不能访问本站点」。
	//
	// 本接口只在认证中心域名上可达，此刻的 hostTarget 就是认证中心站点，
	// 拿它去判授权等于在问"这个人能不能进认证中心"——与他真正想去的业务站点毫无关系。
	// 真查了反而是个死锁：管理员按直觉只给账号授权 app.com，用户就永远登不进认证中心；
	// 要让它工作还得把认证中心的 code 也塞进每个账号的允许列表，
	// 那等于把认证中心本身对所有人开放。
	// 逐站点的授权判定在 accessAuthorizeForHost，签票与兑票各做一次。

	// 站点级二次验证要看「用户真正想去的那个站点」，同样不能看 hostTarget。
	siteOtp := waf.accessTargetHostOtpMode(req.Rq, cfg, hostCfg.RequireOtp)
	if accessAccountService.NeedOtp(acct, siteOtp, cfg.RequireOtp) {
		stage := uuid.GenUUID()
		global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_ACCESS_STAGE+stage, otpStage{
			AccountId: acct.Id, Rq: req.Rq, BindHost: r.Host,
		}, otpStageTTL)
		// 密码已经对了，清掉失败计数，避免用户在 OTP 环节被之前的失败数拖累
		waf.accessClearFail(clientIP, username)
		writeAccessJSON(w, http.StatusOK, map[string]interface{}{
			"success": true, "need_otp": true, "stage": stage,
			"message": "请输入动态验证码",
		})
		return
	}

	waf.accessFinishLogin(w, r, *acct, hostTarget, cfg, clientIP, req.Rq)
}

func (waf *WafEngine) accessHandleOtp(w http.ResponseWriter, r *http.Request,
	hostTarget *wafenginmodel.HostSafe, cfg *accessgate.Config, clientIP string) {

	var req accessOtpReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&req); err != nil {
		writeAccessJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false, "message": "请求格式错误",
		})
		return
	}

	var stage otpStage
	if err := global.GCACHE_WAFCACHE.GetAs(enums.CACHE_ACCESS_STAGE+req.Stage, &stage); err != nil ||
		stage.AccountId == "" {
		writeAccessJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false, "message": "验证已超时，请重新登录",
		})
		return
	}

	// 第二步必须回到第一步那个域名。
	//
	// 少了这一条，攻击者可以在自己有权限的 a.com 上过密码校验拿到 stage，
	// 再把 stage 拿到无权限的 b.com 上完成 OTP —— 令牌就按 b.com 签发了，
	// 第一步做的站点授权判定被整个绕过。
	if !strings.EqualFold(stage.BindHost, r.Host) {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_STAGE + req.Stage)
		writeAccessJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false, "message": "验证环境已变化，请重新登录",
		})
		return
	}

	// OTP 单独计数：动态码只有 6 位数字，不限速的话在 30 秒时间窗内是可以暴力试出来的。
	failKey := enums.CACHE_ACCESS_OTPFAIL + stage.AccountId
	if cnt, _ := global.GCACHE_WAFCACHE.GetInt(failKey); cnt >= cfg.MaxFailCount {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_STAGE + req.Stage)
		writeAccessJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"success": false, "message": "验证码错误次数过多，请重新登录",
		})
		return
	}

	acct, err := accessAccountService.GetDetailApi(stage.AccountId)
	if err != nil || !accessAccountService.VerifyOtp(&acct, req.Code) {
		waf.accessRecordOtpFail(stage.AccountId, cfg)
		accessAuditService.Write(waf_service.AuditEntry{
			Event: model.AccessEventOtpFail, AccountName: acct.AccountName, Host: r.Host,
			HostCode: hostTarget.Host.Code, ClientIP: clientIP, UserAgent: r.UserAgent(),
			Result: model.AccessAuditFail, Message: "动态验证码错误",
		})
		writeAccessJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false, "message": "动态验证码不正确",
		})
		return
	}

	// stage 是一次性的：验过就作废，防止同一个 stage 被反复用来试码
	global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_STAGE + req.Stage)
	global.GCACHE_WAFCACHE.Remove(failKey)

	// 复查账号状态：从输完密码到输完动态码之间最多隔 5 分钟，
	// 管理员完全可能在这段时间里把账号禁用掉。
	//
	// 同样不查站点授权，理由与 accessHandleValidate 里那段注释完全一致——
	// 这里的 hostTarget 是认证中心站点。早先这里漏掉了这个区分，导致
	// 「只授权了某个业务站点 + 绑了动态口令」的账号密码能过、动态码也对，
	// 却在最后一步被 403，且提示语是"该账号无权访问本站点"，极难自查。
	fresh, usableErr := accessAccountService.CheckStillUsable(acct.Id)
	if usableErr != nil {
		msg := usableErr.Error()
		accessAuditService.Write(waf_service.AuditEntry{
			Event: model.AccessEventLoginFail, AccountName: acct.AccountName, Host: r.Host,
			HostCode: hostTarget.Host.Code, ClientIP: clientIP, UserAgent: r.UserAgent(),
			Result: model.AccessAuditFail, Message: "二次验证通过但账号已不可用：" + msg,
		})
		writeAccessJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false, "message": msg,
		})
		return
	}
	waf.accessFinishLogin(w, r, *fresh, hostTarget, cfg, clientIP, stage.Rq)
}

// accessFinishLogin 建会话、种 Cookie、算出登录后该去哪。
func (waf *WafEngine) accessFinishLogin(w http.ResponseWriter, r *http.Request,
	acct model.AccessAccount, hostTarget *wafenginmodel.HostSafe,
	cfg *accessgate.Config, clientIP, rq string) {

	fingerprint := utils.GenerateFingerprint(r)
	secure := accessCookieSecure(r, hostTarget, cfg)

	// 登录只可能发生在认证中心域名上（见 handleAccessRequest 的分流），
	// 所以会话一律是全站通行的 sso 会话，不存在只服务单个域名的会话。
	plainSess, sess, err := accessSessionService.CreateSession(acct, model.AccessScopeSSO, "",
		clientIP, fingerprint, r.UserAgent(), cfg)
	if err != nil {
		zlog.Error("统一访问认证：创建会话失败", err.Error())
		writeAccessJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false, "message": "服务暂时不可用",
		})
		return
	}
	http.SetCookie(w, buildAccessCookie(cfg.CookieSSOName, plainSess,
		int(cfg.SessionTTL.Seconds()), secure))

	waf.accessClearFail(clientIP, acct.AccountName)
	accessAccountService.MarkLogin(acct.Id, clientIP)
	accessAuditService.Write(waf_service.AuditEntry{
		Event: model.AccessEventLoginOK, AccountName: acct.AccountName,
		SessionCode: sess.SessionCode, Host: r.Host, HostCode: hostTarget.Host.Code,
		ClientIP: clientIP, UserAgent: r.UserAgent(), Fingerprint: fingerprint,
		Result: model.AccessAuditOK, Message: "登录成功",
	})

	// 登录完回到 authorize 去换票，由它把用户送回原本想去的业务域名。
	// 用户当初就是在认证中心上登录的，认证中心自己也可能是被保护的站点——
	// 那种情况同样走这条票据链路，不做本域捷径，省得两套逻辑各错各的。
	redirect := cfg.PathPrefix + "/authorize"
	if rq != "" {
		redirect += "?rq=" + url.QueryEscape(rq)
	}
	writeAccessJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "message": "登录成功", "redirect": redirect,
	})
}

// ─────────────────────────── 注销与状态 ───────────────────────────

func (waf *WafEngine) accessHandleLogout(w http.ResponseWriter, r *http.Request,
	hostTarget *wafenginmodel.HostSafe, cfg *accessgate.Config, clientIP string) {

	secure := accessCookieSecure(r, hostTarget, cfg)

	// 「注销全部站点」只接受 POST。
	//
	// Cookie 是 SameSite=Lax，顶层 GET 导航会携带它——攻击页面只要写一句
	// location='https://sso/samwaf_access/logout?all=1' 就能把受害者从所有站点踢下线。
	// 单站点注销危害小得多（用户重新登一次即可），继续允许 GET，
	// 这样浏览器地址栏和登录页上的退出链接都还能用。
	all := r.URL.Query().Get("all") == "1" && r.Method == http.MethodPost

	accountName := ""
	if ck, err := r.Cookie(cfg.CookieSSOName); err == nil && ck.Value != "" {
		if all {
			// 注销中心会话会级联作废它签出去的所有子令牌，
			// 于是所有站点在下一次请求（最迟 60 秒后）统一掉线。
			code := waf_service.HashAccessCode(ck.Value)
			if sess, err := accessTicketService.LoadSessionByCode(code); err == nil {
				accountName = sess.AccountName
			}
			_ = accessSessionService.RevokeSession(code, model.AccessRevokeByLogout)
		}
		clearAccessCookie(w, cfg.CookieSSOName, secure)
	}
	if ck, err := r.Cookie(cfg.CookieTokenName); err == nil && ck.Value != "" {
		accessSessionService.RevokeToken(ck.Value)
		clearAccessCookie(w, cfg.CookieTokenName, secure)
	}

	accessAuditService.Write(waf_service.AuditEntry{
		Event: model.AccessEventLogout, AccountName: accountName, Host: r.Host,
		HostCode: hostTarget.Host.Code, ClientIP: clientIP, UserAgent: r.UserAgent(),
		Result:  model.AccessAuditOK,
		Message: map[bool]string{true: "注销全部站点", false: "注销当前站点"}[all],
	})

	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		http.Redirect(w, r, cfg.PathPrefix+"/login", http.StatusFound)
		return
	}
	writeAccessJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "message": "已注销",
	})
}

// accessHandleStatus 供 SPA 探测登录态。
// 未登录时不返回任何账号信息——这个端点是免认证可达的，不能变成账号枚举入口。
func (waf *WafEngine) accessHandleStatus(w http.ResponseWriter, r *http.Request,
	cfg *accessgate.Config, clientIP string) {

	fingerprint := utils.GenerateFingerprint(r)
	if ck, err := r.Cookie(cfg.CookieTokenName); err == nil && ck.Value != "" {
		if st := accessSessionService.ValidateToken(ck.Value, r.Host, clientIP, fingerprint, cfg); st != nil {
			writeAccessJSON(w, http.StatusOK, map[string]interface{}{
				"authenticated": true,
				"account":       st.AccountName,
				"expire_in":     st.ExpireUnix - time.Now().Unix(),
			})
			return
		}
	}
	writeAccessJSON(w, http.StatusOK, map[string]interface{}{"authenticated": false})
}

// accessCurrentSSOSession 取当前请求携带的有效中心会话，没有则返回 nil。
func (waf *WafEngine) accessCurrentSSOSession(r *http.Request, cfg *accessgate.Config,
	clientIP, fingerprint string) *model.AccessSession {

	ck, err := r.Cookie(cfg.CookieSSOName)
	if err != nil || ck.Value == "" {
		return nil
	}
	return accessSessionService.ValidateSSOSession(ck.Value, r.Host, clientIP, fingerprint, cfg)
}

// ─────────────────────────── 失败锁定 ───────────────────────────

// accessCheckLock 双维度锁定检查。
//
// 为什么要两个维度：只按 IP 计数挡不住分布式爆破（每个 IP 试 3 次，换一批 IP 继续）；
// 只按账号计数则会被人拿来当拒绝服务用（故意把别人的账号锁掉）。两个都记、任一超限即锁，
// 是这两种失败模式之间的折中。
func (waf *WafEngine) accessCheckLock(clientIP, username string, cfg *accessgate.Config) (bool, string) {
	if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_ACCESS_LOCK + "ip:" + clientIP) {
		return true, fmt.Sprintf("登录失败次数过多，请 %d 分钟后再试", int(cfg.LockDuration.Minutes()))
	}
	if username != "" &&
		global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_ACCESS_LOCK+"user:"+strings.ToLower(username)) {
		return true, fmt.Sprintf("该账号登录失败次数过多，请 %d 分钟后再试", int(cfg.LockDuration.Minutes()))
	}
	return false, ""
}

// accessFailMu 保护失败计数的「读-改-写」序列。
//
// 缓存层没有原子自增，裸的 Get→+1→Set 在并发下会被压平：
// 200 个并发请求全部读到 0、全部写回 1，实际只前进了 1 次，
// 「10 次失败即锁定」于是形同虚设，口令爆破速率几乎不受限。
// 一把全局互斥就够了——登录是低频路径，这里的竞争可以忽略。
var accessFailMu sync.Mutex

// accessRecordFail 记一次失败，返回剩余可尝试次数。
func (waf *WafEngine) accessRecordFail(clientIP, username string, cfg *accessgate.Config) int {
	accessFailMu.Lock()
	defer accessFailMu.Unlock()

	remain := cfg.MaxFailCount
	for _, key := range accessFailKeys(clientIP, username) {
		cnt, _ := global.GCACHE_WAFCACHE.GetInt(enums.CACHE_ACCESS_FAIL + key)
		cnt++
		if cnt >= cfg.MaxFailCount {
			global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_ACCESS_LOCK+key, "1", cfg.LockDuration)
			global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_FAIL + key)
			remain = 0
			continue
		}
		global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_ACCESS_FAIL+key, cnt, cfg.LockDuration)
		if r := cfg.MaxFailCount - cnt; r < remain {
			remain = r
		}
	}
	if remain < 0 {
		remain = 0
	}
	return remain
}

// accessRecordOtpFail 记一次动态码失败。与密码计数共用同一把锁，理由相同：
// 6 位数字的动态码在 30 秒时间窗内是可以暴力试出来的，计数必须真的准。
func (waf *WafEngine) accessRecordOtpFail(accountId string, cfg *accessgate.Config) {
	accessFailMu.Lock()
	defer accessFailMu.Unlock()
	key := enums.CACHE_ACCESS_OTPFAIL + accountId
	cnt, _ := global.GCACHE_WAFCACHE.GetInt(key)
	global.GCACHE_WAFCACHE.SetWithTTl(key, cnt+1, cfg.LockDuration)
}

func (waf *WafEngine) accessClearFail(clientIP, username string) {
	for _, key := range accessFailKeys(clientIP, username) {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_FAIL + key)
	}
}

func accessFailKeys(clientIP, username string) []string {
	keys := []string{"ip:" + clientIP}
	if strings.TrimSpace(username) != "" {
		keys = append(keys, "user:"+strings.ToLower(strings.TrimSpace(username)))
	}
	return keys
}

func writeAccessJSON(w http.ResponseWriter, status int, body map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.WriteHeader(status)
	buf, _ := json.Marshal(body)
	_, _ = w.Write(buf)
}

// accessFallbackLoginHTML 是模板文件缺失时的内置回退页。
// 刻意做到最小：没有外链资源、没有产品标识，只保证功能可用，
// 让用户在模板释放失败时仍然能登进去而不是彻底进不来。
const accessFallbackLoginHTML = `<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f5f6f8;display:flex;
min-height:100vh;align-items:center;justify-content:center;margin:0}
.b{background:#fff;padding:32px;border-radius:10px;box-shadow:0 2px 16px rgba(0,0,0,.08);width:320px}
input{width:100%;box-sizing:border-box;padding:10px;margin:6px 0;border:1px solid #dcdfe6;border-radius:6px}
button{width:100%;padding:10px;margin-top:12px;border:0;border-radius:6px;background:#0052d9;color:#fff;cursor:pointer}
#m{color:#d54941;font-size:13px;min-height:18px;margin-top:8px}</style>
<div class="b"><h3 style="margin:0 0 16px">Sign in</h3>
<input id="u" placeholder="Username" autocomplete="username">
<input id="p" type="password" placeholder="Password" autocomplete="current-password">
<input id="c" placeholder="Verification code" style="display:none">
<button id="s">Continue</button><div id="m"></div></div>
<script>
var P="/samwaf_access",R="__SAMWAF_RQ__",stage="";
function post(u,d){return fetch(P+u,{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify(d)}).then(function(r){return r.json()})}
document.getElementById("s").onclick=function(){
 var m=document.getElementById("m");m.textContent="";
 if(stage){post("/otp",{stage:stage,code:document.getElementById("c").value}).then(function(j){
   if(j.success){location.replace(j.redirect||"/")}else{m.textContent=j.message||"Failed"}});return}
 post("/validate",{username:document.getElementById("u").value,
   password:document.getElementById("p").value,rq:R}).then(function(j){
   if(j.success&&j.need_otp){stage=j.stage;document.getElementById("c").style.display="block";
     m.textContent=j.message||"";return}
   if(j.success){location.replace(j.redirect||"/")}else{m.textContent=j.message||"Failed"}})};
document.addEventListener("keydown",function(e){if(e.key==="Enter"){document.getElementById("s").click()}});
</script>`
