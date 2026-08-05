package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafenginecore/accessgate"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// access_ticket.go 实现跨域 SSO：让「在认证中心登录一次」等价于「所有受保护站点都已登录」。
//
// 为什么需要这一整套东西：Cookie 无法跨注册域共享。a.com 上种的 Cookie，
// 浏览器绝不会发给 b.com。要让「登录一次处处通行」成立，只能走
// 「中心域名 + 一次性票据回跳」这套方案。
//
// 完整时序：
//
//	① 访问 https://app.com/foo        → 无子令牌 → 302 到 中心/authorize?rq=<签名>
//	② 中心 /authorize                 → 验 rq → 有中心会话则签票，302 回 app.com/callback?tk=<票据>
//	                                    → 无中心会话则渲染登录页
//	③ 中心 /validate (+/otp)          → 校验凭据 → 建中心会话 + 种 SSO Cookie → 回到 ②
//	④ app.com /callback               → 一次性消费票据 → 建子令牌 + 种本域 Cookie → 302 回 /foo
//
// 两个凭据的职责刻意分开：
//   - rq  只需要「防篡改」，所以用无状态 HMAC 签名，跨 Worker 天生可用（优雅升级期间双进程并存）
//   - 票据 需要「恰好用一次」，这是全局互斥语义，只能靠数据库条件更新，见 ConsumeTicket

// accessAuthReq 是编码进 rq 的载荷。字段名压到一个字母，因为它要塞进 URL。
type accessAuthReq struct {
	R string `json:"r"` // 原始完整 URL，认证成功后要回到这里
	H string `json:"h"` // 发起认证的域名(含端口)，票据与回跳都绑定它
	E int64  `json:"e"` // 过期时间戳
	N string `json:"n"` // 随机 nonce，让相同请求每次的签名都不同
}

// accessAuthReqTTL rq 的有效期。5 分钟足够用户从跳转走到登录完成，
// 又不至于让一个被截获的 rq 长期可用。
const accessAuthReqTTL = 5 * time.Minute

// signAuthReq 生成 rq：base64url(payload) + "." + base64url(HMAC-SHA256(secret, payload))。
// 密钥为空时返回空串——调用方会退化成不带 rq 的跳转（登录后回首页），
// 绝不能退化成"不验签"，那等于把开放重定向的门直接敞开。
func signAuthReq(secret []byte, req accessAuthReq) string {
	if len(secret) == 0 {
		return ""
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyAuthReq 验签并解出载荷。任何一步不通过都返回 false。
func verifyAuthReq(secret []byte, rq string) (accessAuthReq, bool) {
	var out accessAuthReq
	if len(secret) == 0 || rq == "" {
		return out, false
	}
	idx := strings.LastIndex(rq, ".")
	if idx <= 0 || idx == len(rq)-1 {
		return out, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(rq[:idx])
	if err != nil {
		return out, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(rq[idx+1:])
	if err != nil {
		return out, false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	// hmac.Equal 是定长比较，不能换成 bytes.Equal 或 ==：签名比对是计时攻击的经典目标
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return out, false
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return out, false
	}
	if out.E > 0 && time.Now().Unix() > out.E {
		return out, false
	}
	return out, true
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

// buildAccessEntryURL 构造未认证时要跳去的地址。
//
//	在认证中心域名上：/samwaf_access/login?rq=...（同域相对路径即可）
//	在业务域名上：    https://<认证中心>/samwaf_access/authorize?rq=...
//
// 没有配认证中心时不该走到这里 —— DoAccessGate 会先放行整个请求（见那里的注释）。
// 真走到了就只能给同域登录页，聊胜于无。
func (waf *WafEngine) buildAccessEntryURL(r *http.Request, cfg *accessgate.Config) string {
	ret := accessCurrentURL(r)
	rq := signAuthReq(cfg.HmacSecret, accessAuthReq{
		R: ret,
		H: r.Host,
		E: time.Now().Add(accessAuthReqTTL).Unix(),
		N: randHex(16),
	})
	if cfg.IsCenterMode() && !strings.EqualFold(r.Host, cfg.CenterHost) {
		u := cfg.CenterOrigin + cfg.PathPrefix + "/authorize"
		if rq != "" {
			u += "?rq=" + url.QueryEscape(rq)
		}
		return u
	}
	u := cfg.PathPrefix + "/login"
	if rq != "" {
		u += "?rq=" + url.QueryEscape(rq)
	}
	return u
}

// accessCurrentURL 还原当前请求的完整 URL（含查询串，否则用户的深链接参数会丢）。
//
// 用 r.URL.RequestURI() 而不是 r.RequestURI：后者在 absolute-form 请求
// （代理场景下客户端可以发 "GET http://host/path HTTP/1.1"）里是整个绝对地址，
// 直接拼在 scheme://host 后面会得到 http://hosthttp://host/path 这种垃圾。
// r.URL.RequestURI() 总是返回 path?query。
func accessCurrentURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// accessHandleAuthorize 处理认证中心的 /authorize。
//
// 只在认证中心域名上提供服务：其它域名访问一律 404。
// 这不是洁癖——在业务域名上暴露 authorize 会让攻击者能在任意受管域名上发起签票流程。
func (waf *WafEngine) accessHandleAuthorize(w http.ResponseWriter, r *http.Request,
	cfg *accessgate.Config, clientIP string) {

	if !cfg.IsCenterMode() || !strings.EqualFold(r.Host, cfg.CenterHost) {
		http.NotFound(w, r)
		return
	}

	rq := r.URL.Query().Get("rq")
	payload, ok := verifyAuthReq(cfg.HmacSecret, rq)
	if !ok {
		// 验签失败可能是过期，也可能是伪造。都不给细节，直接引导重新登录。
		waf.accessServeLoginPage(w, r, cfg, "")
		return
	}

	// 回跳目标必须通过完整的四层校验（语法/绑定/路由表/不信任查询参数），见 access_redirect.go
	returnTo, valid := waf.validateReturnTo(payload.R, payload.H)
	if !valid {
		accessAuditService.Write(waf_service.AuditEntry{
			Event: model.AccessEventBadReturnTo, Host: r.Host, URL: payload.R,
			ClientIP: clientIP, UserAgent: r.UserAgent(), Result: model.AccessAuditFail,
			Message: "回跳地址校验失败，疑似开放重定向尝试",
		})
		waf.accessServeLoginPage(w, r, cfg, "")
		return
	}

	fingerprint := utils.GenerateFingerprint(r)
	sess := waf.accessCurrentSSOSession(r, cfg, clientIP, fingerprint)
	if sess == nil {
		// 还没登录：渲染登录页，把 rq 透传进去，登录成功后再回到本接口
		waf.accessServeLoginPage(w, r, cfg, rq)
		return
	}

	// 授权与账号状态必须在这里复查，不能只靠登录时那一次。
	//
	// 登录发生在认证中心域名上，那次 IsHostAllowed 判的是"能不能进认证中心"，
	// 与用户此刻想去的业务站点毫无关系。少了下面这段，只要能登进认证中心
	// 就能换到任意站点的令牌 —— 按账号授权站点这个功能会彻底失效。
	// 同时顺带复查账号状态：从登录到换票之间管理员可能已经把账号禁用了。
	// 认证中心这一侧只有目标域名字符串可用，只能反查
	if !waf.accessAuthorizeForHost(w, r, sess, payload.H, "", clientIP, fingerprint, cfg) {
		return
	}

	ticket, err := accessTicketService.IssueTicket(*sess, payload.H, returnTo, clientIP, fingerprint, cfg)
	if err != nil {
		zlog.Error("统一访问认证：签发票据失败", err.Error())
		http.Error(w, "服务暂时不可用", http.StatusInternalServerError)
		return
	}
	accessAuditService.Write(waf_service.AuditEntry{
		Event: model.AccessEventTicketIssue, AccountName: sess.AccountName,
		SessionCode: sess.SessionCode, Host: payload.H, ClientIP: clientIP,
		UserAgent: r.UserAgent(), Fingerprint: fingerprint, Result: model.AccessAuditOK,
		Message: "签发跨站点访问票据",
	})

	// 回跳到业务域名的 callback。目标域名取自已验签的 payload.H，不是查询参数。
	target := accessSchemeOf(returnTo) + "://" + payload.H + cfg.PathPrefix +
		"/callback?tk=" + url.QueryEscape(ticket)
	http.Redirect(w, r, target, http.StatusFound)
}

// accessAuthorizeForHost 复查「这个会话此刻还能不能进 targetHost 这个站点」。
// 不通过时自行写完响应并返回 false，调用方直接 return 即可。
//
// knownHostCode 是调用方手里已有的权威站点码；为空时才回退到按域名反查。
// 之所以优先用传入值：ServeHTTP 在存在 catch-all 站点时会把所有请求的 hostTarget
// 都覆盖成 catch-all 那一个，而 lookupHostCode 刻意不认 catch-all（见 access_redirect.go），
// 两者就成了两个真相源。callback 侧本来就持有 hostTarget.Host.Code，不该再去猜。
func (waf *WafEngine) accessAuthorizeForHost(w http.ResponseWriter, r *http.Request,
	sess *model.AccessSession, targetHost, knownHostCode, clientIP, fingerprint string,
	cfg *accessgate.Config) bool {

	acct, err := accessAccountService.CheckStillUsable(sess.AccountCode)
	if err != nil {
		// 账号已被禁用/删除/过期：连同会话一并撤销，别让它继续换票
		_ = accessSessionService.RevokeSession(sess.SessionCode, model.AccessRevokeByAccount)
		accessAuditService.Write(waf_service.AuditEntry{
			Event: model.AccessEventDenied, AccountName: sess.AccountName,
			SessionCode: sess.SessionCode, Host: targetHost, ClientIP: clientIP,
			UserAgent: r.UserAgent(), Fingerprint: fingerprint,
			Result: model.AccessAuditFail, Message: "换票时账号已不可用：" + err.Error(),
		})
		waf.accessServeLoginPage(w, r, cfg, "")
		return false
	}

	// 目标域名必须能定位到站点；定位不到说明站点已下线，没有必要也没有依据签票
	hostCode := knownHostCode
	if hostCode == "" {
		var ok bool
		if hostCode, ok = waf.lookupHostCode(targetHost); !ok {
			hostCode = ""
		}
	}
	if hostCode == "" || !accessAccountService.IsHostAllowed(acct, hostCode) {
		accessAuditService.Write(waf_service.AuditEntry{
			Event: model.AccessEventDenied, AccountName: sess.AccountName,
			SessionCode: sess.SessionCode, Host: targetHost, HostCode: hostCode,
			ClientIP: clientIP, UserAgent: r.UserAgent(), Fingerprint: fingerprint,
			Result: model.AccessAuditFail, Message: "账号未被授权访问该站点",
		})
		writeAccessJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false, "message": "该账号无权访问本站点",
		})
		return false
	}
	return true
}

// accessHandleCallback 处理业务域名的 /callback：消费票据、种本域 Cookie、回到原地址。
func (waf *WafEngine) accessHandleCallback(w http.ResponseWriter, r *http.Request,
	hostTarget *wafenginmodel.HostSafe, cfg *accessgate.Config, clientIP string) {

	tk := r.URL.Query().Get("tk")
	fingerprint := utils.GenerateFingerprint(r)

	ticket, err := accessTicketService.ConsumeTicket(tk, r.Host, clientIP, fingerprint, cfg)
	if err != nil {
		// 消费失败只有三种可能：伪造、重放、过期。三种都记成安全事件——
		// 正常流程里票据是即签即用的，兑换失败本身就是异常信号。
		accessAuditService.Write(waf_service.AuditEntry{
			Event: model.AccessEventTicketReplay, Host: r.Host,
			HostCode: hostTarget.Host.Code, ClientIP: clientIP, UserAgent: r.UserAgent(),
			Fingerprint: fingerprint, Result: model.AccessAuditFail, Message: err.Error(),
		})
		// 不报错，直接把用户送回去重走一遍认证：真实用户遇到的多半是"点了浏览器后退"，
		// 给他一个 500 页面毫无帮助。
		http.Redirect(w, r, waf.buildAccessEntryURL(r, cfg), http.StatusFound)
		return
	}

	sess, err := accessTicketService.LoadSessionByCode(ticket.SessionCode)
	if err != nil {
		http.Redirect(w, r, waf.buildAccessEntryURL(r, cfg), http.StatusFound)
		return
	}

	// 纵深防御：签票时已经查过一次授权，这里在真正发放令牌前再查一次。
	// 成本几乎为零，却能挡住「票据签发后到兑换前账号被禁用」以及
	// 未来某次改动漏掉签票侧校验的情况。
	// 这里传入 hostTarget.Host.Code —— 它就是即将被服务的那个站点，
	// 也正是下面 accessIssueTokenCookie 写进 AccessToken.HostCode 的值，
	// 保证"判定所依据的站点"与"实际被服务的站点"是同一个。
	if !waf.accessAuthorizeForHost(w, r, sess, r.Host, hostTarget.Host.Code, clientIP, fingerprint, cfg) {
		return
	}

	if err := waf.accessIssueTokenCookie(w, r, *sess, hostTarget, cfg, clientIP, fingerprint); err != nil {
		zlog.Error("统一访问认证：签发子令牌失败", err.Error())
		http.Error(w, "服务暂时不可用", http.StatusInternalServerError)
		return
	}
	accessAuditService.Write(waf_service.AuditEntry{
		Event: model.AccessEventTicketConsume, AccountName: sess.AccountName,
		SessionCode: sess.SessionCode, Host: r.Host, HostCode: hostTarget.Host.Code,
		ClientIP: clientIP, UserAgent: r.UserAgent(), Fingerprint: fingerprint,
		Result: model.AccessAuditOK, Message: "票据兑换成功，本站点已放行",
	})

	// 再校验一次回跳地址。票据是自己签的没错，但多这一次校验的成本几乎为零，
	// 而它能挡住「库被改写」「代码演进中某处漏了校验」这类情况。
	target, valid := waf.validateReturnTo(ticket.ReturnTo, r.Host)
	if !valid {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// accessIssueTokenCookie 为当前业务域签发子令牌并写 Cookie。
func (waf *WafEngine) accessIssueTokenCookie(w http.ResponseWriter, r *http.Request,
	sess model.AccessSession, hostTarget *wafenginmodel.HostSafe, cfg *accessgate.Config,
	clientIP, fingerprint string) error {

	plain, err := accessSessionService.IssueToken(sess, r.Host, hostTarget.Host.Code,
		clientIP, fingerprint, cfg)
	if err != nil {
		return err
	}
	http.SetCookie(w, buildAccessCookie(cfg.CookieTokenName, plain,
		int(cfg.TokenTTL.Seconds()), accessCookieSecure(r, hostTarget, cfg)))
	return nil
}

// buildAccessCookie 统一构造 Cookie，避免各处属性写歪。
//
// SameSite 固定 Lax，这一条不能改成 Strict：
// callback 是从认证中心域到业务域的顶层 GET 导航，Strict 会导致刚种下的 Cookie
// 在紧接着的 302 里不被携带，用户会陷入「登录成功 → 又跳登录页」的无限循环。
// Lax 恰好允许顶层 GET 携带，是这个场景下唯一正确的取值。
// 也不用 None——没有跨站 iframe/XHR 的需求，None 只会白白放大 CSRF 面。
func buildAccessCookie(name, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// accessCookieSecure 判断是否该给 Cookie 打 Secure。
//
// 必须自动判定而不是硬编码 true：纯 HTTP 的站点打了 Secure，浏览器根本不会存这个 Cookie，
// 用户会看到"登录成功但立刻又要登录"。
func accessCookieSecure(r *http.Request, hostTarget *wafenginmodel.HostSafe, cfg *accessgate.Config) bool {
	if cfg.ForceSecureCookie {
		return true
	}
	if r.TLS != nil {
		return true
	}
	// 站点开了强制跳 HTTPS，说明最终一定走在 https 上
	return hostTarget != nil && hostTarget.Host.AutoJumpHTTPS == 1
}

// clearAccessCookie 让浏览器立刻丢弃某个 Cookie。
func clearAccessCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func accessSchemeOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Scheme != "" {
		return u.Scheme
	}
	return "https"
}
