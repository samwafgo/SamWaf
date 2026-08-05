package wafenginecore

import (
	"SamWaf/common/domaintool"
	"SamWaf/utils"
	"net/url"
	"strings"
)

// access_redirect.go 是统一访问认证的「回跳地址校验」。
//
// 认证网关天然是开放重定向的高危点：它必须在认证成功后把用户送回原来想去的地址，
// 而那个地址是从请求里来的。做得松一点，攻击者就能拿一个看起来完全合法的
// https://你的站点/samwaf_access/authorize?rq=... 把受害者钓到自己的服务器上，
// 甚至顺走 Referer 里的票据。
//
// 这里的核心思路是「双重收窄」：
//  1. 回跳目标必须等于票据/签名里记录的那个域名（不是"某个白名单里的域名"）；
//  2. 那个域名还必须真的由本 WAF 在代理。
//
// 换句话说，攻击者即使能诱导出一次 302，也只能把受害者送回他自己发起认证的那个站点，
// 拿不到任何跨站的收益。

// maxReturnToLen 回跳地址长度上限。
// 正常业务 URL 远达不到这个量级，超长值基本只出现在构造攻击载荷时。
const maxReturnToLen = 2048

// validateReturnTo 校验回跳地址，返回归一化后的安全地址。
//
// expectHost 是「票据或已验签的 rq 里记录的域名」，回跳目标必须与它完全一致。
// 校验不通过时返回 ("", false)，调用方应当回退到 "/" 并记一条 bad_return_to 审计。
//
// 注意调用方的责任：最终 302 的目标永远只能取自「已验签的 rq」或「数据库里的票据行」，
// 绝不能直接读 r.URL.Query().Get("redirect") —— 那样这里做多少校验都是白做。
func (waf *WafEngine) validateReturnTo(raw, expectHost string) (string, bool) {
	if raw == "" || expectHost == "" {
		return "", false
	}
	if len(raw) > maxReturnToLen {
		return "", false
	}

	// ① 语法层：先挡掉字符级的绕过手法。
	//    反斜杠必须拒绝——浏览器会把 \/\/evil.com 或 /\evil.com 当协议相对地址解析，
	//    而 Go 的 url.Parse 不会，两者的分歧正是这类绕过的成因。
	//    控制字符（含 CR/LF/TAB）拒绝，避免响应头拆分。
	if strings.ContainsAny(raw, "\\") {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", false
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	// 只接受绝对地址：协议相对地址(//evil.com)会被 url.Parse 解析成 Scheme="" Host="evil.com"，
	// 在这里被 scheme 判定拦下。
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	if u.Host == "" {
		return "", false
	}
	// userinfo 必须为空：https://good.com@evil.com 的真实目标是 evil.com，
	// 但肉眼和很多粗糙的字符串校验都会误判成 good.com。
	if u.User != nil {
		return "", false
	}
	// 路径要么为空要么是绝对路径
	if u.Path != "" && !strings.HasPrefix(u.Path, "/") {
		return "", false
	}
	// 片段对服务端毫无意义，且是 XSS 载荷的常见藏身处，直接丢掉
	u.Fragment = ""
	u.RawFragment = ""

	// ② 绑定层：目标域名必须等于票据里记录的域名。
	//    这一条比「在白名单里」严格得多——即使 WAF 代理了 100 个站点，
	//    从 a.com 发起的认证也只能回到 a.com。
	if !strings.EqualFold(u.Host, expectHost) {
		return "", false
	}

	// ③ 路由表层：该域名必须真的由本 WAF 在代理。
	//    防的是「站点已下线但票据还在」以及配置里被写入了不受控域名的情况。
	if !waf.isManagedHost(u.Host) {
		return "", false
	}

	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), true
}

// lookupHostCode 按域名(可带端口)反查站点唯一码。
//
// 供「按账号授权站点」的判定使用：跨域 SSO 在认证中心上签票时，
// 手里只有目标域名字符串，必须先换成 host_code 才能判断账号有没有权限进那个站点。
func (waf *WafEngine) lookupHostCode(hostWithPort string) (string, bool) {
	if hostWithPort == "" {
		return "", false
	}
	rt := waf.rt()
	host := strings.ToLower(strings.TrimSpace(hostWithPort))
	candidates := []string{host}
	if !strings.Contains(host, ":") {
		candidates = []string{host + ":443", host + ":80"}
	}
	if key, ok := rt.HostTargetNoPort[utils.GetPureDomain(host)]; ok {
		if h, ok2 := rt.HostTarget[key]; ok2 && h != nil {
			return h.Host.Code, true
		}
	}
	for _, c := range candidates {
		if h, ok := rt.HostTarget[c]; ok && h != nil {
			return h.Host.Code, true
		}
		if h, ok := rt.HostTarget[domaintool.MaskSubdomain(c)]; ok && h != nil {
			return h.Host.Code, true
		}
		if code, ok := rt.HostTargetMoreDomain[c]; ok {
			return code, true
		}
		if code, ok := rt.HostTargetMoreDomain[domaintool.MaskSubdomain(c)]; ok {
			return code, true
		}
	}
	return "", false
}

// isManagedHost 判断一个域名(可带端口)是否由本 WAF 代理。
//
// 这里刻意复刻 ServeHTTP 的四表查找顺序（HostTargetNoPort → HostTarget → 泛域名
// → HostTargetMoreDomain → 宽松端口 *:port），而不是只查 HostTarget：
// 少查任何一张表，都会让「绑定了多域名」或「用了泛域名」的正常站点认证后回跳失败。
//
// 与 ServeHTTP 的唯一差别是本函数只读、不产生任何副作用。
func (waf *WafEngine) isManagedHost(hostWithPort string) bool {
	if hostWithPort == "" {
		return false
	}
	rt := waf.rt()
	host := strings.ToLower(strings.TrimSpace(hostWithPort))

	// 未带端口时按 ServeHTTP 的规则补默认端口。
	// 这里没有 r.TLS 可依据，所以 80/443 都试一遍——只是判定"是否受管"，
	// 放宽到两个端口不会引入越权，漏判反而会让 HTTPS 站点回跳失败。
	candidates := []string{host}
	if !strings.Contains(host, ":") {
		candidates = []string{host + ":443", host + ":80"}
	}

	// 刻意不认「不指定域名」的通配站点（HostTargetNoPort["*"] 与 HostTarget["*:port"]）。
	//
	// 那类站点会让任意 Host 头都命中路由表，于是 validateReturnTo 的
	// 绑定层(目标==票据里的域名)与路由表层(域名受本 WAF 代理)会同时失效——
	// 而票据里的域名本身就来自攻击者可控的 Host 头。结果就是：
	// 攻击者能让 WAF 自己签出一个指向 evil.com 的合法跳转，
	// 拿认证中心域名当跳板做钓鱼，并把一次性票据明文送进自己的服务器日志。
	//
	// 代价是「只配了通配站点」的部署无法回跳到深链接（登录后落到首页）。
	// 回跳目标必须是具名站点，这个方向上宁可少一点便利。
	//
	// lookupHostCode 也刻意不认 catch-all，与本函数保持同一口径 —— 别"顺手补全"。
	pure := utils.GetPureDomain(host)
	if _, ok := rt.HostTargetNoPort[pure]; ok && pure != "*" {
		return true
	}

	for _, c := range candidates {
		if _, ok := rt.HostTarget[c]; ok {
			return true
		}
		if _, ok := rt.HostTarget[domaintool.MaskSubdomain(c)]; ok {
			return true
		}
		if _, ok := rt.HostTargetMoreDomain[c]; ok {
			return true
		}
		if _, ok := rt.HostTargetMoreDomain[domaintool.MaskSubdomain(c)]; ok {
			return true
		}
	}
	return false
}
