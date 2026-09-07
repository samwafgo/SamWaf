package accessgate

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// hostkey.go 负责把 r.Host 归一化成「站点身份」，并由它派生令牌 Cookie 名。
//
// 这里是整个 Access 模块的安全支点，两个下游共用同一份结果：
//   - 令牌 Cookie 名的派生（TokenCookieName）
//   - 令牌绑定的比对（AccessState.matchBindings）
// 两者若各归一化一次，一旦出现差异就会变成「Cookie 找得到、绑定判不过」的死循环。

// NormalizeHost 归一化 host[:port]。isTLS 决定默认端口怎么算。
//
// 默认端口的去除必须按 scheme 判定：若不看 scheme 一律去掉 :80 与 :443，
// HTTP 站点的 oa.x:443 与 HTTPS 站点的 oa.x 会归一化成同一个字符串，
// 令牌于是在两个不同站点之间互通。
func NormalizeHost(host string, isTLS bool) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return ""
	}
	// Host 头不该带用户信息，带了就取 @ 之后的部分，
	// 免得 a@oa.x 与 oa.x 各占一个 Cookie 槽位。
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	hostPart, port := splitHostPort(h)
	// oa.x. 是 oa.x 的 FQDN 绝对形式，同一个站点
	hostPart = strings.TrimSuffix(hostPart, ".")
	if hostPart == "" {
		return ""
	}
	if (isTLS && port == "443") || (!isTLS && port == "80") {
		port = ""
	}
	if port == "" {
		return hostPart
	}
	return hostPart + ":" + port
}

// splitHostPort 拆主机与端口，IPv6 的方括号原样保留。
//
// 不用 net.SplitHostPort：它在没有端口时返回错误，而这里「没有端口」是常态。
// 未加方括号的裸 IPv6（如 ::1）按 RFC 7230 本就不是合法 Host，
// 这里按「整串都是主机」处理，不去猜哪个冒号是端口分隔符。
func splitHostPort(h string) (string, string) {
	if strings.HasPrefix(h, "[") {
		i := strings.Index(h, "]")
		if i < 0 {
			return h, ""
		}
		rest := h[i+1:]
		if strings.HasPrefix(rest, ":") {
			return h[:i+1], rest[1:]
		}
		return h[:i+1], ""
	}
	if strings.Count(h, ":") == 1 {
		i := strings.Index(h, ":")
		return h[:i], h[i+1:]
	}
	return h, ""
}

// TokenCookieName 派生业务域子令牌的 Cookie 名：prefix + "_tk_" + sha256(host)[:8]。
//
// 为什么不能所有站点共用一个名字：Cookie 存储不区分端口（RFC 6265），
// oa.x:7013 与 oa.x:7014 这两个独立站点会争抢同一个槽位，后登录的覆盖先登录的；
// 而令牌又是按 host 绑定的，被覆盖的那个站点从此永远验不过。
//
// 取 8 字节而不是 4：碰撞不构成越权（绑定仍按 host 严格比对），只退化成上面那个
// 覆盖问题，但加宽的成本是零。
//
// 新名字仍以 CookiePrefix 开头，所以 stripAccessCookies 的前缀剥离无需改动。
func TokenCookieName(prefix, normalizedHost string) string {
	if prefix == "" {
		prefix = disabledDefault.CookiePrefix
	}
	if normalizedHost == "" {
		// 正常路径走不到：能进网关说明请求已按 Host 匹配到站点。
		// 真走到了就回退到旧名字，保持可用而不是把人锁在外面。
		return prefix + "_tk"
	}
	sum := sha256.Sum256([]byte(normalizedHost))
	return prefix + "_tk_" + hex.EncodeToString(sum[:8])
}

// LegacyTokenCookieName 是改造前所有站点共用的固定名字，只用于升级后清理残留。
func LegacyTokenCookieName(prefix string) string {
	if prefix == "" {
		prefix = disabledDefault.CookiePrefix
	}
	return prefix + "_tk"
}
