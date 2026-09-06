package utils

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/wafenginecore/clientip"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// ManageTrustedProxyKeywordPrivate 可信代理网段支持的关键字：展开为内网+环回网段，
// 容器/内网部署填一个词即可，可与具体网段混写。
const ManageTrustedProxyKeywordPrivate = "private"

// maxManageProxyHops 单个代理头最多解析的跳数。代理链再长也到不了这个量级，
// 超过即视为畸形/构造流量，整头丢弃：避免超大头把逐跳结构撑成几十 MB（该逻辑在登录认证之前执行）。
const maxManageProxyHops = 64

// maxManageProxyHeaderEcho 诊断回显的头原文长度上限
const maxManageProxyHeaderEcho = 512

// maxManageProxyHopEcho 诊断回显的单跳原文长度上限（合法 IP 最长 45 字符，超出必是畸形值）
const maxManageProxyHopEcho = 64

// manageTrustedPrivateCIDRs private 关键字展开的网段（与手册、前端提示保持一致）
var manageTrustedPrivateCIDRs = func() []*net.IPNet {
	list := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"}
	nets := make([]*net.IPNet, 0, len(list))
	for _, c := range list {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// 管理端真实IP的取值原因（诊断接口回显用）
const (
	ManageIPReasonNoProxyHeader      = "no_proxy_header"      // 未配代理头 → 网络层IP
	ManageIPReasonPeerUntrusted      = "peer_untrusted"       // 直连对端不属可信代理 → 网络层IP
	ManageIPReasonNoValidHeader      = "no_valid_header"      // 头缺失或无合法IP → 网络层IP
	ManageIPReasonOverBroadGate      = "overbroad_gate"       // 对端只因过宽网段被判可信，头里无可验证结论 → 网络层IP
	ManageIPReasonRightmostUntrusted = "rightmost_untrusted"  // 从右往左第一个非可信hop
	ManageIPReasonAllTrustedLeftmost = "all_trusted_leftmost" // 整条链都可信 → 取最左
)

// ManageClientIPHop 代理头里的一跳
type ManageClientIPHop struct {
	IP        string `json:"ip"`
	Valid     bool   `json:"valid"`
	Trusted   bool   `json:"trusted"`
	TrustedBy string `json:"trusted_by"`
}

// ManageClientIPHeaderTrace 单个代理头的判定过程
type ManageClientIPHeaderTrace struct {
	Name    string              `json:"name"`
	Value   string              `json:"value"`
	Hops    []ManageClientIPHop `json:"hops"`
	Used    bool                `json:"used"`
	TooLong bool                `json:"too_long"` // 跳数超上限被整头丢弃
}

// ManageClientIPTrace 管理端真实IP的完整判定过程，供诊断接口回显
type ManageClientIPTrace struct {
	RemoteIP       string                      `json:"remote_ip"`
	ProxyHeader    string                      `json:"proxy_header"`
	TrustedProxies string                      `json:"trusted_proxies"`
	CDNProvider    string                      `json:"cdn_provider"`
	PeerTrusted    bool                        `json:"peer_trusted"`
	PeerTrustedBy  string                      `json:"peer_trusted_by"`
	GateOverBroad  bool                        `json:"gate_over_broad"` // 对端仅因过宽网段(如 0.0.0.0/0)被判可信
	Headers        []ManageClientIPHeaderTrace `json:"headers"`
	ClientIP       string                      `json:"client_ip"`
	Reason         string                      `json:"reason"`
}

// GetManageClientIP 获取管理端客户端真实IP。
// 安全默认：未配置代理头（GCONFIG_MANAGE_PROXY_HEADER 为空）时直接返回网络层 IP（c.RemoteIP()）。
// 即便配置了代理头，也仅当"直连对端 c.RemoteIP() 属于可信代理网段 GCONFIG_MANAGE_TRUSTED_PROXIES"
// 时才采信代理头；否则一律用网络层 IP。防止任意直连客户端伪造 X-Forwarded-For/X-Real-IP 绕过
// 登录错误锁定 / 管理端 IP 白名单 / 令牌 IP 绑定。
func GetManageClientIP(c *gin.Context) string {
	return TraceManageClientIP(c).ClientIP
}

// TraceManageClientIP 与 GetManageClientIP 同一套判定，额外记录判定过程供诊断接口回显。
//
// 取值分两轮，先要可验证的结论、拿不到才用不可验证的兜底：
//
//	第一轮：逐个头找"最右侧的非可信 hop"。反向代理按追加语义(nginx $proxy_add_x_forwarded_for)
//	        把真实客户端 IP 追加在右侧、客户端伪造的值留在左侧，这个结论有代理链背书。
//	第二轮：所有头的 hop 都落在可信网段内(可信网段覆盖到真实客户端时会这样，如内网管理员+内网网段)，
//	        此时取最左侧的链起点。这个结论与"客户端伪造了一个网段内的 IP"在协议上不可区分，
//	        因此只在可信网段本身够窄时才用——网段宽到 0.0.0.0/0 就等于没有闸门，一律回退网络层 IP。
func TraceManageClientIP(c *gin.Context) ManageClientIPTrace {
	trace := ManageClientIPTrace{
		RemoteIP:       c.RemoteIP(),
		ProxyHeader:    global.GCONFIG_MANAGE_PROXY_HEADER,
		TrustedProxies: global.GCONFIG_MANAGE_TRUSTED_PROXIES,
		CDNProvider:    global.GCONFIG_MANAGE_CDN_PROVIDER,
	}
	trace.ClientIP = trace.RemoteIP

	if strings.TrimSpace(trace.ProxyHeader) == "" {
		trace.Reason = ManageIPReasonNoProxyHeader
		return trace
	}
	var narrowGate bool
	trace.PeerTrusted, trace.PeerTrustedBy, narrowGate = trustManageProxy(trace.RemoteIP)
	if !trace.PeerTrusted {
		trace.Reason = ManageIPReasonPeerUntrusted
		return trace
	}
	trace.GateOverBroad = !narrowGate
	if !narrowGate {
		// 可信网段宽到等于没有闸门：头里的任何值都与伪造不可区分，连读都不读，按网络层 IP 识别。
		// 注意不能只在下面第二轮拦——0.0.0.0/0 是 4 字节掩码，net.IPNet.Contains 对 IPv6 地址
		// 因长度不匹配恒为 false，异族的伪造值会被第一轮当成"非可信 hop"直接采信。
		trace.Reason = ManageIPReasonOverBroadGate
		return trace
	}

	for _, header := range strings.Split(trace.ProxyHeader, ",") {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		trace.Headers = append(trace.Headers, buildManageHeaderTrace(c, header))
	}

	// 第一轮：可验证的结论
	for i := range trace.Headers {
		for j := len(trace.Headers[i].Hops) - 1; j >= 0; j-- {
			hop := trace.Headers[i].Hops[j]
			if hop.Valid && !hop.Trusted {
				trace.Headers[i].Used = true
				trace.ClientIP = normalizeIPText(hop.IP)
				trace.Reason = ManageIPReasonRightmostUntrusted
				return trace
			}
		}
	}
	// 第二轮：不可验证的兜底，闸门够窄才用
	for i := range trace.Headers {
		for _, hop := range trace.Headers[i].Hops {
			if !hop.Valid {
				continue
			}
			trace.Headers[i].Used = true
			trace.ClientIP = normalizeIPText(hop.IP)
			trace.Reason = ManageIPReasonAllTrustedLeftmost
			warnManageProxyChainAllTrusted()
			return trace
		}
	}
	// 所有头都缺失或无合法 IP
	trace.Reason = ManageIPReasonNoValidHeader
	return trace
}

// buildManageHeaderTrace 解析单个代理头的逐跳可信判定
func buildManageHeaderTrace(c *gin.Context, header string) ManageClientIPHeaderTrace {
	raw := c.GetHeader(header)
	headerTrace := ManageClientIPHeaderTrace{Name: header, Value: raw}
	if len(headerTrace.Value) > maxManageProxyHeaderEcho {
		headerTrace.Value = headerTrace.Value[:maxManageProxyHeaderEcho]
	}
	if raw == "" {
		return headerTrace
	}
	// 先数逗号再切：超大头直接丢弃，不让 Split 先分配一遍
	if strings.Count(raw, ",") >= maxManageProxyHops {
		headerTrace.TooLong = true
		return headerTrace
	}
	for _, part := range strings.Split(raw, ",") {
		ip := strings.TrimSpace(part)
		hop := ManageClientIPHop{IP: ip}
		if len(hop.IP) > maxManageProxyHopEcho {
			hop.IP = hop.IP[:maxManageProxyHopEcho]
		}
		if IsValidIPv4(ip) || IsValidIPv6(ip) {
			hop.Valid = true
			// 只有足够具体的条目才能把某一跳认定成基础设施：过宽条目（如与窄条目混写的 0.0.0.0/0）
			// 若参与 hop 判定，会把攻击者伪造的公网 IP 一并盖成"可信"，反过来把它推给第二轮采信。
			if trusted, by, narrow := trustManageProxy(ip); trusted && narrow {
				hop.Trusted, hop.TrustedBy = true, by
			}
		}
		headerTrace.Hops = append(headerTrace.Hops, hop)
	}
	return headerTrace
}

// normalizeIPText 把同一地址的多种写法归一（如 ::ffff:1.2.3.4 → 1.2.3.4），
// 避免下游按字符串比较的 IP 白名单/登录锁定计数/令牌IP绑定把同一个来源当成多个。
func normalizeIPText(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

// trustManageProxy 判断 IP 是否属于管理端可信代理：
// 引用的 CDN 厂商回源段 ∪ GCONFIG_MANAGE_TRUSTED_PROXIES（CIDR / 单 IP / private 关键字，逗号分隔）。
// 第三个返回值 narrow 表示命中的条目是否足够具体——过宽的条目（如 0.0.0.0/0）能放行闸门，
// 但不足以支撑第二轮那个不可验证的兜底结论。两者都为空 → 不信任任何代理头（安全默认）。
func trustManageProxy(ip string) (trusted bool, by string, narrow bool) {
	ip = strings.TrimSpace(ip)
	if global.GCONFIG_MANAGE_CDN_PROVIDER != "" && clientip.IsProviderIP(global.GCONFIG_MANAGE_CDN_PROVIDER, ip) {
		return true, "cdn:" + global.GCONFIG_MANAGE_CDN_PROVIDER, true
	}
	if global.GCONFIG_MANAGE_TRUSTED_PROXIES == "" {
		return false, "", false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, "", false
	}
	matched, matchedBy := false, ""
	for _, entry := range strings.Split(global.GCONFIG_MANAGE_TRUSTED_PROXIES, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, ManageTrustedProxyKeywordPrivate) {
			for _, ipnet := range manageTrustedPrivateCIDRs {
				if ipnet.Contains(parsed) {
					return true, "private:" + ipnet.String(), true
				}
			}
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil || !ipnet.Contains(parsed) {
				continue
			}
			if !isOverBroadProxyCIDR(ipnet) {
				return true, "cidr:" + entry, true
			}
			// 过宽条目先记下，继续找有没有更具体的条目也命中
			matched, matchedBy = true, "cidr:"+entry
			continue
		}
		if single := net.ParseIP(entry); single != nil && single.Equal(parsed) {
			return true, "ip:" + entry, true
		}
	}
	return matched, matchedBy, false
}

// isOverBroadProxyCIDR 判断网段是否宽到不足以充当"可信代理"的判据。
// 阈值取到 IPv4 /4、IPv6 /3：真实部署里最宽的写法是 10.0.0.0/8 与 fc00::/7，都在阈值之内；
// 0.0.0.0/0、::/0 以及把全网拆成两半的 0.0.0.0/1 + 128.0.0.0/1 这类写法都会被判为过宽。
func isOverBroadProxyCIDR(ipnet *net.IPNet) bool {
	ones, bits := ipnet.Mask.Size()
	if bits == 32 {
		return ones <= 4
	}
	return ones <= 3
}

// manageProxyAllTrustedWarnAt 兜底取值告警限频（unix 秒）
var manageProxyAllTrustedWarnAt int64

// warnManageProxyChainAllTrusted 走到第二轮兜底时提醒一次：这个取值无法与伪造区分。
// 每 10 分钟最多一条，避免高频请求刷爆日志。
func warnManageProxyChainAllTrusted() {
	now := time.Now().Unix()
	last := atomic.LoadInt64(&manageProxyAllTrustedWarnAt)
	if now-last < 600 || !atomic.CompareAndSwapInt64(&manageProxyAllTrustedWarnAt, last, now) {
		return
	}
	zlog.Warn("管理端代理头里的所有IP都落在可信代理网段内，已按代理链起点取真实客户端IP。该取值无法与客户端伪造区分，建议把 security.manage_trusted_proxies 收窄到上游代理自身的地址")
}

// IsValidManageTrustedProxyEntry 校验可信代理网段的单个条目（CIDR / 单 IP / private 关键字）
func IsValidManageTrustedProxyEntry(entry string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return true
	}
	if strings.EqualFold(entry, ManageTrustedProxyKeywordPrivate) {
		return true
	}
	if strings.Contains(entry, "/") {
		_, _, err := net.ParseCIDR(entry)
		return err == nil
	}
	return net.ParseIP(entry) != nil
}

// ManageTrustedProxiesHasOverBroad 判断可信代理网段里是否有过宽的条目（如 0.0.0.0/0、::/0），
// 返回命中的条目原文。这类条目只能放行闸门，不足以据此从代理头里认定真实客户端 IP。
func ManageTrustedProxiesHasOverBroad(trustedProxies string) (bool, string) {
	for _, entry := range strings.Split(trustedProxies, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" || !strings.Contains(entry, "/") {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil && isOverBroadProxyCIDR(ipnet) {
			return true, entry
		}
	}
	return false, ""
}
