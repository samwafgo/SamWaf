package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"SamWaf/global"
)

// 「用户在管理端填写的对外拉取地址」。
//
//
// 默认策略：只允许公网目标。真实部署里确有人把黑名单/订阅源放在内网镜像上，
// 所以留一个带外逃生门 config.yml 的 security.outbound_allowed_hosts，
// 与 security.ssl_export_allowed_dirs 同款——只读 config，不进数据库、不经 API，
// 攻击者/OpenAPI Key/超管都改不动这份清单。留空 = 只允许公网（fail-closed）。

// outboundDialTimeout 单次建连超时；outboundTotalTimeout 是不显式传超时时的整体默认值。
const (
	outboundDialTimeout = 10 * time.Second
	outboundKeepAlive   = 30 * time.Second
)

// outboundAllowEntry 允许清单里的一条：精确主机名，或 IP/CIDR。
// 刻意不支持通配符——通配符在这种"绕过安全校验"的清单里太容易写宽。
type outboundAllowEntry struct {
	host  string     // 小写主机名，精确匹配
	ipNet *net.IPNet // IP 归一化成 /32、/128
}

// parseOutboundAllowList 解析 config.yml 里的允许清单。每次调用现读现解析：
// 清单极短、调用频率极低（只在发起对外请求时），省掉缓存失效的心智负担。
func parseOutboundAllowList() []outboundAllowEntry {
	raw := strings.TrimSpace(global.GCONFIG_OUTBOUND_ALLOWED_HOSTS)
	if raw == "" {
		return nil
	}
	entries := make([]outboundAllowEntry, 0, 4)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(item); err == nil {
			entries = append(entries, outboundAllowEntry{ipNet: ipNet})
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			entries = append(entries, outboundAllowEntry{ipNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}})
			continue
		}
		entries = append(entries, outboundAllowEntry{host: strings.ToLower(item)})
	}
	return entries
}

// IsOutboundHostAllowlisted 判断主机（域名或 IP 字面量）是否命中运营方带外声明的允许清单。
// 命中即跳过"必须公网"的判定——这正是内网镜像源的逃生门。
func IsOutboundHostAllowlisted(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	for _, e := range parseOutboundAllowList() {
		if e.host != "" && e.host == host {
			return true
		}
		if e.ipNet != nil && ip != nil && e.ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// isOutboundIPAllowlisted 判断具体 IP 是否命中清单里的 IP/CIDR 条目。
// 只在连接期用：主机名条目在这里无从比对，故不参与。
func isOutboundIPAllowlisted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, e := range parseOutboundAllowList() {
		if e.ipNet != nil && e.ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsAllowedOutboundURL 校验「用户可配的对外拉取地址」：仅 http/https，
// 且主机要么命中带外允许清单，要么解析出的所有 IP 均为公网。
// 返回 (是否允许, 拒绝原因)。
func IsAllowedOutboundURL(rawURL string) (bool, string) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false, "URL 解析失败"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false, "仅允许 http/https 协议"
	}
	host := u.Hostname()
	if host == "" {
		return false, "URL 缺少主机"
	}
	if IsOutboundHostAllowlisted(host) {
		return true, ""
	}
	// 走代理时本机不一定能解析目标域名（只有代理能解），这里再强行 LookupIP
	// 会把「只允许经代理出网」的部署整个打死。此时只保留协议 + IP 字面量判定，
	// 域名交给代理，与 SafeOutboundHTTPClient 的连接期处理保持一致。
	if outboundProxyFor(u) != nil {
		if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
			return false, fmt.Sprintf("目标IP %s 属于内网/环回/保留地址，已拒绝", host)
		}
		return true, ""
	}
	ok, reason := IsSafeOutboundHost(host)
	if !ok {
		// 主机名解析到内网时，若所有非公网解析结果都落在清单的 IP/CIDR 条目内，同样放行。
		// 连接期 safeOutboundDialContext 对每个真实拨号 IP 做同一判定，两层口径一致。
		if isHostCoveredByAllowlist(host) {
			return true, ""
		}
		return false, reason + "（确需访问内网源请在 config.yml 的 security.outbound_allowed_hosts 中声明该主机）"
	}
	return true, ""
}

// isHostCoveredByAllowlist 主机名的每条解析结果要么是公网、要么落在清单 IP/CIDR 条目内时才放行。
// 解析失败/无结果一律 false（fail-closed，与 IsSafeOutboundHost 同口径）。
func isHostCoveredByAllowlist(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if isPublicIP(ip) || isOutboundIPAllowlisted(ip) {
			continue
		}
		return false
	}
	return true
}

// PrecheckOutboundURL 保存配置时的对外地址预检（协议 / 主机字面量），供 api·service 层早报错用。
//
// 与 IsAllowedOutboundURL 的区别：域名解析失败时**放行**。保存配置的时刻网络可能还没通、
// 内网 DNS 可能还没配好，因为一次临时解析失败就不让人保存是过度拦截；
// 真正的安全边界在发起请求前（IsAllowedOutboundURL + SafeOutboundHTTPClient），
// 那里是 fail-closed 的。IP 字面量则在这里就能定死，不放过。
func PrecheckOutboundURL(rawURL string) (bool, string) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false, "URL 解析失败"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false, "仅允许 http/https 协议"
	}
	host := u.Hostname()
	if host == "" {
		return false, "URL 缺少主机"
	}
	if IsOutboundHostAllowlisted(host) {
		return true, ""
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
		return false, fmt.Sprintf("目标IP %s 属于内网/环回/保留地址，已拒绝（确需访问请在 config.yml 的 security.outbound_allowed_hosts 中声明）", host)
	}
	return true, ""
}

// RedactURLCredentials 去掉 URL 里的用户名/口令，供日志与审计使用。
// 订阅源/来源地址是用户填的，完全可能带 https://user:token@host/path；
// 原样写进审计表等于把凭证泄露给能看审计的其它角色。解析失败时按原样返回前缀截断，
// 宁可信息少一点也不能把可能带凭证的原串整个吐出去。
func RedactURLCredentials(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || !strings.Contains(s, "@") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		if err != nil {
			// 解析不了但含 @，无法确定哪段是凭证，直接抹掉 @ 之前的部分
			if i := strings.LastIndex(s, "@"); i >= 0 {
				return "redacted@" + s[i+1:]
			}
		}
		return s
	}
	// 用普通单词而不是 *** ：url.String() 会把 * 百分号编码成 %2A%2A%2A，读日志时很碍眼
	u.User = url.User("redacted")
	return u.String()
}

// outboundProxyFor 返回该 URL 实际会走的代理（没有则 nil）。
// 用 http.ProxyFromEnvironment 而不是裸扫环境变量，是为了正确处理 NO_PROXY：
// 被 NO_PROXY 排除的主机是直连的，那些连接必须继续受完整判定约束。
func outboundProxyFor(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	p, err := http.ProxyFromEnvironment(&http.Request{URL: u, Header: make(http.Header)})
	if err != nil {
		return nil
	}
	return p
}

// outboundProxyAddrs 收集环境变量里配置的代理地址（host:port，小写），
// 供连接期放行「连到代理本身」的那一跳——代理常在内网（如 127.0.0.1:8080），
// 硬判"连接目标必须是公网"会把这类正常部署打死。
func outboundProxyAddrs() map[string]bool {
	addrs := make(map[string]bool, 4)
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			continue
		}
		if !strings.Contains(v, "://") {
			v = "http://" + v
		}
		if pu, err := url.Parse(v); err == nil && pu.Host != "" {
			addrs[strings.ToLower(pu.Host)] = true
			if pu.Port() == "" {
				// 环境变量里可以省略端口，补上 scheme 默认端口，便于与实际 dial 地址比对
				switch strings.ToLower(pu.Scheme) {
				case "https":
					addrs[strings.ToLower(pu.Hostname())+":443"] = true
				default:
					addrs[strings.ToLower(pu.Hostname())+":80"] = true
				}
			}
		}
	}
	return addrs
}

// safeOutboundDialContext 连接期再校验一次真实目标 IP，堵住"URL 校验通过之后
// DNS 再改指内网"的重绑定/TOCTOU：先解析、逐个判定，再直连已判定过的那个 IP，
// 保证"校验的 IP"与"真正连的 IP"是同一个。
func safeOutboundDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: outboundDialTimeout, KeepAlive: outboundKeepAlive}

	// 连到代理本身的那一跳：真正的目标主机由 Transport 交给代理，这里判不了也不该判。
	// 被 NO_PROXY 排除的主机不会走到这个分支（Transport 会直连），仍受完整判定约束。
	if outboundProxyAddrs()[strings.ToLower(addr)] {
		return dialer.DialContext(ctx, network, addr)
	}

	// 主机名命中带外清单：运营方明确授权的内网镜像，按原样连接
	if IsOutboundHostAllowlisted(host) {
		return dialer.DialContext(ctx, network, addr)
	}

	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) && !isOutboundIPAllowlisted(ip) {
			return nil, fmt.Errorf("目标IP %s 属于内网/环回/保留地址，已拒绝", host)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("主机名 %s 解析失败: %v", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("主机名 %s 无解析结果", host)
	}
	// 只要应答里混进一个内网地址就整体拒绝：允许"挑公网的连"等于给
	// 攻击者一个稳定的重试窗口，最终仍会连上内网。
	for _, ia := range ips {
		if !isPublicIP(ia.IP) && !isOutboundIPAllowlisted(ia.IP) {
			return nil, fmt.Errorf("主机名 %s 解析到内网/保留地址 %s，已拒绝", host, ia.IP.String())
		}
	}
	var lastErr error
	for _, ia := range ips {
		conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), port))
		if e == nil {
			return conn, nil
		}
		lastErr = e
	}
	return nil, lastErr
}

// safeOutboundTransport 全进程共用一个 Transport：连接池要能复用，
// 而且每次 new 一个的话，定时任务扫一圈订阅渠道就会留下一堆各自持有空闲连接的池。
// 策略不会因此变陈旧——允许清单是在 dialer 内部现读的。
var safeOutboundTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           safeOutboundDialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          20,
	MaxIdleConnsPerHost:   2,
	IdleConnTimeout:       30 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// SafeOutboundHTTPClient 返回用于"用户可配对外地址"的 HTTP 客户端，三层防护：
//  1. 调用方先过 IsAllowedOutboundURL（初始 URL）；
//  2. 每一跳 30x 目标重新判定（含带外清单）；
//  3. 连接期按真实解析结果再判定一次并直连该 IP（防 DNS 重绑定）。
//
// 走代理的那一跳跳过第 3 层（连接目标是代理本身，判定无意义且会误伤内网代理部署）；
// 被 NO_PROXY 排除因而直连的主机仍受第 3 层约束。
// timeout <= 0 时不设整体超时，由调用方自行控制（下载大文件场景）。
func SafeOutboundHTTPClient(timeout time.Duration) *http.Client {
	client := &http.Client{
		Transport: safeOutboundTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("重定向次数过多")
			}
			host := req.URL.Hostname()
			if IsOutboundHostAllowlisted(host) {
				return nil
			}
			// 走代理时本机可能解析不了目标域名，与 IsAllowedOutboundURL 保持同一口径
			if outboundProxyFor(req.URL) != nil {
				if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
					return fmt.Errorf("重定向目标不被允许: 目标IP %s 属于内网/环回/保留地址", host)
				}
				return nil
			}
			if ok, reason := IsSafeOutboundHost(host); !ok {
				return fmt.Errorf("重定向目标不被允许: %s", reason)
			}
			return nil
		},
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}
