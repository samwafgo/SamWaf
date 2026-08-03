package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafenginecore/clientip"
	"net"
	"net/http"
	"strings"
)

// getBizClientIP 业务侧"真实客户端 IP"提取加固版，镜像管理侧 utils.GetManageClientIP 的可信思路。
// 关键向后兼容：host.IPSourceMode 为空(""，存量站点默认)时，行为与旧版 getClientIP 完全一致
// ——按 GCONFIG_RECORD_PROXY_HEADER 取 X-Forwarded-For 最左第一个。用户显式选择加固模式后才改变取值。
//
// 各模式：
//
//	""(兼容)   : 旧行为，取配置头最左第一个(可被伪造，仅为不破坏存量)
//	nic        : 网络层直连 IP(r.RemoteAddr)
//	header     : 取指定头(IPRealHeader)，不校验来源(已知代理但无回源段时用)
//	xff_depth  : 从右往左跳过可信代理，取最右非可信 hop
//	cdn_preset : 仅当直连对端属于该 CDN 厂商回源段(或用户手填可信网段)才信任其真实 IP 头，否则视为伪造回退网络层
func (waf *WafEngine) getBizClientIP(r *http.Request, host model.Hosts) (error, string, string) {
	switch host.IPSourceMode {
	case "nic":
		return splitRemoteAddr(r.RemoteAddr)
	case "header":
		if ip := headerFirstValidIP(r, host.IPRealHeader); ip != "" {
			return nil, ip, "0"
		}
		return splitRemoteAddr(r.RemoteAddr) // 头缺失/非法 → 回退网络层
	case "xff_depth":
		if ip := extractXFFDepth(r, host); ip != "" {
			return nil, ip, "0"
		}
		return splitRemoteAddr(r.RemoteAddr)
	case "cdn_preset":
		return waf.extractCDNPreset(r, host)
	default:
		// "" 兼容：完全保持旧行为
		return waf.getClientIP(r, strings.Split(global.GCONFIG_RECORD_PROXY_HEADER, ",")...)
	}
}

// splitRemoteAddr 从 r.RemoteAddr 拆出网络层 IP 与端口
func splitRemoteAddr(remoteAddr string) (error, string, string) {
	ip, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return err, "", ""
	}
	return nil, ip, port
}

// headerFirstValidIP 取指定头逗号分隔的第一个合法 IP(头名为空或无合法值返回空串)
func headerFirstValidIP(r *http.Request, header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	val := r.Header.Get(header)
	if val == "" {
		return ""
	}
	for _, part := range strings.Split(val, ",") {
		ip := strings.TrimSpace(part)
		if utils.IsValidIPv4(ip) || utils.IsValidIPv6(ip) {
			return ip
		}
	}
	return ""
}

// extractXFFDepth 从 X-Forwarded-For(或 IPRealHeader 指定头)按可信代理/层深取真实客户端 IP。
// 若配置了可信网段 IPTrustProxies：从右往左跳过可信 hop，取最右非可信 IP(同管理侧语义)。
// 否则按 IPTrustDepth：取从右起第 depth 个 IP(depth 默认 1，即最右)。
func extractXFFDepth(r *http.Request, host model.Hosts) string {
	header := host.IPRealHeader
	if strings.TrimSpace(header) == "" {
		header = "X-Forwarded-For"
	}
	val := r.Header.Get(header)
	if val == "" {
		return ""
	}
	var parts []string
	for _, p := range strings.Split(val, ",") {
		ip := strings.TrimSpace(p)
		if utils.IsValidIPv4(ip) || utils.IsValidIPv6(ip) {
			parts = append(parts, ip)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	trusted := strings.TrimSpace(host.IPTrustProxies)
	if trusted != "" {
		// 从右往左取第一个非可信 hop
		for i := len(parts) - 1; i >= 0; i-- {
			if !ipInCIDRList(parts[i], trusted) {
				return parts[i]
			}
		}
		return "" // 全是可信代理
	}
	depth := host.IPTrustDepth
	if depth < 1 {
		depth = 1
	}
	idx := len(parts) - depth
	if idx < 0 || idx >= len(parts) {
		return ""
	}
	return parts[idx]
}

// extractCDNPreset cdn_preset 模式：仅当直连对端属于所选厂商回源段(或用户手填可信网段)时才信任其真实 IP 头。
func (waf *WafEngine) extractCDNPreset(r *http.Request, host model.Hosts) (error, string, string) {
	err, netIP, _ := splitRemoteAddr(r.RemoteAddr)
	if err != nil {
		return err, "", ""
	}
	// 来源可信判定：厂商官方回源段(Tier A 自动拉取) 或 用户手填网段(Tier B/兜底)
	sourceTrusted := clientip.IsProviderIP(host.CDNProvider, netIP)
	if !sourceTrusted && strings.TrimSpace(host.IPTrustProxies) != "" {
		sourceTrusted = ipInCIDRList(netIP, host.IPTrustProxies)
	}
	if sourceTrusted {
		header := host.IPRealHeader
		if strings.TrimSpace(header) == "" {
			header = clientip.DefaultHeader(host.CDNProvider)
		}
		if ip := headerFirstValidIP(r, header); ip != "" {
			return nil, ip, "0"
		}
	}
	// 来源不可信或头缺失 → 回退网络层(宁可少信任，不可采信伪造)
	return nil, netIP, "0"
}

// ipInCIDRList 判断 ip 是否落在逗号分隔的 CIDR/IP 列表内
func ipInCIDRList(ip, csv string) bool {
	for _, entry := range strings.Split(csv, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if utils.CheckIPInCIDR(ip, entry) {
			return true
		}
	}
	return false
}
