package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"net"
	"net/netip"
	"strings"
	"time"

	"go.uber.org/zap"
)

type tunnelAccessDenial string

const (
	denyPolicyUnavailable tunnelAccessDenial = "准入配置尚未就绪"
	denyInvalidPeer       tunnelAccessDenial = "客户端 IP 无效"
	denyFixedList         tunnelAccessDenial = "来源 IP 命中固定禁止名单"
	denyWhitelistMiss     tunnelAccessDenial = "来源 IP 未命中固定允许名单或有效动态白名单"
	denyInvalidSchedule   tunnelAccessDenial = "访问时段配置无效"
	denyOutsideSchedule   tunnelAccessDenial = "当前时间不在允许访问时段内"
	denyInvalidRegion     tunnelAccessDenial = "地区防御配置无效"
	denyRegionUnknown     tunnelAccessDenial = "国家未知，地区防御设置为禁止"
	denyRegionRule        tunnelAccessDenial = "命中地区防御禁止规则"
	denyRegionFallback    tunnelAccessDenial = "未命中地区规则，默认动作为禁止"
)

type tunnelAccessPolicy struct {
	tunnel        model.Tunnel
	region        model.TunnelRegionProtection
	invalidRegion bool
	enhanced      bool
	whitelist     bool
	allow         []netip.Prefix
	deny          []netip.Prefix
	dynamic       map[netip.Addr]time.Time
}

func tunnelPrefixes(list string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			prefixes = append(prefixes, prefix.Masked())
		} else if ip, err := netip.ParseAddr(entry); err == nil && ip.Zone() == "" {
			ip = ip.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return prefixes
}

func tunnelPrefixMatch(list []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range list {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func tunnelPeerIP(peer string) netip.Addr {
	ip, err := netip.ParseAddr(peer)
	if err != nil {
		if host, _, err := net.SplitHostPort(peer); err == nil {
			ip, _ = netip.ParseAddr(host)
		}
	}
	return ip.WithZone("").Unmap()
}

func tunnelRegionDenial(region model.TunnelRegionProtection, country string) tunnelAccessDenial {
	if country == "" {
		if region.Unknown == "deny" {
			return denyRegionUnknown
		}
		return ""
	}
	for _, rule := range region.Rules {
		if !rule.Enabled {
			continue
		}
		if (rule.Operator == "eq" && country == rule.Country) || (rule.Operator == "ne" && country != rule.Country) {
			if rule.Action != "allow" {
				return denyRegionRule
			}
			return ""
		}
	}
	if region.Fallback == "deny" {
		return denyRegionFallback
	}
	return ""
}

func tunnelCountry(ip string) string {
	if manager := global.GIPLOCATION_MANAGER; manager != nil {
		return manager.LookupCountryCode(ip)
	}
	return ""
}

func (waf *WafTunnelEngine) checkTunnelAccess(clientIP, tunnelID string) tunnelAccessDenial {
	state, ok := waf.ddns.states.Load(tunnelID)
	if !ok {
		return denyPolicyUnavailable
	}
	policy := state.(*tunnelProtectionRuntime).snapshot.Load()
	if policy == nil {
		return denyPolicyUnavailable
	}
	return policy.denial(clientIP, time.Now(), tunnelCountry)
}

func (p *tunnelAccessPolicy) denial(clientIP string, now time.Time, lookupCountry func(string) string) tunnelAccessDenial {
	if !p.enhanced {
		if reason := fixedIPDenial(clientIP, p.tunnel); reason != "" {
			return reason
		}
		return tunnelTimeDenial(p.tunnel.AllowedTimeRanges, now)
	}
	ip := tunnelPeerIP(clientIP)
	if !ip.IsValid() {
		return denyInvalidPeer
	}
	if tunnelPrefixMatch(p.deny, ip) {
		return denyFixedList
	}
	if p.whitelist && !tunnelPrefixMatch(p.allow, ip) && !now.Before(p.dynamic[ip]) {
		return denyWhitelistMiss
	}
	if reason := tunnelTimeDenial(p.tunnel.AllowedTimeRanges, now); reason != "" {
		return reason
	}
	if p.invalidRegion {
		return denyInvalidRegion
	}
	if p.region.Enabled {
		return tunnelRegionDenial(p.region, lookupCountry(ip.String()))
	}
	return ""
}

func logTunnelAccessDenied(reason tunnelAccessDenial, protocol, clientIP, clientPort string, serverPort int, tunnelID string) {
	zlog.WarnFields("[隧道防护] 拒绝访问："+string(reason),
		zap.String("protocol", protocol), zap.String("tunnel_id", tunnelID),
		zap.String("client_ip", clientIP), zap.String("client_port", clientPort), zap.Int("server_port", serverPort))
}
