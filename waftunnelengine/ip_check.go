package waftunnelengine

import (
	"SamWaf/model"
	"net"
	"strings"
)

// CheckIPAccess 检查固定名单是否允许访问。
func CheckIPAccess(_ string, clientIP string, _ string, _ string, tunnel model.Tunnel) bool {
	return fixedIPDenial(clientIP, tunnel) == ""
}

func fixedIPDenial(clientIP string, tunnel model.Tunnel) tunnelAccessDenial {
	if clientIP == "" {
		return denyInvalidPeer
	}
	if net.ParseIP(clientIP) == nil && strings.Contains(clientIP, ":") {
		host, _, err := net.SplitHostPort(clientIP)
		if err != nil {
			return denyInvalidPeer
		}
		clientIP = host
	}
	if tunnel.DenyIp != "" && fixedIPMatch(tunnel.DenyIp, clientIP) {
		return denyFixedList
	}
	if tunnel.AllowIp != "" && !fixedIPMatch(tunnel.AllowIp, clientIP) {
		return denyWhitelistMiss
	}
	return ""
}

func fixedIPMatch(list, clientIP string) bool {
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err == nil && network.Contains(net.ParseIP(clientIP)) {
				return true
			}
		} else if entry == clientIP {
			return true
		}
	}
	return false
}
