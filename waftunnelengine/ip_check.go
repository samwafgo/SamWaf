package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"net"
	"strings"
)

// CheckIPAccess 检查IP是否允许访问
// 返回值: true表示允许访问，false表示拒绝访问
func CheckIPAccess(clientIP string, tunnel model.Tunnel) bool {
	// 如果客户端IP为空，拒绝访问
	if clientIP == "" {
		zlog.Warn("客户端IP为空，拒绝访问")
		return false
	}

	// 处理IP地址，去除端口部分
	if strings.Contains(clientIP, ":") {
		host, _, err := net.SplitHostPort(clientIP)
		if err != nil {
			zlog.Error("解析客户端IP失败: " + err.Error())
			return false
		}
		clientIP = host
	}

	// 检查黑名单（优先级高）
	if tunnel.DenyIp != "" {
		denyIPs := strings.Split(tunnel.DenyIp, ",")
		for _, ip := range denyIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}

			// 支持CIDR格式和精确匹配
			if strings.Contains(ip, "/") {
				// CIDR格式
				_, ipNet, err := net.ParseCIDR(ip)
				if err == nil && ipNet.Contains(net.ParseIP(clientIP)) {
					zlog.Info("IP " + clientIP + " 在黑名单CIDR " + ip + " 范围内，拒绝访问")
					return false
				}
			} else if ip == clientIP {
				// 精确匹配
				zlog.Info("IP " + clientIP + " 在黑名单中，拒绝访问")
				return false
			}
		}
	}

	// 检查白名单
	if tunnel.AllowIp != "" {
		// 白名单不为空，需要在白名单中才允许访问
		allowIPs := strings.Split(tunnel.AllowIp, ",")
		for _, ip := range allowIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}

			// 支持CIDR格式和精确匹配
			if strings.Contains(ip, "/") {
				// CIDR格式
				_, ipNet, err := net.ParseCIDR(ip)
				if err == nil && ipNet.Contains(net.ParseIP(clientIP)) {
					zlog.Info("IP " + clientIP + " 在白名单CIDR " + ip + " 范围内，允许访问")
					return true
				}
			} else if ip == clientIP {
				// 精确匹配
				zlog.Info("IP " + clientIP + " 在白名单中，允许访问")
				return true
			}
		}

		// 如果有白名单但IP不在其中，拒绝访问
		zlog.Info("IP " + clientIP + " 不在白名单中，拒绝访问")
		return false
	}

	// 如果没有设置白名单，且不在黑名单中，则允许访问
	zlog.Info("隧道访问 IP " + clientIP + " 通过访问控制检查，允许访问")
	return true
}
