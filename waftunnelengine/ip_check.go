package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"fmt"
	"net"
	"strings"
)

// CheckIPAccess 检查IP是否允许访问
// 参数: protocol 协议类型(TCP/UDP), clientIP 客户端IP, clientPort 客户端端口, serverPort 服务端口, tunnel 隧道配置
// 返回值: true表示允许访问，false表示拒绝访问
func CheckIPAccess(protocol string, clientIP string, clientPort string, serverPort string, tunnel model.Tunnel) bool {
	// 如果客户端IP为空，拒绝访问
	if clientIP == "" {
		zlog.Warn(fmt.Sprintf("客户端IP为空，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
			protocol, clientIP, clientPort, serverPort))
		return false
	}

	// 处理IP地址，去除端口部分（如果传入的是完整地址）
	if strings.Contains(clientIP, ":") {
		host, _, err := net.SplitHostPort(clientIP)
		if err != nil {
			zlog.Error(fmt.Sprintf("解析客户端IP失败 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s 错误:%s]",
				protocol, clientIP, clientPort, serverPort, err.Error()))
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
					zlog.Info(fmt.Sprintf("IP在黑名单CIDR范围内，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s CIDR:%s]",
						protocol, clientIP, clientPort, serverPort, ip))
					return false
				}
			} else if ip == clientIP {
				// 精确匹配
				zlog.Info(fmt.Sprintf("IP在黑名单中，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
					protocol, clientIP, clientPort, serverPort))
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
					zlog.Info(fmt.Sprintf("IP在白名单CIDR范围内，允许访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s CIDR:%s]",
						protocol, clientIP, clientPort, serverPort, ip))
					return true
				}
			} else if ip == clientIP {
				// 精确匹配
				zlog.Info(fmt.Sprintf("IP在白名单中，允许访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
					protocol, clientIP, clientPort, serverPort))
				return true
			}
		}

		// 如果有白名单但IP不在其中，拒绝访问
		zlog.Info(fmt.Sprintf("IP不在白名单中，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
			protocol, clientIP, clientPort, serverPort))
		return false
	}

	// 如果没有设置白名单，且不在黑名单中，则允许访问
	zlog.Info(fmt.Sprintf("隧道访问通过访问控制检查，允许访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
		protocol, clientIP, clientPort, serverPort))
	return true
}
