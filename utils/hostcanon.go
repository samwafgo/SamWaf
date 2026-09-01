package utils

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalHost 把站点域名归一成路由表唯一 key：IDNA A-label（Punycode）+ ASCII 小写。
//
// DNS 域名大小写不敏感；浏览器对中文域名发的是 Punycode Host / SNI。
// 注册与查找必须走同一函数，否则会出现「要绑中文又绑转码」「Example.COM 对不上 example.com」。
//
// 入参是纯域名（不要带端口）。`*`、`*.example.com`、IP 原样归一；IDNA 失败时退回 Trim+小写，查找路径不能因非法 Host 头 panic。
func CanonicalHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.TrimSuffix(s, ".")
	if s == "*" {
		return "*"
	}

	if ip := net.ParseIP(unbracketHost(s)); ip != nil {
		return ip.String()
	}

	wildcard := false
	rest := s
	if strings.HasPrefix(s, "*.") {
		wildcard = true
		rest = s[2:]
		if rest == "" {
			return "*"
		}
	}

	ascii, err := idna.Lookup.ToASCII(rest)
	if err != nil || ascii == "" {
		ascii = strings.ToLower(rest)
	} else {
		ascii = strings.ToLower(ascii)
	}
	if wildcard {
		return "*." + ascii
	}
	return ascii
}

// CanonicalHostPort 归一「域名」或「域名:端口」。端口数字保持不变。
func CanonicalHostPort(raw string) string {
	h, p, hasPort := SplitHostPortLoose(raw)
	if !hasPort {
		return CanonicalHost(raw)
	}
	return CanonicalHost(h) + ":" + p
}

// SplitHostPortLoose 拆 Host 头里的域名与端口。无端口时 hasPort=false，host 为原文。
func SplitHostPortLoose(hostPort string) (host, port string, hasPort bool) {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return "", "", false
	}
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort, "", false
	}
	return h, p, true
}

// CanonicalRequestHost 把 HTTP 请求 Host 归一成路由表 key（host:port）及端口。
// 请求未带端口时：HTTPS 默认 443，HTTP 默认 80（与 ServeHTTP 原逻辑一致）。
func CanonicalRequestHost(rHost string, isTLS bool) (hostPort, port string) {
	defaultPort := "80"
	if isTLS {
		defaultPort = "443"
	}
	h, p, hasPort := SplitHostPortLoose(rHost)
	if !hasPort {
		return CanonicalHost(rHost) + ":" + defaultPort, defaultPort
	}
	return CanonicalHost(h) + ":" + p, p
}

// SplitBindMoreHost 拆「绑定多域名」文本：按行、去空白、丢空行。
func SplitBindMoreHost(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func unbracketHost(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}
