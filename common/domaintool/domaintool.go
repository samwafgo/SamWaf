package domaintool

import "strings"

func MaskSubdomain(domain string) string {
	// 分离域名和端口部分
	parts := strings.Split(domain, ":")
	host := parts[0]
	port := ""
	if len(parts) > 1 {
		port = ":" + parts[1]
	}

	// 分割域名部分
	subdomains := strings.Split(host, ".")
	if len(subdomains) <= 2 {
		// 如果只有根域名部分，直接返回
		return domain
	}

	// 将第一段替换为 "*"
	subdomains[0] = "*"
	maskedHost := strings.Join(subdomains, ".")

	return maskedHost + port
}
