package libinjection

import (
	"SamWaf/innerbean"
	"strings"
)

// 独特工具指纹：在 URL 或 User-Agent 命中即判定。
var scannerSigsAny = []string{
	"sqlmap", "nikto", "nessus", "acunetix", "appscan",
	"masscan", "wpscan", "gobuster", "dirbuster", "feroxbuster",
	"ffuf", "wfuzz", "zgrab", "openvas", "w3af",
	"skipfish", "whatweb", "netsparker",
}

// 像普通英文/科学词的工具名(nuclei/nmap/arachni)：只在 UA 里判，避免正常 URL/内容误伤。
var scannerSigsUA = []string{"nuclei", "nmap", "arachni"}

// IsScan 检测已知扫描/攻击工具。URL+UA 一起查、大小写不敏感。
// 未纳入 curl/python-requests/Go-http-client 等常见客户端，避免误伤。
func IsScan(log *innerbean.WebLog) bool {
	urlAndUA := strings.ToLower(log.URL + "\n" + log.USER_AGENT)
	for _, s := range scannerSigsAny {
		if strings.Contains(urlAndUA, s) {
			return true
		}
	}
	ua := strings.ToLower(log.USER_AGENT)
	for _, s := range scannerSigsUA {
		if strings.Contains(ua, s) {
			return true
		}
	}
	return false
}
