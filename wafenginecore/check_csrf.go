package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"strings"
)

// CheckCsrf CSRF 跨站请求伪造防护：对状态变更请求(POST/PUT/DELETE/PATCH)校验 Origin/Referer 来源是否属于本站
func (waf *WafEngine) CheckCsrf(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}

	cfg := model.ParseCsrfConfig(hostTarget.Host.CsrfJSON)
	// 未开启直接放行
	if cfg.IsEnable == 0 {
		return result
	}

	// 安全方法（GET/HEAD/OPTIONS 等）不做 CSRF 校验
	if !isCsrfProtectedMethod(r.Method, cfg.ProtectMethods) {
		return result
	}

	// 命中排除路径前缀则放行（webhook/回调/Token鉴权API 等）
	if isCsrfExcludedPath(r.URL.Path, cfg.ExcludePaths) {
		return result
	}

	// 构建允许来源 host 集合：本站域名 + 绑定多域名 + 额外允许来源
	bindMoreHost := ""
	if hostTarget != nil {
		bindMoreHost = hostTarget.Host.BindMoreHost
	}
	allowedHosts := buildCsrfAllowedHosts(r.Host, bindMoreHost, cfg.AllowedOrigins)

	// Origin 是权威信号：存在且非 "null" 时直接据此判定
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && !strings.EqualFold(origin, "null") {
		originHost := extractHostFromOrigin(origin)
		if isCsrfOriginAllowed(originHost, allowedHosts) {
			return result
		}
		return csrfBlock(weblogbean)
	}

	// Origin 缺失/为 null 时退化到 Referer 判定
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer != "" {
		refererHost := extractHostFromOrigin(referer)
		if isCsrfOriginAllowed(refererHost, allowedHosts) {
			return result
		}
		return csrfBlock(weblogbean)
	}

	// Origin 与 Referer 均缺失：按配置决定放行或拦截
	if cfg.AllowEmptyRef == 1 {
		return result
	}
	return csrfBlock(weblogbean)
}

// csrfBlock 统一构造 CSRF 拦截结果
func csrfBlock(weblogbean *innerbean.WebLog) detection.Result {
	weblogbean.RISK_LEVEL = 2 // 有害
	return detection.Result{
		JumpGuardResult: false,
		IsBlock:         true,
		Title:           "CSRF跨站请求伪造防护",
		Content:         "检测到跨站请求伪造(CSRF)，已被拦截",
	}
}

// isCsrfProtectedMethod 判断请求方法是否在需保护的方法列表内（逗号分隔，大小写不敏感）
func isCsrfProtectedMethod(method string, protectMethods string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return false
	}
	for _, m := range strings.Split(protectMethods, ",") {
		if strings.ToUpper(strings.TrimSpace(m)) == method {
			return true
		}
	}
	return false
}

// isCsrfExcludedPath 判断请求路径是否命中任一排除前缀（换行分隔）
func isCsrfExcludedPath(path string, excludePaths string) bool {
	if excludePaths == "" {
		return false
	}
	for _, line := range strings.Split(excludePaths, "\n") {
		prefix := strings.TrimSpace(line)
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// extractHostFromOrigin 从 Origin(scheme://host[:port]) 或 Referer(完整URL) 中提取小写裸 host(去端口)
func extractHostFromOrigin(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	host := ""
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host = u.Hostname() // Hostname 已去除端口
	} else {
		// 容错：非标准格式，尝试手工剥离 scheme 与路径
		host = s
		if idx := strings.Index(host, "://"); idx >= 0 {
			host = host[idx+3:]
		}
		if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
	}
	return strings.ToLower(host)
}

// isCsrfOriginAllowed 判断来源 host 是否在允许集合内（精确匹配 + *.example.com 通配）
func isCsrfOriginAllowed(originHost string, allowedHosts []string) bool {
	if originHost == "" {
		return false
	}
	for _, allowed := range allowedHosts {
		if allowed == "" {
			continue
		}
		if strings.HasPrefix(allowed, "*.") {
			// 通配域名：*.example.com 匹配 a.example.com、example.com
			suffix := strings.TrimPrefix(allowed, "*") // ".example.com"
			bare := strings.TrimPrefix(allowed, "*.")  // "example.com"
			if originHost == bare || strings.HasSuffix(originHost, suffix) {
				return true
			}
		} else if originHost == allowed {
			return true
		}
	}
	return false
}

// buildCsrfAllowedHosts 汇总允许来源 host：本站域名(去端口) + BindMoreHost 各行 + AllowedOrigins 各行解析出的 host
func buildCsrfAllowedHosts(reqHost string, bindMoreHost string, allowedOrigins string) []string {
	hosts := make([]string, 0, 4)

	// 本站域名（去端口，小写）
	selfHost := reqHost
	if idx := strings.Index(selfHost, ":"); idx >= 0 {
		selfHost = selfHost[:idx]
	}
	selfHost = strings.ToLower(strings.TrimSpace(selfHost))
	if selfHost != "" {
		hosts = append(hosts, selfHost)
	}

	// 绑定的多域名（换行分隔）
	if bindMoreHost != "" {
		for _, line := range strings.Split(bindMoreHost, "\n") {
			h := strings.ToLower(strings.TrimSpace(line))
			if h != "" {
				hosts = append(hosts, h)
			}
		}
	}

	// 额外允许来源（换行分隔；可能是 host 或 scheme://host[:port]）
	if allowedOrigins != "" {
		for _, line := range strings.Split(allowedOrigins, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// 通配域名保持原样（供 isCsrfOriginAllowed 识别）
			if strings.HasPrefix(line, "*.") {
				hosts = append(hosts, strings.ToLower(line))
				continue
			}
			h := extractHostFromOrigin(line)
			if h != "" {
				hosts = append(hosts, h)
			}
		}
	}

	return hosts
}
