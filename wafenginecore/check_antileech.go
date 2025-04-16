package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// CheckAntiLeech 检查防盗链
func (waf *WafEngine) CheckAntiLeech(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	antiLeechConfig := model.AntiLeechConfig{
		IsEnableAntiLeech: 0,
		FileTypes:         "",
		ValidReferers:     "",
		Action:            "",
		RedirectURL:       "",
	}

	json.Unmarshal([]byte(hostTarget.Host.AntiLeechJSON), &antiLeechConfig)
	// 检查是否启用了防盗链
	if antiLeechConfig.IsEnableAntiLeech == 0 {
		return result
	}

	// 检查请求的URL是否匹配需要防盗链的文件类型
	if !isProtectedFileType(r.URL.Path, antiLeechConfig.FileTypes) {
		return result
	}

	// 获取Referer
	referer := r.Header.Get("Referer")

	// 检查Referer是否有效
	hostWithoutPort := r.Host
	if strings.Contains(hostWithoutPort, ":") {
		hostWithoutPort, _, _ = strings.Cut(hostWithoutPort, ":")
	}
	// 收集所有server_names
	serverNames := []string{hostWithoutPort}
	if hostTarget != nil {
		bindMoreHost := hostTarget.Host.BindMoreHost
		if bindMoreHost != "" {
			lines := strings.Split(bindMoreHost, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					serverNames = append(serverNames, line)
				}
			}
		}
	}
	if isValidReferer(referer, serverNames, strings.Split(antiLeechConfig.ValidReferers, ";")) {
		return result
	}

	// 如果Referer无效，根据配置的Action进行处理
	result.IsBlock = true
	result.Title = "防盗链保护"
	if antiLeechConfig.Action == "redirect" && antiLeechConfig.RedirectURL != "" {
		// 防止重定向循环
		redirectURL, err := url.Parse(antiLeechConfig.RedirectURL)
		if err == nil {
			// 处理r.Host和redirectURL.Host，去掉端口，仅比较纯域名
			reqHost := r.Host
			if strings.Contains(reqHost, ":") {
				reqHost, _, _ = strings.Cut(reqHost, ":")
			}
			redirectHost := redirectURL.Host
			if strings.Contains(redirectHost, ":") {
				redirectHost, _, _ = strings.Cut(redirectHost, ":")
			}
			if reqHost == redirectHost && strings.HasPrefix(r.URL.Path, redirectURL.Path) {
				result.IsBlock = true
				result.Title = "防盗链保护"
				result.Content = "检测到重定向循环，已阻断"
				return result
			}
		}
		// 记录日志
		zlog.Debug("防盗链保护: 检测到非法引用，重定向到: " + antiLeechConfig.RedirectURL)

		// 设置重定向URL
		result.Content = "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;url=" +
			antiLeechConfig.RedirectURL + "\"></head><body>Redirecting...</body></html>"
	} else {
		// 默认阻止访问
		result.Content = "您没有权限访问此资源"
	}

	return result
}

// isProtectedFileType 检查URL是否匹配需要防盗链的文件类型
func isProtectedFileType(path string, fileTypes string) bool {
	if fileTypes == "" {
		return false
	}

	pattern := ".*\\.(" + fileTypes + ")$"
	matched, err := regexp.MatchString(pattern, strings.ToLower(path))
	if err != nil {
		zlog.Error("防盗链正则匹配错误: " + err.Error())
		return false
	}

	return matched
}

// isValidReferer 检查Referer是否有效
func isValidReferer(referer string, hosts []string, validReferers []string) bool {
	// 如果没有设置有效的Referer列表，则默认允许所有
	if len(validReferers) == 0 {
		return true
	}

	// 如果没有Referer，检查是否允许none
	if referer == "" {
		return contains(validReferers, "none")
	}

	// 解析Referer URL
	parsedReferer, err := url.Parse(referer)
	if err != nil {
		return contains(validReferers, "blocked")
	}
	refererHost := parsedReferer.Host

	// 检查是否允许当前服务器名称（支持多域名）
	if contains(validReferers, "server_names") {
		for _, h := range hosts {
			if refererHost == h {
				return true
			}
		}
	}

	// 检查是否匹配其他有效的Referer模式
	for _, validReferer := range validReferers {
		// 跳过特殊关键字
		if validReferer == "none" || validReferer == "blocked" || validReferer == "server_names" {
			continue
		}

		// 处理正则表达式模式 (~开头)
		if strings.HasPrefix(validReferer, "~") {
			pattern := strings.TrimPrefix(validReferer, "~")
			matched, err := regexp.MatchString(pattern, refererHost)
			if err == nil && matched {
				return true
			}
		} else if strings.HasPrefix(validReferer, "*.") {
			// 处理通配符域名 (*.example.com)
			suffix := strings.TrimPrefix(validReferer, "*")
			if strings.HasSuffix(refererHost, suffix) {
				return true
			}
		} else if refererHost == validReferer {
			// 完全匹配
			return true
		}
	}

	return false
}

// contains 检查字符串数组是否包含指定字符串
func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}
