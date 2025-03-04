package libinjection

import (
	"net/url"
	"regexp"
	"strings"
)

// HasDirTraversal 检测URL是否存在目录穿越漏洞
func HasDirTraversal(rawURL string) bool {
	// 解析URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// 定义路径穿越特征正则表达式
	pattern := `(\.\./|\.\.\\|%2e%2e/|%2e%2e\\)`
	regex := regexp.MustCompile(pattern)

	// 检查URL路径部分
	path := parsedURL.Path
	if checkComponent(path, regex) {
		return true
	}

	// 检查查询参数值
	query := parsedURL.Query()
	for _, values := range query {
		for _, value := range values {
			// 解码URL编码后再检查（防止%2e%2e%2f绕过）
			decodedValue, err := url.QueryUnescape(value)
			if err != nil {
				decodedValue = value // 如果解码失败，使用原始值
			}
			if checkComponent(decodedValue, regex) {
				return true
			}
		}
	}

	return false
}

// 检查单个组件是否包含恶意特征
func checkComponent(component string, regex *regexp.Regexp) bool {
	// 检查是否包含路径遍历模式
	if regex.MatchString(component) {
		return true
	}

	// 额外检查Windows路径特征
	if strings.Contains(component, "..\\") {
		return true
	}

	return false
}
