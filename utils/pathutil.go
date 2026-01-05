package utils

import (
	"crypto/rand"
	"encoding/base32"
	"regexp"
	"strings"
)

// GenerateRandomPathPrefix 生成随机路径前缀，用于隐藏系统特征
// 返回格式: /_waf_{8位随机字符}
// 示例: /_waf_a7k3m9x2
func GenerateRandomPathPrefix() string {
	// 生成8字节随机数
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		// 如果随机数生成失败，使用时间戳作为备选方案
		return "/_waf_fallback"
	}

	// Base32编码并转小写，去除填充字符
	encoded := strings.ToLower(base32.StdEncoding.EncodeToString(b))
	encoded = strings.ReplaceAll(encoded, "=", "")

	// 取前8位
	if len(encoded) > 8 {
		encoded = encoded[:8]
	}

	return "/_waf_" + encoded
}

// ValidatePathPrefix 验证路径前缀格式是否合法
// 规则:
// 1. 必须以 /_ 开头
// 2. 长度至少10个字符
// 3. 只允许小写字母、数字、下划线、斜杠
func ValidatePathPrefix(path string) bool {
	if path == "" {
		return false
	}

	// 必须以 /_ 开头
	if !strings.HasPrefix(path, "/_") {
		return false
	}

	// 最小长度检查
	if len(path) < 10 {
		return false
	}

	// 只允许小写字母、数字、下划线、斜杠
	matched, err := regexp.MatchString(`^/_[a-z0-9_]+$`, path)
	if err != nil {
		return false
	}

	return matched
}

// GetCaptchaPathOrDefault 获取验证码路径前缀，如果为空则返回默认值
func GetCaptchaPathOrDefault(pathPrefix string) string {
	if pathPrefix == "" {
		return "/samwaf_captcha"
	}
	return pathPrefix
}

// GetHttpAuthPathOrDefault 获取HTTP认证路径前缀，如果为空则返回默认值
func GetHttpAuthPathOrDefault(pathPrefix string) string {
	if pathPrefix == "" {
		return "/samwaf_httpauth"
	}
	return pathPrefix
}

// NormalizePath 规范化路径，确保以/开头且不以/结尾
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)

	// 确保以 / 开头
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 移除末尾的 /
	path = strings.TrimSuffix(path, "/")

	return path
}
