package batch

import (
	"SamWaf/utils"
	"regexp"
	"strings"
)

// ItemExtractor 项目提取器接口
type ItemExtractor interface {
	// ExtractItem 从行中提取项目
	ExtractItem(line string) string
	// ValidateItem 验证项目是否有效
	ValidateItem(item string) bool
}

// IPExtractor IP提取器
type IPExtractor struct{}

// ExtractItem 从行中提取IP地址
func (e *IPExtractor) ExtractItem(line string) string {
	// 匹配IPv4地址或IPv4网段
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)

	// 匹配IPv6地址或IPv6网段 (简化版本)
	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?\b`)

	// 先尝试匹配IPv4
	if match := ipv4Regex.FindString(line); match != "" {
		return match
	}

	// 再尝试匹配IPv6
	if match := ipv6Regex.FindString(line); match != "" {
		return match
	}

	return line // 如果没有匹配到，返回原始行
}

// ValidateItem 验证IP地址是否有效
func (e *IPExtractor) ValidateItem(item string) bool {
	validRet, _ := utils.IsValidIPOrNetwork(item)
	return validRet
}

// DefaultExtractor 默认提取器，不做特殊处理
type DefaultExtractor struct{}

// ExtractItem 默认提取，只做简单的空格处理
func (e *DefaultExtractor) ExtractItem(line string) string {
	return strings.TrimSpace(line)
}

// ValidateItem 默认验证，非空即有效
func (e *DefaultExtractor) ValidateItem(item string) bool {
	return item != ""
}

// SensitiveExtractor 敏感词提取器
type SensitiveExtractor struct{}

// ExtractItem 敏感词提取，去除前后空格
func (e *SensitiveExtractor) ExtractItem(line string) string {
	return strings.TrimSpace(line)
}

// ValidateItem 敏感词验证，非空且长度合理
func (e *SensitiveExtractor) ValidateItem(item string) bool {
	return item != "" && len(item) <= 1000 // 限制敏感词最大长度
}

// GetExtractor 根据批量任务类型获取合适的提取器
func GetExtractor(batchType string) ItemExtractor {
	switch batchType {
	case "ipallow", "ipdeny":
		return &IPExtractor{}
	case "sensitive":
		return &SensitiveExtractor{}
	default:
		return &DefaultExtractor{}
	}
}
