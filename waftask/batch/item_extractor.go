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

// 匹配IPv4地址或IPv4网段
var ipv4Regex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)

// 匹配IPv6地址或IPv6网段 (简化版本)
var ipv6Regex = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?\b`)

// ExtractItem 从行中提取IP地址
func (e *IPExtractor) ExtractItem(line string) string {
	trimmed := strings.TrimSpace(line)

	// 整行本身就是一个合法的 IP 模式(单IP/CIDR/通配符/区间)时原样返回。
	// 这一步必须在正则之前：正则对 "1.2.3.4-1.2.3.99" 只会截出 "1.2.3.4"，
	// 而截出来的单 IP 恰好又能通过校验，结果是用户导入一个区间、库里静默变成一个 IP，
	// 全程没有任何报错——比直接拒绝更糟。
	if ok, _ := utils.IsValidIPPattern(trimmed); ok {
		return trimmed
	}

	// 整行不是纯 IP 模式（例如带注释、带前后缀的日志行），再退回正则抽取
	if match := ipv4Regex.FindString(line); match != "" {
		return match
	}
	if match := ipv6Regex.FindString(line); match != "" {
		return match
	}

	return line // 如果没有匹配到，返回原始行
}

// ValidateItem 验证IP是否有效。语法范围与手工录入的黑/白名单一致
// （单IP / CIDR / 通配符 / 区间），保证同一个写法在两个入口行为相同。
func (e *IPExtractor) ValidateItem(item string) bool {
	validRet, _ := utils.IsValidIPPattern(item)
	return validRet
}

// IPGroupExtractor IP组条目提取器。
//
// 抽取逻辑与黑/白名单完全一致，只多挡一层「全通配」：组可能被白名单引用，
// 源里混进一条 *.*.*.* 就等于全站放行，而手工录入(validateGroupItemIP)本来就是拒绝的，
// 两个入口必须同样严格。
type IPGroupExtractor struct {
	IPExtractor
}

// ValidateItem 在 IP 合法性之外额外拒绝全通配写法
func (e *IPGroupExtractor) ValidateItem(item string) bool {
	if utils.IsCatchAllIPPattern(item) {
		return false
	}
	return e.IPExtractor.ValidateItem(item)
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
	case "ipgroup":
		return &IPGroupExtractor{}
	case "sensitive":
		return &SensitiveExtractor{}
	default:
		return &DefaultExtractor{}
	}
}
