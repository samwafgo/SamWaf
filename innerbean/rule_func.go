package innerbean

import (
	"bytes"
	"net"
	"strings"
)

// RuleFunc 规则函数助手，提供各种通用的规则判断函数
// 使用方式: 在DataContext中注册为 "RF"，然后在规则中调用
// 例如: RF.IPInRange(MF.SRC_IP, "192.168.0.0", "192.168.1.254")
type RuleFunc struct{}

// NewRuleFunc 创建规则函数助手实例
func NewRuleFunc() *RuleFunc {
	return &RuleFunc{}
}

// ================== IP 相关函数 ==================

// IPInRange 判断IP是否在指定范围内（包含起始和结束IP）
// ip: 要检查的IP地址
// startIP: 起始IP地址
// endIP: 结束IP地址
// 返回: true表示IP在范围内，false表示不在
// 使用示例: RF.IPInRange(MF.SRC_IP, "172.16.0.0", "172.20.255.254")
func (rf *RuleFunc) IPInRange(ip, startIP, endIP string) bool {
	parsedIP := net.ParseIP(ip)
	parsedStart := net.ParseIP(startIP)
	parsedEnd := net.ParseIP(endIP)

	if parsedIP == nil || parsedStart == nil || parsedEnd == nil {
		return false
	}

	// 确保都是相同格式（IPv4或IPv6）
	parsedIP = parsedIP.To16()
	parsedStart = parsedStart.To16()
	parsedEnd = parsedEnd.To16()

	// IP >= startIP && IP <= endIP
	return bytes.Compare(parsedIP, parsedStart) >= 0 && bytes.Compare(parsedIP, parsedEnd) <= 0
}

// IPInCIDR 判断IP是否在指定的CIDR网段内
// ip: 要检查的IP地址
// cidr: CIDR格式的网段，如 "192.168.1.0/24"
// 返回: true表示IP在网段内，false表示不在
// 使用示例: RF.IPInCIDR(MF.SRC_IP, "192.168.1.0/24")
func (rf *RuleFunc) IPInCIDR(ip, cidr string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ipNet.Contains(parsedIP)
}

// IPInRanges 判断IP是否在多个范围中的任意一个（类似SQL的IN操作）
// ip: 要检查的IP地址
// ranges: IP范围列表，格式为 "startIP-endIP" 或 CIDR格式 "192.168.0.0/24"
// 返回: true表示IP在任意一个范围内，false表示都不在
// 使用示例: RF.IPInRanges(MF.SRC_IP, "172.16.0.0-172.20.255.254", "192.168.0.0/24")
func (rf *RuleFunc) IPInRanges(ip string, ranges ...string) bool {
	for _, r := range ranges {
		// 检查是否是CIDR格式
		if strings.Contains(r, "/") {
			if rf.IPInCIDR(ip, r) {
				return true
			}
		} else if strings.Contains(r, "-") {
			// 范围格式: startIP-endIP
			parts := strings.Split(r, "-")
			if len(parts) == 2 {
				if rf.IPInRange(ip, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])) {
					return true
				}
			}
		} else {
			// 单个IP精确匹配
			if ip == strings.TrimSpace(r) {
				return true
			}
		}
	}
	return false
}

// IPEquals 判断两个IP是否相等（支持IPv4和IPv6的标准化比较）
// ip1: 第一个IP地址
// ip2: 第二个IP地址
// 返回: true表示相等，false表示不相等
func (rf *RuleFunc) IPEquals(ip1, ip2 string) bool {
	parsedIP1 := net.ParseIP(ip1)
	parsedIP2 := net.ParseIP(ip2)

	if parsedIP1 == nil || parsedIP2 == nil {
		return ip1 == ip2 // 如果无法解析，直接字符串比较
	}

	return parsedIP1.Equal(parsedIP2)
}

// ================== 字符串相关函数 ==================

// In 判断值是否在给定的列表中（类似SQL的IN操作）
// value: 要检查的值
// list: 可能的值列表
// 返回: true表示值在列表中，false表示不在
// 使用示例: RF.In(MF.METHOD, "GET", "POST", "PUT")
func (rf *RuleFunc) In(value string, list ...string) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}

// InIgnoreCase 判断值是否在给定的列表中（忽略大小写，类似SQL的IN操作）
// value: 要检查的值
// list: 可能的值列表
// 返回: true表示值在列表中，false表示不在
// 使用示例: RF.InIgnoreCase(MF.METHOD, "get", "post", "put")
func (rf *RuleFunc) InIgnoreCase(value string, list ...string) bool {
	valueLower := strings.ToLower(value)
	for _, item := range list {
		if valueLower == strings.ToLower(item) {
			return true
		}
	}
	return false
}

// ContainsAny 判断字符串是否包含给定列表中的任意一个
// value: 要检查的字符串
// list: 要搜索的子串列表
// 返回: true表示包含至少一个，false表示一个都不包含
// 使用示例: RF.ContainsAny(MF.USER_AGENT, "bot", "spider", "crawler")
func (rf *RuleFunc) ContainsAny(value string, list ...string) bool {
	for _, item := range list {
		if strings.Contains(value, item) {
			return true
		}
	}
	return false
}

// ContainsAnyIgnoreCase 判断字符串是否包含给定列表中的任意一个（忽略大小写）
// value: 要检查的字符串
// list: 要搜索的子串列表
// 返回: true表示包含至少一个，false表示一个都不包含
// 使用示例: RF.ContainsAnyIgnoreCase(MF.USER_AGENT, "Bot", "Spider", "Crawler")
func (rf *RuleFunc) ContainsAnyIgnoreCase(value string, list ...string) bool {
	valueLower := strings.ToLower(value)
	for _, item := range list {
		if strings.Contains(valueLower, strings.ToLower(item)) {
			return true
		}
	}
	return false
}

// ContainsAll 判断字符串是否包含给定列表中的全部
// value: 要检查的字符串
// list: 要搜索的子串列表
// 返回: true表示包含全部，false表示至少缺少一个
// 使用示例: RF.ContainsAll(MF.URL, "/admin", ".php")
func (rf *RuleFunc) ContainsAll(value string, list ...string) bool {
	for _, item := range list {
		if !strings.Contains(value, item) {
			return false
		}
	}
	return len(list) > 0
}

// StartsWithAny 判断字符串是否以给定列表中的任意一个开头
// value: 要检查的字符串
// list: 可能的前缀列表
// 返回: true表示匹配至少一个前缀，false表示一个都不匹配
// 使用示例: RF.StartsWithAny(MF.URL, "/admin", "/api", "/manage")
func (rf *RuleFunc) StartsWithAny(value string, list ...string) bool {
	for _, item := range list {
		if strings.HasPrefix(value, item) {
			return true
		}
	}
	return false
}

// EndsWithAny 判断字符串是否以给定列表中的任意一个结尾
// value: 要检查的字符串
// list: 可能的后缀列表
// 返回: true表示匹配至少一个后缀，false表示一个都不匹配
// 使用示例: RF.EndsWithAny(MF.URL, ".php", ".asp", ".jsp")
func (rf *RuleFunc) EndsWithAny(value string, list ...string) bool {
	for _, item := range list {
		if strings.HasSuffix(value, item) {
			return true
		}
	}
	return false
}

// ================== 数值比较函数 ==================

// IntInRange 判断整数是否在指定范围内（包含边界）
// value: 要检查的整数
// min: 最小值
// max: 最大值
// 返回: true表示在范围内，false表示不在
// 使用示例: RF.IntInRange(MF.STATUS_CODE, 400, 499)
func (rf *RuleFunc) IntInRange(value, min, max int64) bool {
	return value >= min && value <= max
}

// IntIn 判断整数是否在给定的列表中
// value: 要检查的整数
// list: 可能的值列表
// 返回: true表示在列表中，false表示不在
// 使用示例: RF.IntIn(MF.STATUS_CODE, 200, 201, 204)
func (rf *RuleFunc) IntIn(value int64, list ...int64) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}

// ================== 逻辑辅助函数 ==================

// Not 逻辑非
// value: 布尔值
// 返回: 取反后的值
// 使用示例: RF.Not(RF.IPInRange(MF.SRC_IP, "192.168.0.0", "192.168.1.254"))
func (rf *RuleFunc) Not(value bool) bool {
	return !value
}

// IsEmpty 判断字符串是否为空
// value: 要检查的字符串
// 返回: true表示为空，false表示不为空
func (rf *RuleFunc) IsEmpty(value string) bool {
	return value == ""
}

// IsNotEmpty 判断字符串是否不为空
// value: 要检查的字符串
// 返回: true表示不为空，false表示为空
func (rf *RuleFunc) IsNotEmpty(value string) bool {
	return value != ""
}

// LengthBetween 判断字符串长度是否在指定范围内
// value: 要检查的字符串
// min: 最小长度
// max: 最大长度
// 返回: true表示长度在范围内，false表示不在
func (rf *RuleFunc) LengthBetween(value string, min, max int64) bool {
	length := int64(len(value))
	return length >= min && length <= max
}

// ================== 规则动作标记函数 ==================
//
// 这几个方法本身不做任何事情（no-op），只是让规则的 then 块能声明"命中之后干什么"。
// 引擎走的是 FetchMatchingRules（只求值 when，不执行 then），动作是在规则加载阶段
// 由 utils.ExtractRuleActions 从规则文本里解析出来的，方法体永远不会被调用。
// 之所以还要定义成真实方法，是因为 GRL 需要能编译通过。
//
// 未声明任何动作的规则默认为拦截（Deny），保证老规则行为不变。

// Deny 命中后拦截请求（默认动作，可不写）
// 使用示例: then RF.Deny();
func (rf *RuleFunc) Deny() {}

// Log 命中后仅记录，不拦截，继续执行后续检测
// 使用示例: then RF.Log();
func (rf *RuleFunc) Log() {}

// Allow 命中后放行（不被自定义规则拦截），可选跳过指定的后续检测模块
// modules: 要跳过的检测模块名，如 "CC"、"AI"、"SQLI"；传 "ALL" 表示跳过全部
// 使用示例: then RF.Allow();              仅本环节放行，后续检测照常
// 使用示例: then RF.Allow("CC", "AI");    放行并跳过CC和AI检测
func (rf *RuleFunc) Allow(modules ...string) {}

// AllowAll 命中后放行并跳过后续所有检测，直通后端（等价于 RF.Allow("ALL")）
// 使用示例: then RF.AllowAll();
func (rf *RuleFunc) AllowAll() {}
