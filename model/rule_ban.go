package model

import (
	"SamWaf/enums"
	"strings"
)

// BuildRuleBanKey 规则封禁键：站点作用域（hostCode|IP），值与 TTL 均为封禁分钟数
func BuildRuleBanKey(hostCode, ip string) string {
	return enums.CACHE_RULE_BAN_PRE + hostCode + "|" + ip
}

// ParseRuleBanKey 解析规则封禁键，返回 hostCode、IP、是否解析成功
func ParseRuleBanKey(key string) (string, string, bool) {
	if !strings.HasPrefix(key, enums.CACHE_RULE_BAN_PRE) {
		return "", "", false
	}
	rest := strings.TrimPrefix(key, enums.CACHE_RULE_BAN_PRE)
	idx := strings.LastIndex(rest, "|")
	if idx <= 0 {
		return "", "", false
	}
	return rest[:idx], rest[idx+1:], true
}
