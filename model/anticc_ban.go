package model

import (
	"SamWaf/enums"
	"strings"
)

// CC 封禁作用域。
// global：封禁对全部站点生效（旧版本唯一行为，迁移过来的存量配置保持它）
// host  ：封禁只对触发的那个站点生效
const (
	CCBanScopeGlobal = "global"
	CCBanScopeHost   = "host"
)

// BuildCCBanKey 构造 CC 封禁缓存键：前缀 + 作用域 + 站点码 + 客户端标识。
//
// 键格式 `<PRE><scope>|<hostCode>|<ip>`：ip 排在最后一段，即使它含有分隔符也只会影响自身，
// 不可能伪装成别的作用域或站点（代理模式下 ip 取自请求头，属于外部输入）。
// scope=global 时 hostCode 恒为空，保证同一 IP 在全局作用域下只有一个键。
func BuildCCBanKey(scope, hostCode, ip string) string {
	if scope != CCBanScopeHost {
		scope = CCBanScopeGlobal
		hostCode = ""
	}
	return enums.CACHE_CCVISITBAN_PRE + scope + "|" + hostCode + "|" + ip
}

// ParseCCBanKey 从封禁键还原作用域、站点码与客户端标识。
// 兼容旧版本 `<PRE><ip>` 的两段式键（升级前写入、仍在 Redis 里没过期的那批），按全局作用域解析。
func ParseCCBanKey(key string) (scope, hostCode, ip string, ok bool) {
	if !strings.HasPrefix(key, enums.CACHE_CCVISITBAN_PRE) {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(key, enums.CACHE_CCVISITBAN_PRE)
	parts := strings.SplitN(rest, "|", 3)
	if len(parts) < 3 {
		// 旧格式：整段都是 IP
		return CCBanScopeGlobal, "", rest, rest != ""
	}
	if parts[0] != CCBanScopeHost {
		parts[0] = CCBanScopeGlobal
	}
	return parts[0], parts[1], parts[2], parts[2] != ""
}

// CCBanLookupKeys 返回判定「该站点的这个 IP 是否处于封禁期」需要检查的全部键。
// 全局封禁对所有站点生效，站点封禁只对本站点生效，因此两个都要查。
func CCBanLookupKeys(hostCode, ip string) []string {
	return []string{
		BuildCCBanKey(CCBanScopeGlobal, "", ip),
		BuildCCBanKey(CCBanScopeHost, hostCode, ip),
	}
}

// LegacyCCBanKey 旧版本的两段式键，仅用于兼容期的查询与解封。
func LegacyCCBanKey(ip string) string {
	return enums.CACHE_CCVISITBAN_PRE + ip
}
