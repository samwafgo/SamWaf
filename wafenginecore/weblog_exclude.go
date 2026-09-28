package wafenginecore

import (
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/ipset"
	"sync/atomic"
)

// 写入侧排除：按来源 IP 不记录访问日志（M6 H1）。
//
// 清单是全局 + 站点两级（D15），行格式：
//   - 单IP / CIDR / 通配符 / 区间（语法同 ipset.MatchSet）
//   - group:组短码  引用一个 IP 组（组内容走 ipset 全局快照，改组即全部引用方生效）
//   - # 开头是注释；空行跳过；逗号与换行都算分隔
//
// 静音程度按 D13：只静音正常请求，安全事件照常留痕——办公出口多是 NAT 共享 IP，
// 一刀切静音意味着真被打了也看不见。判定挂在 shouldRecordWebLog（入队前），
// 被排除的请求同样不进三层落库 / stats_* / 分析层汇总。

// 清单文本的解析与编译统一放在 ipset（叶子包）里：引擎按它决定记不记日志，
// IP归属查询按它回答「这个 IP 为什么没有日志」，两边必须是同一套解析。

// parseIPLogExcludeLines 把清单文本拆成 IP 模式与组短码两组
func parseIPLogExcludeLines(raw string) (patterns []string, groupCodes []string) {
	return ipset.ParseListText(raw)
}

// BuildIPLogExcludeIndex 编译站点级清单里的 IP 模式；空清单返回 nil。
func BuildIPLogExcludeIndex(raw string) *ipset.MatchSet {
	return ipset.BuildFromListText(raw)
}

// ExtractIPLogExcludeGroupCodes 抽出站点级清单里引用的组短码（去重保序）。
func ExtractIPLogExcludeGroupCodes(raw string) []string {
	return ipset.GroupCodesOf(raw)
}

// ipLogExcludeCompiled 是全局清单的编译结果，配置热更新时整体替换。
type ipLogExcludeCompiled struct {
	index      *ipset.MatchSet
	groupCodes []string
}

func (c *ipLogExcludeCompiled) match(clientIP string) bool {
	if c == nil {
		return false
	}
	if c.index.ContainsStr(clientIP) {
		return true
	}
	for _, code := range c.groupCodes {
		if ipset.GetGroupMatcher(code).ContainsStr(clientIP) {
			return true
		}
	}
	return false
}

// globalIPLogExclude 全局排除清单的编译快照；nil 表示未配置。
// MatchSet.ContainsStr / GetGroupMatcher 均为 nil 安全（返回 false）。
var globalIPLogExclude atomic.Pointer[ipLogExcludeCompiled]

// SetGlobalIPLogExclude 由系统配置热更新入口调用（waftask/task_config.go）。
func SetGlobalIPLogExclude(raw string) {
	patterns, codes := parseIPLogExcludeLines(raw)
	var index *ipset.MatchSet
	if len(patterns) > 0 {
		index = ipset.BuildMatchSet(patterns)
	}
	globalIPLogExclude.Store(&ipLogExcludeCompiled{index: index, groupCodes: codes})
}

// isIPLogExcluded 判定来源 IP 是否命中全局或站点级排除清单。hostSafe 可为 nil（只判全局）。
func isIPLogExcluded(clientIP string, hostSafe *wafenginmodel.HostSafe) bool {
	if clientIP == "" {
		return false
	}
	if globalIPLogExclude.Load().match(clientIP) {
		return true
	}
	if hostSafe == nil {
		return false
	}
	if hostSafe.IPLogExcludeIndex.ContainsStr(clientIP) {
		return true
	}
	for _, code := range hostSafe.IPLogExcludeGroupCodes {
		if ipset.GetGroupMatcher(code).ContainsStr(clientIP) {
			return true
		}
	}
	return false
}
