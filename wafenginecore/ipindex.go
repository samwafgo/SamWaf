package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/wafenginecore/ipset"
	"net"
)

// BuildIPBlockIndex 由手工 IP 黑名单编译快速匹配索引(MatchSet)，供请求热路径 O(1)/常数级判定。
// 空列表返回 nil，判定处(checkdenyip)会自动回退线性遍历，兼容旧路径。
//
// 引用 IP 组的行(IpType==group)不进本索引：组内容由 ipset 全局原子快照实时提供，
// 这样改组时无需重建任何站点的索引，所有引用站点同时生效。
// 判定条件写 == IPEntryTypeGroup 而非 != IPEntryTypeIP —— 存量行的 ip_type 是空串。
func BuildIPBlockIndex(list []model.IPBlockList) *ipset.MatchSet {
	if len(list) == 0 {
		return nil
	}
	ips := make([]string, 0, len(list))
	for i := 0; i < len(list); i++ {
		if list[i].IpType == model.IPEntryTypeGroup {
			continue
		}
		ips = append(ips, list[i].Ip)
	}
	return ipset.BuildMatchSet(ips)
}

// BuildIPAllowIndex 由手工 IP 白名单编译快速匹配索引(MatchSet)。空列表返回 nil。
func BuildIPAllowIndex(list []model.IPAllowList) *ipset.MatchSet {
	if len(list) == 0 {
		return nil
	}
	ips := make([]string, 0, len(list))
	for i := 0; i < len(list); i++ {
		if list[i].IpType == model.IPEntryTypeGroup {
			continue
		}
		ips = append(ips, list[i].Ip)
	}
	return ipset.BuildMatchSet(ips)
}

// ExtractBlockGroupCodes 抽出黑名单里引用的 IP 组短码（去重，保持原有顺序）。
//
// 预抽出来存进 HostSafe，是为了让请求热路径不必线性扫整个名单去找组引用行。
// 返回值一经放进 HostSafe 即视为不可变，热更新时必须整体替换新切片，不能就地 append
// （旧快照与新快照可能共享底层数组，就地改会造成数据竞争）。
func ExtractBlockGroupCodes(list []model.IPBlockList) []string {
	if len(list) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var codes []string
	for i := 0; i < len(list); i++ {
		if list[i].IpType != model.IPEntryTypeGroup || list[i].GroupCode == "" {
			continue
		}
		if _, ok := seen[list[i].GroupCode]; ok {
			continue
		}
		seen[list[i].GroupCode] = struct{}{}
		codes = append(codes, list[i].GroupCode)
	}
	return codes
}

// ExtractAllowGroupCodes 抽出白名单里引用的 IP 组短码（去重，保持原有顺序）。
func ExtractAllowGroupCodes(list []model.IPAllowList) []string {
	if len(list) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var codes []string
	for i := 0; i < len(list); i++ {
		if list[i].IpType != model.IPEntryTypeGroup || list[i].GroupCode == "" {
			continue
		}
		if _, ok := seen[list[i].GroupCode]; ok {
			continue
		}
		seen[list[i].GroupCode] = struct{}{}
		codes = append(codes, list[i].GroupCode)
	}
	return codes
}

// matchIPGroups 逐个查全局组快照。命中任一组即返回 true。
// GetGroupMatcher 与 Contains 都是 nil 安全的：组已被删除但引用行还没清理时不会 panic，
// 也不会误判命中。
func matchIPGroups(groupCodes []string, parsedIp net.IP) bool {
	for i := 0; i < len(groupCodes); i++ {
		if ipset.GetGroupMatcher(groupCodes[i]).Contains(parsedIp) {
			return true
		}
	}
	return false
}
