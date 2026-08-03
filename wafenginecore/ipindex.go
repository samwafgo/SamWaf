package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/wafenginecore/ipset"
)

// BuildIPBlockIndex 由手工 IP 黑名单编译快速匹配索引(MatchSet)，供请求热路径 O(1)/常数级判定。
// 空列表返回 nil，判定处(checkdenyip)会自动回退线性遍历，兼容旧路径。
func BuildIPBlockIndex(list []model.IPBlockList) *ipset.MatchSet {
	if len(list) == 0 {
		return nil
	}
	ips := make([]string, 0, len(list))
	for i := 0; i < len(list); i++ {
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
		ips = append(ips, list[i].Ip)
	}
	return ipset.BuildMatchSet(ips)
}
