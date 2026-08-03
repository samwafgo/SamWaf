package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"SamWaf/wafenginecore/ipset"
	"net"
	"net/http"
	"net/url"
)

/*
*
检测不允许访问的 ip
返回是否满足条件
*/
func (waf *WafEngine) CheckDenyIP(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	// 根据当前 host 的 IP 模式选择使用的 IP
	clientIp := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)
	parsedIp := net.ParseIP(clientIp)

	//ip黑名单策略（局部）：手工小名单优先(量小、用户强意图)
	if matchDenyIP(clientIp, parsedIp, hostTarget.IPBlockIndex, hostTarget.IPBlockGroupCodes, hostTarget.IPBlockLists) {
		weblogbean.RISK_LEVEL = 1
		result.IsBlock = true
		result.Title = "IP黑名单"
		result.Content = "您的访问被阻止了IP限制"
		return result
	}
	//ip黑名单策略（全局）
	//注意：全局网站可能还没登记进路由快照（未初始化/正在重载），必须判空，否则解引用 panic
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	if globalHost != nil && globalHost.Host.GUARD_STATUS == 1 {
		if matchDenyIP(clientIp, parsedIp, globalHost.IPBlockIndex, globalHost.IPBlockGroupCodes, globalHost.IPBlockLists) {
			weblogbean.RISK_LEVEL = 1
			result.IsBlock = true
			result.Title = "【全局】IP黑名单"
			result.Content = "您的访问被阻止了IP限制"
			return result
		}
	}
	//威胁情报订阅大集合（全局并集，跨渠道；对所有站点始终生效）
	if ipset.GetGlobalThreatMatcher().Contains(parsedIp) {
		weblogbean.RISK_LEVEL = 1
		result.IsBlock = true
		result.Title = "威胁情报IP"
		result.Content = "您的访问被阻止了威胁情报IP限制"
		return result
	}
	return result
}

// matchDenyIP 判定 clientIp 是否命中黑名单。
//
// 两条独立来源：
//  1. 本站名单里的「单条」行 —— 走编译后的 MatchSet 索引(O(1)/常数级)；
//     索引为 nil(未构建，兼容旧路径)时回退线性遍历，保证不漏判。
//  2. 本站名单里引用的 IP 组 —— 查 ipset 全局原子快照。
//     组内容变更只替换那个快照，本 HostSafe 不需要重新发布，因此所有引用站点(含全局网站)
//     在同一瞬间同时生效。
func matchDenyIP(clientIp string, parsedIp net.IP, index *ipset.MatchSet, groupCodes []string, list []model.IPBlockList) bool {
	if index != nil {
		if index.Contains(parsedIp) {
			return true
		}
	} else {
		// 旧路径回退。用 MatchIPPattern 而非 CheckIPInCIDR，否则通配符与区间在这条路径上会失效。
		// 组引用行的 Ip 字段为空，跳过，交由下面的组快照统一判定。
		for i := 0; i < len(list); i++ {
			if list[i].IpType == model.IPEntryTypeGroup {
				continue
			}
			if utils.MatchIPPattern(clientIp, list[i].Ip) {
				return true
			}
		}
	}
	return matchIPGroups(groupCodes, parsedIp)
}
