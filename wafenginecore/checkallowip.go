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
检测白名单 ip
*/
func (waf *WafEngine) CheckAllowIP(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	// 根据当前 host 的 IP 模式选择使用的 IP
	clientIp := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)
	parsedIp := net.ParseIP(clientIp)

	//ip白名单策略（局部）
	if matchAllowIP(clientIp, parsedIp, hostTarget.IPWhiteIndex, hostTarget.IPWhiteGroupCodes, hostTarget.IPWhiteLists) {
		result.JumpGuardResult = true
		return result
	}
	//ip白名单策略（全局）
	//注意：全局网站可能还没登记进路由快照（未初始化/正在重载），必须判空，否则解引用 panic
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	if globalHost != nil && globalHost.Host.GUARD_STATUS == 1 {
		if matchAllowIP(clientIp, parsedIp, globalHost.IPWhiteIndex, globalHost.IPWhiteGroupCodes, globalHost.IPWhiteLists) {
			result.JumpGuardResult = true
			return result
		}
	}
	return result
}

// matchAllowIP 判定 clientIp 是否命中白名单。结构与 matchDenyIP 一致：
// 「单条」行走编译索引(nil 时回退线性遍历)，「引用 IP 组」的行查 ipset 全局原子快照。
// 组内容变更只替换快照，本 HostSafe 无需重新发布，所有引用站点同时生效。
func matchAllowIP(clientIp string, parsedIp net.IP, index *ipset.MatchSet, groupCodes []string, list []model.IPAllowList) bool {
	if index != nil {
		if index.Contains(parsedIp) {
			return true
		}
	} else {
		// 旧路径回退。用 MatchIPPattern 而非 CheckIPInCIDR，否则通配符与区间在这条路径上会失效。
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
