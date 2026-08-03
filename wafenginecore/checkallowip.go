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
	if matchAllowIP(clientIp, parsedIp, hostTarget.IPWhiteIndex, hostTarget.IPWhiteLists) {
		result.JumpGuardResult = true
		return result
	}
	//ip白名单策略（全局）
	//注意：全局网站可能还没登记进路由快照（未初始化/正在重载），必须判空，否则解引用 panic
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	if globalHost != nil && globalHost.Host.GUARD_STATUS == 1 {
		if matchAllowIP(clientIp, parsedIp, globalHost.IPWhiteIndex, globalHost.IPWhiteLists) {
			result.JumpGuardResult = true
			return result
		}
	}
	return result
}

// matchAllowIP 判定 clientIp 是否命中白名单：优先走编译后的 MatchSet 索引，
// 索引为 nil(未构建，兼容旧路径)时回退原线性遍历，保证不漏判。
func matchAllowIP(clientIp string, parsedIp net.IP, index *ipset.MatchSet, list []model.IPAllowList) bool {
	if index != nil {
		return index.Contains(parsedIp)
	}
	for i := 0; i < len(list); i++ {
		if utils.CheckIPInCIDR(clientIp, list[i].Ip) {
			return true
		}
	}
	return false
}
