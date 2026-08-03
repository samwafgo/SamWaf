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
	if matchDenyIP(clientIp, parsedIp, hostTarget.IPBlockIndex, hostTarget.IPBlockLists) {
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
		if matchDenyIP(clientIp, parsedIp, globalHost.IPBlockIndex, globalHost.IPBlockLists) {
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

// matchDenyIP 判定 clientIp 是否命中黑名单：优先走编译后的 MatchSet 索引(O(1)/常数级)，
// 索引为 nil(未构建，兼容旧路径)时回退原线性遍历，保证不漏判。
func matchDenyIP(clientIp string, parsedIp net.IP, index *ipset.MatchSet, list []model.IPBlockList) bool {
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
