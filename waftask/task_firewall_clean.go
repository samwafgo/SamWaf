package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/service/waf_service"
)

var (
	wafFirewallIPBlockService = waf_service.WafFirewallIPBlockServiceApp
)

// TaskFirewallCleanExpired 清理过期的防火墙IP封禁规则
func TaskFirewallCleanExpired() {
	innerLogName := "TaskFirewallCleanExpired"

	zlog.Info(innerLogName, "开始清理过期的防火墙IP封禁规则")

	// 调用清理服务
	count, err := wafFirewallIPBlockService.ClearExpiredRules()
	if err != nil {
		zlog.Error(innerLogName, "清理过期规则失败", "error", err.Error())
		return
	}

	if count > 0 {
		zlog.Info(innerLogName, "清理过期规则完成",
			"清理数量", count,
			"说明", "已自动清理过期的防火墙IP封禁规则并从系统防火墙中移除")
	} else {
		zlog.Debug(innerLogName, "无过期规则需要清理")
	}
}
