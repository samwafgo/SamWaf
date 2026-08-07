package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/service/waf_service"
)

var (
	wafHostGuardService = waf_service.WafHostGuardServiceApp
)

// TaskHostGuardCleanExpired 解封主机防爆破中已到期的IP。
//
// 每分钟跑一次，而不是沿用防火墙那个 5 分钟粒度：阶梯第一级只有 5 分钟，
// 用 5 分钟粒度会让用户看到"明明写着封 5 分钟，实际封了 10 分钟"。
func TaskHostGuardCleanExpired() {
	innerLogName := "TaskHostGuardCleanExpired"

	// 功能没开就别去碰数据库和防火墙
	if global.GCONFIG_HOST_GUARD_ENABLED != 1 {
		return
	}

	count, err := wafHostGuardService.CleanExpiredBans()
	if err != nil {
		zlog.Error(innerLogName, "解封到期IP失败", "error", err.Error())
		return
	}
	if count > 0 {
		zlog.Info(innerLogName, "解封完成", "解封数量", count)
	} else {
		zlog.Debug(innerLogName, "无到期封禁")
	}
}
