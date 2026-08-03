package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/service/waf_service"
)

var (
	wafThreatIPService = waf_service.WafThreatIPServiceApp
)

// TaskThreatIPSync 定时检查威胁情报订阅渠道，按各渠道周期(IntervalHour)到期后拉取并落地；
// 同时按各 CDN 厂商节奏(AutoFetch 开启且到期)刷新其回源段中心库。
func TaskThreatIPSync() {
	innerLogName := "TaskThreatIPSync"
	zlog.Debug(innerLogName, "开始检查威胁情报订阅/CDN回源段是否到期")
	wafThreatIPService.SyncAllDue()
	waf_service.WafCDNIPServiceApp.SyncAllDue()
}
