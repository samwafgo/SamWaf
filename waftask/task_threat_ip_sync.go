package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/service/waf_service"
)

var (
	wafThreatIPService = waf_service.WafThreatIPServiceApp
)

// TaskThreatIPSync 定时检查威胁情报订阅渠道，按各渠道周期(IntervalHour)到期后拉取并落地；
// 随后做一次**不联网**的落地对账；同时按各 CDN 厂商节奏(AutoFetch 开启且到期)刷新其回源段中心库。
func TaskThreatIPSync() {
	innerLogName := "TaskThreatIPSync"
	zlog.Debug(innerLogName, "开始检查威胁情报订阅/CDN回源段是否到期")
	wafThreatIPService.SyncAllDue()
	// 落地对账放在同步之后：同步只管"内容有没有更新"，对账管"内容有没有真的落到防火墙上"。
	// 落地可能被中断(Windows 一次重建是几十次独立 netsh)、被用户手工清理、被组策略刷掉，
	// 这些都不会改变内容 sha，只能靠对账发现并用库里的快照覆盖式修复。
	wafThreatIPService.ReconcileLanding()
	waf_service.WafCDNIPServiceApp.SyncAllDue()
}
