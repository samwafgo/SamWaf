package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/service/waf_service"
)

var (
	wafAccessSessionService = waf_service.WafAccessSessionServiceApp
	wafAccessAuditService   = waf_service.WafSecurityAuditServiceApp
)

// TaskAccessClean 统一访问认证的数据清理。
//
// 四件事：
//  1. 把已过期但还标着"有效"的会话/令牌置为已撤销 —— 校验时本来就会判过期时间，
//     这一步只是让管理端会话列表的状态与事实一致，不影响安全性
//  2. 删掉过期票据。票据只活 60 秒，多留 10 分钟够排查问题，再留就是纯占空间
//  3. 删掉长期无用的历史会话/令牌行
//  4. 按 GCONFIG_ACCESS_AUDIT_RETAIN_DAYS 清理审计日志
//
// 全部是幂等的删除/更新，跑多少次都安全；跑不起来也只是数据堆积，不影响认证功能。
func TaskAccessClean() {
	innerLogName := "TaskAccessClean"

	expiredSession, expiredToken, delTicket, delOld :=
		wafAccessSessionService.CleanExpired(7)
	delAudit := wafAccessAuditService.CleanExpired(int(global.GCONFIG_ACCESS_AUDIT_RETAIN_DAYS))

	if expiredSession+expiredToken+delTicket+delOld+delAudit > 0 {
		zlog.Info(innerLogName, "统一访问认证数据清理完成",
			"过期会话", expiredSession,
			"过期令牌", expiredToken,
			"删除票据", delTicket,
			"删除历史令牌", delOld,
			"删除审计日志", delAudit)
	} else {
		zlog.Debug(innerLogName, "无需清理")
	}
}
