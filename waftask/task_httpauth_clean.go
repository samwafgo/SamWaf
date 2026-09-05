package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"strconv"
)

var wafHttpAuthSessionService = waf_service.WafHttpAuthSessionServiceApp

// httpAuthSessionKeepDays 已失效会话行的保留天数。
// 留着是为了让管理员事后还能看到「谁在什么时候被踢的/什么时候到期的」，
// 超过这个天数就没有排查价值了，只剩占空间。
const httpAuthSessionKeepDays = 30

// TaskHttpAuthClean 网站密码访问的会话清理。
//
// 两件事：
//  1. 把已过期但还标着"有效"的会话置为已失效 —— 校验时本来就会独立判过期时间，
//     这一步只是让管理端会话列表的状态与事实一致，不影响安全性
//  2. 删掉超过保留期的历史失效行
//
// 全部幂等，跑多少次都安全；跑不起来也只是数据堆积，不影响认证功能。
func TaskHttpAuthClean() {
	innerLogName := "TaskHttpAuthClean"

	expired, deleted := wafHttpAuthSessionService.CleanExpired(httpAuthSessionKeepDays)
	if expired+deleted == 0 {
		zlog.Debug(innerLogName, "无需清理")
		return
	}
	zlog.Info(innerLogName, "网站密码访问会话清理完成", "标记到期", expired, "删除历史行", deleted)

	// 到期按轮汇总一条审计，不逐条写：一批同时到期的会话逐条记，就是一堆内容雷同的流水，
	// 把真正要看的登录/踢下线记录淹掉。
	if expired > 0 {
		waf_service.WafSecurityAuditServiceApp.Write(waf_service.AuditEntry{
			Event:   model.HttpAuthEventExpired,
			Result:  model.AccessAuditOK,
			Message: "网站密码访问会话到期清理，本轮 " + strconv.FormatInt(expired, 10) + " 条",
		})
	}
}
