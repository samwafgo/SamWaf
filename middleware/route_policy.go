package middleware

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

// RouteClass 共享组路由的授权类别。
type RouteClass int

const (
	RouteClassWrite    RouteClass = iota // 一般写操作：审计管理员以外的角色
	RouteClassRead                       // 只读查询：任意已登录角色
	RouteClassSelf                       // 只影响本人（改本人密码、界面偏好、升级须知已读等）：任意已登录角色
	RouteClassSecurity                   // 网站与回源相关的防护策略写操作：安全管理员、超级管理员
	RouteClassSystem                     // 系统级访问控制、证书、自升级：系统管理员、超级管理员
)

func (rc RouteClass) String() string {
	switch rc {
	case RouteClassRead:
		return "read"
	case RouteClassSelf:
		return "self"
	case RouteClassSecurity:
		return "security"
	case RouteClassSystem:
		return "system"
	default:
		return "write"
	}
}

// 共享组路由策略表，键为「方法 路由模板」（与 gin 的 c.FullPath() 一致）。
// 共享组新增路由必须在这里登记，守护单测会逐条核对；未登记的路由只放行超级管理员。
var (
	routesRead = []string{
		"GET /api/v1/analysis/actor/list",
		"GET /api/v1/analysis/detail",
		"GET /api/v1/analysis/path/list",
		"GET /api/v1/analysis/spider",
		"GET /api/v1/analysis/wafanalysisdaycountryrange",
		"GET /api/v1/cdnip/provider/info",
		"GET /api/v1/cdnip/provider/list",
		"POST /api/v1/cdnip/provider/ranges",
		"GET /api/v1/export",
		"GET /api/v1/file/data_files",
		"GET /api/v1/gpt/config",
		"GET /api/v1/heartbeat",
		"POST /api/v1/hostconn/list",
		"GET /api/v1/hostconn/refresh",
		"GET /api/v1/hostconn/summary",
		"POST /api/v1/hostguard/ban/list",
		"POST /api/v1/hostguard/event/list",
		"GET /api/v1/hostguard/ladder/list",
		"POST /api/v1/hostguard/offender/list",
		"GET /api/v1/hostguard/statistics",
		"GET /api/v1/hostguard/status",
		"POST /api/v1/hostguard/whitelist/test",
		"GET /api/v1/iplocation/config",
		"GET /api/v1/iplocation/status",
		"POST /api/v1/iplocation/test",
		"GET /api/v1/iplocation/upgrade/check",
		"GET /api/v1/iplocation/upgrade/progress",
		"GET /api/v1/license/detail",
		"GET /api/v1/logfilewrite/backupfiles",
		"GET /api/v1/logfilewrite/currentfile",
		"GET /api/v1/logfilewrite/preview",
		"GET /api/v1/logfilewrite/variables",
		"GET /api/v1/monitor/system_info",
		"GET /api/v1/notify/channel/detail",
		"POST /api/v1/notify/channel/list",
		"GET /api/v1/notify/globalthrottle",
		"GET /api/v1/notify/log/detail",
		"POST /api/v1/notify/log/list",
		"GET /api/v1/notify/subscription/detail",
		"POST /api/v1/notify/subscription/list",
		"POST /api/v1/notify/subscription/preview",
		"GET /api/v1/notify/subscription/templatevars",
		"GET /api/v1/firewall/ipblock/capability",
		"GET /api/v1/firewall/ipblock/detail",
		"POST /api/v1/firewall/ipblock/list",
		"GET /api/v1/firewall/ipblock/statistics",
		"GET /api/v1/samwaf/report/config",
		"POST /api/v1/samwaf/report/download",
		"GET /api/v1/samwaf/report/list",
		"GET /api/v1/sslconfig/detail",
		"POST /api/v1/sslconfig/list",
		"GET /api/v1/statrumtimesysinfo",
		"GET /api/v1/statsysinfo",
		"GET /api/v1/sysinfo/announcement",
		"GET /api/v1/sysinfo/checkversion",
		"GET /api/v1/sysinfo/rollbacklist",
		"GET /api/v1/sysinfo/runtimeinfo",
		"GET /api/v1/sysinfo/systemparams",
		"GET /api/v1/sysinfo/updateprogress",
		"GET /api/v1/sysinfo/version",
		"POST /api/v1/threatip/channel/list",
		"GET /api/v1/threatip/channel/detail",
		"POST /api/v1/threatip/exclude/audit",
		"GET /api/v1/threatip/exclude/builtin",
		"POST /api/v1/threatip/exclude/list",
		"POST /api/v1/threatip/exclude/preview",
		"POST /api/v1/threatip/landed/ips",
		"GET /api/v1/threatip/landed/summary",
		"GET /api/v1/tunnel/tunnel/connections",
		"GET /api/v1/tunnel/tunnel/detail",
		"POST /api/v1/tunnel/tunnel/list",
		"GET /api/v1/tunnel/tunnel/protection/detail",
		"GET /api/v1/upgradenotice/summary",
		"POST /api/v1/upgradenotice/list",
		"GET /api/v1/vipconfig/getAdminTitles",
		"GET /api/v1/vipconfig/getCorsAllowOrigins",
		"GET /api/v1/vipconfig/getDomainWhitelist",
		"GET /api/v1/vipconfig/getIpWhitelist",
		"GET /api/v1/vipconfig/getManageCDNProvider",
		"GET /api/v1/vipconfig/getManageTrustedProxies",
		"GET /api/v1/vipconfig/getNoticeTitle",
		"GET /api/v1/vipconfig/getSecurityEntry",
		"GET /api/v1/vipconfig/getSslBindCert",
		"GET /api/v1/vipconfig/getSslForceHttps",
		"GET /api/v1/vipconfig/getSslStatus",
		"GET /api/v1/vipconfig/localCertStatus",
		"GET /api/v1/wafhost/blockingpage/backendunavailablebuiltin",
		"GET /api/v1/wafhost/blockingpage/detail",
		"POST /api/v1/wafhost/blockingpage/list",
		"GET /api/v1/wafhost/blockingpage/unmatchedbuiltin",
		"GET /api/v1/wafhost/cacherule/detail",
		"POST /api/v1/wafhost/cacherule/list",
		"GET /api/v1/wafhost/caserverinfo/detail",
		"POST /api/v1/wafhost/caserverinfo/list",
		"GET /api/v1/wafhost/dataretention/detail",
		"POST /api/v1/wafhost/dataretention/list",
		"GET /api/v1/wafhost/host/alldomainbyhostcode",
		"GET /api/v1/wafhost/host/allhost",
		"POST /api/v1/wafhost/host/checkports",
		"GET /api/v1/wafhost/host/detail",
		"GET /api/v1/wafhost/host/ipsource/probe",
		"POST /api/v1/wafhost/host/list",
		"GET /api/v1/wafhost/hostgroup/all",
		"GET /api/v1/wafhost/hostgroup/detail",
		"POST /api/v1/wafhost/hostgroup/list",
		"GET /api/v1/wafhost/httpauthbase/detail",
		"POST /api/v1/wafhost/httpauthbase/list",
		"POST /api/v1/wafhost/httpauthsession/list",
		"GET /api/v1/wafhost/ip/lookup",
		"GET /api/v1/wafhost/loadbalance/detail",
		"POST /api/v1/wafhost/loadbalance/list",
		"GET /api/v1/wafhost/onekeymod/detail",
		"POST /api/v1/wafhost/onekeymod/list",
		"GET /api/v1/wafhost/pathrule/detail",
		"POST /api/v1/wafhost/pathrule/list",
		"GET /api/v1/wafhost/port/overview",
		"GET /api/v1/wafhost/privategroup/detail",
		"POST /api/v1/wafhost/privategroup/list",
		"POST /api/v1/wafhost/privategroup/listbybelongcloud",
		"GET /api/v1/wafhost/privateinfo/detail",
		"POST /api/v1/wafhost/privateinfo/list",
		"GET /api/v1/wafhost/sslexpire/detail",
		"POST /api/v1/wafhost/sslexpire/list",
		"GET /api/v1/wafhost/sslorder/detail",
		"POST /api/v1/wafhost/sslorder/list",
		"GET /api/v1/wafhost/tamperrule/baseline",
		"GET /api/v1/wafhost/tamperrule/detail",
		"POST /api/v1/wafhost/tamperrule/list",
		"GET /api/v1/wafhost/task/detail",
		"POST /api/v1/wafhost/task/list",
		"GET /api/v1/wafhost/task/log",
		"GET /api/v1/waflog/attack/alliptag",
		"GET /api/v1/waflog/attack/allsharedb",
		"POST /api/v1/waflog/attack/attackiplist",
		"GET /api/v1/waflog/attack/detail",
		"GET /api/v1/waflog/attack/download",
		"GET /api/v1/waflog/attack/export",
		"GET /api/v1/waflog/attack/httpcopymask",
		"GET /api/v1/waflog/attack/iptagdbstatus",
		"POST /api/v1/waflog/attack/list",
		"POST /api/v1/waflog/attack/watchlist/list",
		"GET /api/v1/waflog/exports",
		"GET /api/v1/waflog/exports/:id",
		"GET /api/v1/waflog/exports/capabilities",
		"GET /api/v1/wafstatqpstrend",
		"GET /api/v1/wafstatsitedetail",
		"GET /api/v1/wafstatsiteoverview",
		"GET /api/v1/wafstatsumday",
		"GET /api/v1/wafstatsumdayrange",
		"GET /api/v1/wafstatsumdaytopiprange",
		"GET /api/v1/ws",
		"POST /api/v1/batch_task/list",
		"GET /api/v1/batch_task/detail",
	}

	routesSelf = []string{
		"POST /api/v1/account/changemypwd",
		"POST /api/v1/logout",
		"POST /api/v1/uipreference/save",
		"GET /api/v1/uipreference/get",
		"POST /api/v1/upgradenotice/ack",
		"POST /api/v1/upgradenotice/downgradeack",
		"POST /api/v1/upgradenotice/ignore",
		"POST /api/v1/upgradenotice/popupshown",
		"POST /api/v1/upgradenotice/restore",
		// 日志导出任务：创建、取消、取下载票据只作用于本人发起的任务，另由 service 按账号校验
		"POST /api/v1/waflog/exports/:id/cancel",
		"POST /api/v1/waflog/exports/:id/download-ticket",
	}

	routesSecurity = []string{
		"POST /api/v1/import",
		"POST /api/v1/wafhost/host/add",
		"POST /api/v1/wafhost/host/batchcopyconfig",
		"GET /api/v1/wafhost/host/del",
		"POST /api/v1/wafhost/host/diagnostic",
		"POST /api/v1/wafhost/host/edit",
		"GET /api/v1/wafhost/host/guardstatus",
		"POST /api/v1/wafhost/host/health/test",
		"GET /api/v1/wafhost/host/ipsource/probe/clear",
		"POST /api/v1/wafhost/host/modfiyallstatus",
		"GET /api/v1/wafhost/host/startstatus",
		"POST /api/v1/wafhost/hostgroup/add",
		"POST /api/v1/wafhost/hostgroup/assign",
		"GET /api/v1/wafhost/hostgroup/del",
		"POST /api/v1/wafhost/hostgroup/edit",
		"POST /api/v1/wafhost/hostgroup/sort",
		"POST /api/v1/wafhost/loadbalance/add",
		"GET /api/v1/wafhost/loadbalance/del",
		"POST /api/v1/wafhost/loadbalance/edit",
		"POST /api/v1/wafhost/pathrule/add",
		"GET /api/v1/wafhost/pathrule/del",
		"POST /api/v1/wafhost/pathrule/edit",
		"POST /api/v1/batch_task/add",
		"GET /api/v1/batch_task/del",
		"POST /api/v1/batch_task/edit",
		"GET /api/v1/batch_task/manual",
	}

	routesSystem = []string{
		// 系统级访问控制、证书、自升级：仅系统管理员（或超级管理员）
		"POST /api/v1/vipconfig/updateIpWhitelist",
		"POST /api/v1/vipconfig/updateManageTrustedProxies",
		"GET /api/v1/vipconfig/manageClientIpProbe",
		"GET /api/v1/vipconfig/cdnProviderRanges",
		"POST /api/v1/vipconfig/updateManageCDNProvider",
		"POST /api/v1/vipconfig/updateCorsAllowOrigins",
		"POST /api/v1/vipconfig/updateSslEnable",
		"POST /api/v1/vipconfig/uploadSslCert",
		"POST /api/v1/vipconfig/generateLocalCert",
		"POST /api/v1/vipconfig/rotateLocalCa",
		"POST /api/v1/vipconfig/clearLocalCert",
		"POST /api/v1/vipconfig/restartManager",
		"POST /api/v1/vipconfig/updateSecurityEntry",
		"POST /api/v1/vipconfig/updateNoticeTitle",
		"POST /api/v1/vipconfig/updateAdminTitles",
		"POST /api/v1/vipconfig/updateDomainWhitelist",
		"POST /api/v1/vipconfig/updateSslForceHttps",
		"POST /api/v1/vipconfig/updateSslBindCert",
		"POST /api/v1/wafhost/caserverinfo/add",
		"POST /api/v1/wafhost/caserverinfo/edit",
		"GET /api/v1/wafhost/caserverinfo/del",
		"POST /api/v1/wafhost/sslorder/add",
		"GET /api/v1/wafhost/sslorder/del",
		"POST /api/v1/wafhost/sslorder/edit",
		"POST /api/v1/sslconfig/add",
		"POST /api/v1/sslconfig/edit",
		"GET /api/v1/sslconfig/del",
		"POST /api/v1/cdnip/provider/autofetch",
		"POST /api/v1/cdnip/provider/credential",
		"POST /api/v1/cdnip/provider/credential/clear",
		"POST /api/v1/cdnip/provider/refresh",
		"GET /api/v1/sysinfo/update",
		"GET /api/v1/sysinfo/cancelupdate",
		"GET /api/v1/sysinfo/rollback",
		"GET /api/v1/resetWAF",
	}

	routesWrite = []string{
		// 会向管理员配置的外部地址发出请求，或生成本机文件
		"POST /api/v1/gpt/chat",
		"POST /api/v1/samwaf/report/create",
		"POST /api/v1/waflog/exports",
		"GET /api/v1/file/delete_by_id",
		"POST /api/v1/gpt/config/save",
		"POST /api/v1/hostconn/block",
		"POST /api/v1/hostguard/ban/manual",
		"POST /api/v1/hostguard/ban/permanent",
		"POST /api/v1/hostguard/ban/release",
		"POST /api/v1/hostguard/ladder/save",
		"POST /api/v1/hostguard/offender/del",
		"POST /api/v1/hostguard/offender/reset",
		"POST /api/v1/hostguard/whitelist/add",
		"POST /api/v1/iplocation/config/save",
		"POST /api/v1/iplocation/reload",
		"POST /api/v1/iplocation/upgrade/apply",
		"POST /api/v1/iplocation/upgrade/cancel",
		"POST /api/v1/iplocation/upload",
		"POST /api/v1/license/checklicense",
		"GET /api/v1/license/confirm",
		"POST /api/v1/logfilewrite/clear",
		"POST /api/v1/notify/channel/add",
		"GET /api/v1/notify/channel/del",
		"POST /api/v1/notify/channel/edit",
		"POST /api/v1/notify/channel/test",
		"POST /api/v1/notify/globalthrottle/update",
		"GET /api/v1/notify/log/del",
		"POST /api/v1/notify/subscription/add",
		"POST /api/v1/notify/subscription/batchconfig",
		"POST /api/v1/notify/subscription/config",
		"GET /api/v1/notify/subscription/del",
		"POST /api/v1/notify/subscription/dryrun",
		"POST /api/v1/notify/subscription/edit",
		"POST /api/v1/notify/subscription/test",
		"POST /api/v1/firewall/ipblock/add",
		"POST /api/v1/firewall/ipblock/batch/add",
		"POST /api/v1/firewall/ipblock/batch/del",
		"POST /api/v1/firewall/ipblock/clear/expired",
		"GET /api/v1/firewall/ipblock/del",
		"POST /api/v1/firewall/ipblock/disable",
		"POST /api/v1/firewall/ipblock/edit",
		"POST /api/v1/firewall/ipblock/enable",
		"POST /api/v1/firewall/ipblock/sync",
		"POST /api/v1/samwaf/report/config",
		"POST /api/v1/samwaf/report/delete",
		"POST /api/v1/threatip/channel/add",
		"GET /api/v1/threatip/channel/del",
		"POST /api/v1/threatip/channel/edit",
		"POST /api/v1/threatip/channel/sync",
		"POST /api/v1/threatip/exclude/add",
		"GET /api/v1/threatip/exclude/del",
		"POST /api/v1/threatip/exclude/edit",
		"POST /api/v1/tunnel/tunnel/add",
		"GET /api/v1/tunnel/tunnel/del",
		"POST /api/v1/tunnel/tunnel/edit",
		"POST /api/v1/tunnel/tunnel/protection/ddns",
		"POST /api/v1/tunnel/tunnel/protection/refresh",
		"POST /api/v1/tunnel/tunnel/protection/region",
		"POST /api/v1/wafhost/blockingpage/add",
		"GET /api/v1/wafhost/blockingpage/del",
		"POST /api/v1/wafhost/blockingpage/edit",
		"POST /api/v1/wafhost/cacherule/add",
		"GET /api/v1/wafhost/cacherule/del",
		"POST /api/v1/wafhost/cacherule/edit",
		"POST /api/v1/wafhost/dataretention/edit",
		"POST /api/v1/wafhost/httpauthbase/add",
		"GET /api/v1/wafhost/httpauthbase/del",
		"POST /api/v1/wafhost/httpauthbase/edit",
		"GET /api/v1/wafhost/httpauthsession/kick",
		"POST /api/v1/wafhost/httpauthsession/kickall",
		"POST /api/v1/wafhost/httpauthsession/kickbyuser",
		"GET /api/v1/wafhost/onekeymod/del",
		"POST /api/v1/wafhost/onekeymod/doModify",
		"POST /api/v1/wafhost/onekeymod/parseNginx",
		"GET /api/v1/wafhost/onekeymod/restore",
		"POST /api/v1/wafhost/privategroup/add",
		"GET /api/v1/wafhost/privategroup/del",
		"POST /api/v1/wafhost/privategroup/edit",
		"POST /api/v1/wafhost/privateinfo/add",
		"GET /api/v1/wafhost/privateinfo/del",
		"POST /api/v1/wafhost/privateinfo/edit",
		"POST /api/v1/wafhost/sslexpire/add",
		"GET /api/v1/wafhost/sslexpire/del",
		"POST /api/v1/wafhost/sslexpire/edit",
		"GET /api/v1/wafhost/sslexpire/nowcheck",
		"GET /api/v1/wafhost/sslexpire/sync_host",
		"POST /api/v1/wafhost/tamperrule/add",
		"POST /api/v1/wafhost/tamperrule/addbatch",
		"GET /api/v1/wafhost/tamperrule/del",
		"POST /api/v1/wafhost/tamperrule/delbatch",
		"POST /api/v1/wafhost/tamperrule/edit",
		"POST /api/v1/wafhost/tamperrule/extract",
		"GET /api/v1/wafhost/tamperrule/relearn",
		"POST /api/v1/wafhost/tamperrule/relearnbatch",
		"POST /api/v1/wafhost/task/add",
		"GET /api/v1/wafhost/task/del",
		"POST /api/v1/wafhost/task/edit",
		"GET /api/v1/wafhost/task/log/clear",
		"GET /api/v1/wafhost/task/manual_exec",
		"POST /api/v1/waflog/attack/deletetagbyname",
		"POST /api/v1/waflog/attack/shard/del",
		"POST /api/v1/waflog/attack/watchlist/add",
		"POST /api/v1/waflog/attack/watchlist/del",
		"DELETE /api/v1/waflog/exports/:id",
	}
)

var routePolicyTable = buildRoutePolicyTable()

func buildRoutePolicyTable() map[string]RouteClass {
	table := make(map[string]RouteClass)
	add := func(keys []string, rc RouteClass) {
		for _, k := range keys {
			if _, dup := table[k]; dup {
				panic("route policy duplicated: " + k)
			}
			table[k] = rc
		}
	}
	add(routesRead, RouteClassRead)
	add(routesSelf, RouteClassSelf)
	add(routesSecurity, RouteClassSecurity)
	add(routesSystem, RouteClassSystem)
	add(routesWrite, RouteClassWrite)
	return table
}

// RoutePolicyEntries 返回策略表副本，供守护单测核对。
func RoutePolicyEntries() map[string]RouteClass {
	out := make(map[string]RouteClass, len(routePolicyTable))
	for k, v := range routePolicyTable {
		out[k] = v
	}
	return out
}

// LookupRouteClass 查路由类别，未登记的返回 write 与 false（调用方按 fail-closed 处理）。
func LookupRouteClass(method, fullPath string) (RouteClass, bool) {
	rc, ok := routePolicyTable[method+" "+fullPath]
	if !ok {
		return RouteClassWrite, false
	}
	return rc, true
}

// RouteClassAllows 判断角色能否访问该类别的路由。
func RouteClassAllows(rc RouteClass, role string) bool {
	role = enums.NormalizeRole(role)
	if role == enums.ROLE_SUPER_ADMIN {
		return true
	}
	switch rc {
	case RouteClassRead, RouteClassSelf:
		return true
	case RouteClassSecurity:
		return role == enums.ROLE_SECURITY_ADMIN
	case RouteClassSystem:
		return role == enums.ROLE_SYSTEM_ADMIN
	default:
		return role != enums.ROLE_AUDIT_ADMIN
	}
}

// routePolicyDeniedMessage 拒绝原因。未登记的路由不提示类别，避免暴露策略表细节。
func routePolicyDeniedMessage(role, method, path string, rc RouteClass, known bool) string {
	if !known {
		return fmt.Sprintf("[%s] %s %s 未登记授权策略", role, method, path)
	}
	return fmt.Sprintf("[%s] %s %s 需要%s权限", role, method, path, rc)
}

// routePolicyDeniedThrottle 同一账号对同一路由的拒绝记录间隔。
const routePolicyDeniedThrottle = 5 * time.Minute

// routePolicyAudit 记录角色校验未通过的请求（同账号同路由节流），测试中可替换。
var routePolicyAudit = func(e waf_service.AuditEntry) {
	key := enums.CACHE_ACCESS_AUDIT + e.Event + ":" + e.AccountName + ":" + e.URL
	if global.GCACHE_WAFCACHE == nil {
		waf_service.WafSecurityAuditServiceApp.Write(e)
		return
	}
	if global.GCACHE_WAFCACHE.IsKeyExist(key) {
		return
	}
	global.GCACHE_WAFCACHE.SetWithTTl(key, "1", routePolicyDeniedThrottle)
	waf_service.WafSecurityAuditServiceApp.Write(e)
}

// RoutePolicy 共享组的角色授权中间件，按路由策略表放行或拒绝。
// 与 RequireRole 口径一致：超级管理员恒通过，OpenAPI Key 调用不受账号角色限制。
// 必须挂载在 Auth() 之后。
func RoutePolicy() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isOpenApi, ok := c.Get("is_openapi"); ok {
			if b, _ := isOpenApi.(bool); b {
				c.Next()
				return
			}
		}
		role := enums.NormalizeRole(c.GetString("userRole"))
		rc, known := LookupRouteClass(c.Request.Method, c.FullPath())
		// 未登记的路由只放行超级管理员：新增路由忘了登记时，其它角色一律拒绝，不按 write 兜底
		if (known && RouteClassAllows(rc, role)) || (!known && role == enums.ROLE_SUPER_ADMIN) {
			c.Next()
			return
		}
		routePolicyAudit(waf_service.AuditEntry{
			Event:       model.AuditEventConfigRoleDenied,
			AccountName: c.GetString("loginAccount"),
			ClientIP:    utils.GetManageClientIP(c),
			URL:         c.Request.Method + " " + c.FullPath(),
			Result:      model.AccessAuditFail,
			Message:     routePolicyDeniedMessage(role, c.Request.Method, c.FullPath(), rc, known),
		})
		response.ForbiddenWithMessage("当前账号角色无权访问该功能", c)
		c.Abort()
	}
}
