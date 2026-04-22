package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type WafOwaspRouter struct{}

// InitWafOwaspRouter 注册 OWASP 规则管理相关路由。
// 前缀 /api/v1/owasp/，大部分为写操作，需要登录后台鉴权（已由外层 Auth 中间件保护）。
func (r *WafOwaspRouter) InitWafOwaspRouter(group *gin.RouterGroup) {
	owaspApi := api.APIGroupAPP.WafOwaspApi
	g := group.Group("")

	g.GET("/api/v1/owasp/rules", owaspApi.RulesListApi)
	g.GET("/api/v1/owasp/rule_detail", owaspApi.RuleDetailApi)
	g.POST("/api/v1/owasp/rule_toggle", owaspApi.RuleToggleApi)
	g.POST("/api/v1/owasp/rule_override", owaspApi.RuleOverrideApi)
	g.POST("/api/v1/owasp/rule_reset", owaspApi.RuleResetApi)
	g.GET("/api/v1/owasp/files", owaspApi.FilesListApi)
	g.GET("/api/v1/owasp/file_content", owaspApi.FileContentApi)
	// Layer 1 基线配置（可修改，优先级低于 Layer 2 tuning）
	g.GET("/api/v1/owasp/base_config", owaspApi.BaseConfigGetApi)
	g.POST("/api/v1/owasp/base_config", owaspApi.BaseConfigSetApi)

	// Layer 2 用户覆盖配置（优先级最高）
	g.GET("/api/v1/owasp/tuning", owaspApi.TuningGetApi)
	g.POST("/api/v1/owasp/tuning", owaspApi.TuningSetApi)
	g.POST("/api/v1/owasp/reload", owaspApi.ReloadApi)
	g.POST("/api/v1/owasp/test/dry_run", owaspApi.TestDryRunApi)

	// 升级相关（在 upgrader 步骤里实现具体 handler）
	g.GET("/api/v1/owasp/update/check", owaspApi.UpdateCheckApi)
	g.POST("/api/v1/owasp/update/apply", owaspApi.UpdateApplyApi)

	// 变更审计日志
	g.GET("/api/v1/owasp/audit_log", owaspApi.AuditLogApi)

	// CRS 事务变量管理
	g.GET("/api/v1/owasp/crs_vars", owaspApi.CRSVarsGetApi)
	g.POST("/api/v1/owasp/crs_var", owaspApi.CRSVarSetApi)
	g.DELETE("/api/v1/owasp/crs_var", owaspApi.CRSVarDeleteApi)

	// 使用文档
	g.GET("/api/v1/owasp/usage/doc", owaspApi.UsageDocApi)

	// 规则命中统计（运行期内存统计，重启清零）
	g.GET("/api/v1/owasp/hit_stats", owaspApi.HitStatsApi)
	g.POST("/api/v1/owasp/hit_stats/reset", owaspApi.HitStatsResetApi)
}
