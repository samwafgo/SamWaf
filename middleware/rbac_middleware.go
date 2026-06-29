package middleware

import (
	"SamWaf/enums"
	"SamWaf/model/common/response"

	"github.com/gin-gonic/gin"
)

// RequireRole 基于角色的访问控制中间件（三权分立强制点）。
// 规则：
//   - 超级管理员(superAdmin) 恒通过（含空角色兜底，保证向后兼容）
//   - OpenAPI Key 调用（is_openapi）放行：API Key 已经过独立校验，
//     其细粒度授权属于开放平台 Key 体系，不在账号角色范围内，避免影响既有自动化
//   - 角色命中 allowedRoles 通过，否则返回 403
//
// 必须挂载在 Auth() 之后（依赖其写入的 userRole）。
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// OpenAPI Key 调用放行（保持既有能力，不被账号角色限制）
		if isOpenApi, ok := c.Get("is_openapi"); ok {
			if b, _ := isOpenApi.(bool); b {
				c.Next()
				return
			}
		}

		roleVal, _ := c.Get("userRole")
		role, _ := roleVal.(string)
		role = enums.NormalizeRole(role)

		// 超级管理员恒通过
		if role == enums.ROLE_SUPER_ADMIN {
			c.Next()
			return
		}

		for _, allowed := range allowedRoles {
			if role == allowed {
				c.Next()
				return
			}
		}

		response.ForbiddenWithMessage("当前账号角色无权访问该功能", c)
		c.Abort()
	}
}
