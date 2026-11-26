package api

import (
	"SamWaf/service/waf_service"
	"SamWaf/utils"

	"github.com/gin-gonic/gin"
)

// staticRootAuditTarget 组装静态目录变更审计的操作人与对象信息。
func staticRootAuditTarget(c *gin.Context, objectType, objectID, hostCode, host, label string) waf_service.StaticRootAuditTarget {
	return waf_service.StaticRootAuditTarget{
		Actor:      c.GetString("loginAccount") + "[" + c.GetString("userRole") + "]",
		ClientIP:   utils.GetManageClientIP(c),
		ObjectType: objectType,
		ObjectID:   objectID,
		HostCode:   hostCode,
		Host:       host,
		Label:      label,
	}
}
