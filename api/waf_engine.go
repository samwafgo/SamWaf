package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"github.com/gin-gonic/gin"
)

type WafEngineApi struct {
}

// ResetWaf 重启WAF引擎
// @Summary      重启WAF引擎
// @Description  重启WAF引擎，重新加载所有规则和配置
// @Tags         引擎-WAF引擎
// @Produce      json
// @Success      200  {object}  response.Response  "重启指令发起成功"
// @Security     ApiKeyAuth
// @Router       /resetWAF [get]
func (w *WafEngineApi) ResetWaf(c *gin.Context) {
	//重启WAF引擎
	global.GWAF_CHAN_ENGINE <- 1
	response.OkWithMessage("重启指令发起成功", c)
}
