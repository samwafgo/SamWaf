package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"github.com/gin-gonic/gin"
)

type WafEngineApi struct {
}

func (w *WafEngineApi) ResetWaf(c *gin.Context) {
	//重启WAF引擎
	global.GWAF_CHAN_ENGINE <- 1
	response.OkWithMessage("重启指令发起成功", c)
}
