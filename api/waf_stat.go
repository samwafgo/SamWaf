package api

import (
	"SamWaf/model/common/response"
	"github.com/gin-gonic/gin"
)

type WafStatApi struct {
}

func (w *WafStatApi) StatHomeApi(c *gin.Context) {

	wafStat, _ := wafStatService.StatHomeApi()
	response.OkWithDetailed(wafStat, "获取成功", c)
}
