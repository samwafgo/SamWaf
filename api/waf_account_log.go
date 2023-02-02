package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafAccountLogApi struct {
}

func (w *WafAccountLogApi) GetDetailApi(c *gin.Context) {
	var req request.WafAccountLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAccountLogService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAccountLogApi) GetListApi(c *gin.Context) {
	var req request.WafAccountLogSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		beans, total, _ := wafAccountLogService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      beans,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
