package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafSysLogApi struct {
}

func (w *WafSysLogApi) GetDetailApi(c *gin.Context) {
	var req request.WafSysLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSysLogService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSysLogApi) GetListApi(c *gin.Context) {
	var req request.WafSysLogSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		beans, total, _ := wafSysLogService.GetListApi(req)
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
