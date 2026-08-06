package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafLoginHistoryApi struct {
}

func (w *WafLoginHistoryApi) GetListApi(c *gin.Context) {
	var req request.WafLoginHistorySearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		if req.PageIndex <= 0 {
			req.PageIndex = 1
		}
		if req.PageSize <= 0 || req.PageSize > 100 {
			req.PageSize = 10
		}
		beans, total, err := wafLoginHistoryService.GetListApi(req)
		if err != nil {
			response.FailWithMessage("查询失败", c)
			return
		}
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
