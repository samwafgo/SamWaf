package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafStatApi struct {
}

func (w *WafStatApi) StatHomeSumDayApi(c *gin.Context) {

	wafStat, _ := wafStatService.StatHomeSumDayApi()
	response.OkWithDetailed(wafStat, "获取成功", c)
}
func (w *WafStatApi) StatHomeSumDayRangeApi(c *gin.Context) {
	var req request.WafStatsDayRangeReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafStat, _ := wafStatService.StatHomeSumDayRangeApi(req)
		response.OkWithDetailed(wafStat, "获取成功", c)
	} else {

		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafStatApi) StatHomeSumDayTopIPRangeApi(c *gin.Context) {
	var req request.WafStatsDayRangeReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafStat, _ := wafStatService.StatHomeSumDayTopIPRangeApi(req)
		response.OkWithDetailed(wafStat, "获取成功", c)
	} else {

		response.FailWithMessage("解析失败", c)
	}
}

// 数据分析界面- 国家级别分析
func (w *WafStatApi) StatAnalysisDayCountryRangeApi(c *gin.Context) {
	var req request.WafStatsAnalysisDayRangeCountryReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafStat := wafStatService.StatAnalysisDayCountryRangeApi(req)
		response.OkWithDetailed(wafStat, "获取成功", c)
	} else {

		response.FailWithMessage("解析失败", c)
	}
}
