package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafAnalysisApi struct {
}

// StatAnalysisDayCountryRangeApi 数据分析界面- 国家级别分析
func (w *WafAnalysisApi) StatAnalysisDayCountryRangeApi(c *gin.Context) {
	var req request.WafStatsAnalysisDayRangeCountryReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafStat := wafAnalysisService.StatAnalysisDayCountryRangeApi(req)
		response.OkWithDetailed(wafStat, "获取成功", c)
	} else {

		response.FailWithMessage("解析失败", c)
	}
}

// AnalysisSpiderRangeApi 数据分析界面- 爬虫分析
func (w *WafAnalysisApi) AnalysisSpiderRangeApi(c *gin.Context) {
	var req request.WafAnalysisSpiderReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAnalysisService.AnalysisSpiderApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {

		response.FailWithMessage("解析失败", c)
	}
}
