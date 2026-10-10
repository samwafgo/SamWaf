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

// AnalysisActorListApi 来源与路径分析 - 行为视角（谁在打）
func (w *WafAnalysisApi) AnalysisActorListApi(c *gin.Context) {
	var req request.WafAnalysisActorReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafAnalysisViewService.ActorListApi(req), "获取成功", c)
}

// AnalysisPathListApi 来源与路径分析 - 目标视角（打哪里）
func (w *WafAnalysisApi) AnalysisPathListApi(c *gin.Context) {
	var req request.WafAnalysisPathReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafAnalysisViewService.PathListApi(req), "获取成功", c)
}

// AnalysisDetailApi 来源与路径分析 - 抽屉下钻
func (w *WafAnalysisApi) AnalysisDetailApi(c *gin.Context) {
	var req request.WafAnalysisDetailReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if req.Kind != "actor" && req.Kind != "path" {
		response.FailWithMessage("kind 只能是 actor 或 path", c)
		return
	}
	if req.Key == "" {
		response.FailWithMessage("请传入要查看的 key", c)
		return
	}
	response.OkWithDetailed(wafAnalysisViewService.DetailApi(req), "获取成功", c)
}
