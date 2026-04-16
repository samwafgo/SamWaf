package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafStatApi struct {
}

// StatSysinfoApi 获取首页系统基本信息
// @Summary      获取首页系统基本信息
// @Description  获取首页显示的系统基本信息（版本、运行状态等）
// @Tags         统计-数据统计
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /statsysinfo [get]
func (w *WafStatApi) StatSysinfoApi(c *gin.Context) {
	data, err := wafStatService.StatHomeSysinfo(c)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(data, "获取成功", c)
}

// StatRumtimeSysinfoApi 获取运行时系统基本信息
// @Summary      获取运行时系统基本信息
// @Description  获取系统运行时信息（CPU、内存等）
// @Tags         统计-数据统计
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /statrumtimesysinfo [get]
func (w *WafStatApi) StatRumtimeSysinfoApi(c *gin.Context) {

	response.OkWithDetailed(wafStatService.StatHomeRumtimeSysinfo(), "获取成功", c)
}

// StatHomeSumDayApi 获取今日访问统计
// @Summary      获取今日访问统计
// @Description  获取今日访问总量和拦截总量统计
// @Tags         统计-数据统计
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafstatsumday [get]
func (w *WafStatApi) StatHomeSumDayApi(c *gin.Context) {

	wafStat, _ := wafStatService.StatHomeSumDayApi()
	response.OkWithDetailed(wafStat, "获取成功", c)
}

// StatHomeSumDayRangeApi 按日期范围统计访问量
// @Summary      按日期范围统计访问量
// @Description  按指定日期范围查询每日访问量和拦截量
// @Tags         统计-数据统计
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafStatsDayRangeReq  true  "日期范围参数"
// @Success      200   {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafstatsumdayrange [get]
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

// StatHomeSumDayTopIPRangeApi 统计攻击IP排行
// @Summary      统计攻击IP排行
// @Description  按日期范围统计攻击IP排行（Top N）
// @Tags         统计-数据统计
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafStatsDayRangeReq  true  "日期范围参数"
// @Success      200   {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafstatsumdaytopiprange [get]
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

// StatSiteOverviewApi 站点综合概览
// @Summary      站点综合概览统计
// @Description  按日期范围查询各站点的综合访问数据（PV/UV/IP/流量/攻击），完全基于预聚合表
// @Tags         统计-数据统计
// @Produce      json
// @Param        start_day  query     string  false  "开始日期 如 20260301"
// @Param        end_day    query     string  false  "结束日期 如 20260310"
// @Success      200        {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafstatsiteoverview [get]
func (w *WafStatApi) StatSiteOverviewApi(c *gin.Context) {
	var req request.WafStatsSiteOverviewReq
	err := c.ShouldBind(&req)
	if err == nil {
		data, _ := wafStatService.StatSiteOverviewApi(req)
		response.OkWithDetailed(data, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// StatSiteDetailApi 站点详情趋势
// @Summary      站点详情趋势查询
// @Description  查询指定站点的趋势数据（24h走小时聚合，7d/30d走天聚合），完全基于预聚合表
// @Tags         统计-数据统计
// @Produce      json
// @Param        host_code   query     string  true   "网站唯一码"
// @Param        time_range  query     string  true   "时间范围:  24h | 7d | 30d"
// @Success      200         {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafstatsitedetail [get]
func (w *WafStatApi) StatSiteDetailApi(c *gin.Context) {
	var req request.WafStatsSiteDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		data, _ := wafStatService.StatSiteDetailApi(req)
		response.OkWithDetailed(data, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
