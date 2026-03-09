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
// @Router       /stat/sysinfo [get]
func (w *WafStatApi) StatSysinfoApi(c *gin.Context) {

	response.OkWithDetailed(wafStatService.StatHomeSysinfo(c), "获取成功", c)
}

// StatRumtimeSysinfoApi 获取运行时系统基本信息
// @Summary      获取运行时系统基本信息
// @Description  获取系统运行时信息（CPU、内存等）
// @Tags         统计-数据统计
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /stat/runtimesysinfo [get]
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
// @Router       /stat/daytotal [get]
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
// @Router       /stat/dayrangecount [post]
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
// @Router       /stat/ipcount [post]
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
