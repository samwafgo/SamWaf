package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

// WafHttpAuthSessionApi 网站密码访问的在线会话管理。
//
// 与「统一访问认证-会话」不是一套东西：那边是全局认证中心的会话，这边是每个站点自己
// 那道门后面的会话，账号体系与开关都各自独立，所以接口、表、缓存 keyspace 全部分开。
type WafHttpAuthSessionApi struct {
}

// GetListApi 获取某站点的在线会话列表
// @Summary      获取网站密码访问的在线会话列表
// @Tags         网站密码访问-会话
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHttpAuthSessionSearchReq  true  "分页查询参数，host_code 必填"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/httpauthsession/list [post]
func (w *WafHttpAuthSessionApi) GetListApi(c *gin.Context) {
	var req request.WafHttpAuthSessionSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, err := wafHttpAuthSessionService.GetListApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// KickApi 踢下线单条会话
// @Summary      踢下线指定会话
// @Description  因存在最长60秒的正向缓存，最迟60秒生效；浏览器弹窗(Basic)方式下表现为强制重新输入一次密码
// @Tags         网站密码访问-会话
// @Produce      json
// @Param        id  query  string  true  "会话ID"
// @Success      200  {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/httpauthsession/kick [get]
func (w *WafHttpAuthSessionApi) KickApi(c *gin.Context) {
	var req request.WafHttpAuthSessionKickReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafHttpAuthSessionService.KickApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("已下线（最迟60秒内生效）", c)
}

// KickByUserApi 按用户批量踢下线
// @Summary      踢下线指定用户在本站点的全部会话
// @Tags         网站密码访问-会话
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHttpAuthSessionKickByUserReq  true  "站点编码与用户名"
// @Success      200   {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/httpauthsession/kickbyuser [post]
func (w *WafHttpAuthSessionApi) KickByUserApi(c *gin.Context) {
	var req request.WafHttpAuthSessionKickByUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	cnt, err := wafHttpAuthSessionService.KickByUserApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"count": cnt}, "已下线（最迟60秒内生效）", c)
}

// KickAllApi 清空本站点的全部会话
// @Summary      踢下线本站点的全部在线会话
// @Description  应急手段：疑似密码泄露时，一次性让本站点所有人重新登录
// @Tags         网站密码访问-会话
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHttpAuthSessionKickAllReq  true  "站点编码"
// @Success      200   {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/httpauthsession/kickall [post]
func (w *WafHttpAuthSessionApi) KickAllApi(c *gin.Context) {
	var req request.WafHttpAuthSessionKickAllReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	cnt, err := wafHttpAuthSessionService.KickAllApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"count": cnt}, "已全部下线（最迟60秒内生效）", c)
}
