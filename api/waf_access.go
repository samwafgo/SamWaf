package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

// waf_access.go 是统一访问认证(Access 模式)的管理端接口。
//
// 分四块：访问账号、全局配置、在线会话、审计日志。
// RBAC 归属见 wafmangeweb/localserver.go —— 前三块是安全管理员，审计日志是审计管理员。

// ─────────────────────────── 访问账号 ───────────────────────────

type WafAccessAccountApi struct {
}

// AddApi 新增访问账号
// @Summary      新增访问账号
// @Description  新增一个统一访问认证的访客账号（密码 bcrypt 存储，不可读回）
// @Tags         统一访问认证-访问账号
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessAccountAddReq  true  "账号信息"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/add [post]
func (w *WafAccessAccountApi) AddApi(c *gin.Context) {
	var req request.WafAccessAccountAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean, err := wafAccessAccountService.AddApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(bean, "添加成功", c)
}

// GetListApi 获取访问账号列表
// @Summary      获取访问账号列表
// @Tags         统一访问认证-访问账号
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessAccountSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/list [post]
func (w *WafAccessAccountApi) GetListApi(c *gin.Context) {
	var req request.WafAccessAccountSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, err := wafAccessAccountService.GetListApi(req)
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

// GetDetailApi 获取访问账号详情
// @Summary      获取访问账号详情
// @Tags         统一访问认证-访问账号
// @Produce      json
// @Param        id  query  string  true  "账号ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/detail [get]
func (w *WafAccessAccountApi) GetDetailApi(c *gin.Context) {
	var req request.WafAccessAccountDetailReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean, err := wafAccessAccountService.GetDetailApi(req.Id)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(bean, "获取成功", c)
}

// ModifyApi 编辑访问账号
// @Summary      编辑访问账号
// @Description  登录名不可修改（会话与审计以它关联）；改密请用 resetpwd 接口
// @Tags         统一访问认证-访问账号
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessAccountEditReq  true  "账号信息"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/edit [post]
func (w *WafAccessAccountApi) ModifyApi(c *gin.Context) {
	var req request.WafAccessAccountEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAccessAccountService.ModifyApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("编辑成功", c)
}

// ResetPwdApi 重置访问账号密码
// @Summary      重置访问账号密码
// @Description  重置后该账号已有的在线会话会被立即踢下线
// @Tags         统一访问认证-访问账号
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessAccountResetPwdReq  true  "新密码"
// @Success      200   {object}  response.Response  "重置成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/resetpwd [post]
func (w *WafAccessAccountApi) ResetPwdApi(c *gin.Context) {
	var req request.WafAccessAccountResetPwdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAccessAccountService.ResetPwdApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("密码已重置，该账号的在线会话已全部下线", c)
}

// DelApi 删除访问账号
// @Summary      删除访问账号
// @Tags         统一访问认证-访问账号
// @Produce      json
// @Param        id  query  string  true  "账号ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/del [get]
func (w *WafAccessAccountApi) DelApi(c *gin.Context) {
	var req request.WafAccessAccountDelReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAccessAccountService.DelApi(req.Id); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("删除成功", c)
}

// OtpInitApi 生成二次验证密钥与二维码
// @Summary      生成访问账号的二次验证密钥
// @Description  仅生成不落库，需调用 otp/bind 用一次正确动态码确认后才算绑定
// @Tags         统一访问认证-访问账号
// @Produce      json
// @Param        id  query  string  true  "账号ID"
// @Success      200  {object}  response.Response  "生成成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/otp/init [get]
func (w *WafAccessAccountApi) OtpInitApi(c *gin.Context) {
	var req request.WafAccessAccountOtpInitReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	secret, url, err := wafAccessAccountService.OtpInitApi(req.Id)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"secret": secret, "url": url}, "生成成功", c)
}

// OtpBindApi 绑定二次验证
// @Summary      绑定访问账号的二次验证
// @Tags         统一访问认证-访问账号
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessAccountOtpBindReq  true  "密钥与动态码"
// @Success      200   {object}  response.Response  "绑定成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/otp/bind [post]
func (w *WafAccessAccountApi) OtpBindApi(c *gin.Context) {
	var req request.WafAccessAccountOtpBindReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAccessAccountService.OtpBindApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("绑定成功", c)
}

// OtpUnbindApi 解绑二次验证
// @Summary      解绑访问账号的二次验证
// @Tags         统一访问认证-访问账号
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessAccountOtpUnbindReq  true  "账号ID"
// @Success      200   {object}  response.Response  "解绑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaccount/otp/unbind [post]
func (w *WafAccessAccountApi) OtpUnbindApi(c *gin.Context) {
	var req request.WafAccessAccountOtpUnbindReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAccessAccountService.OtpUnbindApi(req.Id); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("解绑成功", c)
}

// ─────────────────────────── 全局配置 ───────────────────────────

type WafAccessConfigApi struct {
}

// GetDetailApi 获取统一访问认证配置
// @Summary      获取统一访问认证配置
// @Description  密钥类字段不回显，仅返回 has_hmac_secret / has_service_token 两个标志位
// @Tags         统一访问认证-配置
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessconfig/detail [get]
func (w *WafAccessConfigApi) GetDetailApi(c *gin.Context) {
	response.OkWithDetailed(wafAccessConfigService.GetDetailApi(), "获取成功", c)
}

// GetCenterHostOptionsApi 获取可用作认证中心的站点地址
// @Summary      获取认证中心域名候选列表
// @Description  由已配置且已启动的站点推导（排除全局网站与泛域名），供配置页下拉直接选用
// @Tags         统一访问认证-配置
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessconfig/hostoptions [get]
func (w *WafAccessConfigApi) GetCenterHostOptionsApi(c *gin.Context) {
	response.OkWithDetailed(wafAccessConfigService.GetCenterHostOptionsApi(), "获取成功", c)
}

// SaveApi 保存统一访问认证配置
// @Summary      保存统一访问认证配置
// @Description  保存后立即发布运行时快照，所有站点同时生效
// @Tags         统一访问认证-配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessConfigSaveReq  true  "配置内容"
// @Success      200   {object}  response.Response  "保存成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessconfig/save [post]
func (w *WafAccessConfigApi) SaveApi(c *gin.Context) {
	var req request.WafAccessConfigSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAccessConfigService.SaveApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("保存成功", c)
}

// RegenerateSecretApi 轮换签名密钥
// @Summary      轮换统一访问认证的签名密钥
// @Description  会使所有在途的认证跳转失效（用户重跳一次即可），已登录会话不受影响
// @Tags         统一访问认证-配置
// @Produce      json
// @Success      200  {object}  response.Response  "轮换成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessconfig/regenerate_secret [post]
func (w *WafAccessConfigApi) RegenerateSecretApi(c *gin.Context) {
	if err := wafAccessConfigService.RegenerateSecretApi(); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("签名密钥已轮换", c)
}

// ─────────────────────────── 在线会话 ───────────────────────────

type WafAccessSessionApi struct {
}

// GetListApi 获取在线会话列表
// @Summary      获取统一访问认证的会话列表
// @Tags         统一访问认证-会话
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessSessionSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accesssession/list [post]
func (w *WafAccessSessionApi) GetListApi(c *gin.Context) {
	var req request.WafAccessSessionSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, err := wafAccessSessionService.GetListApi(req)
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

// KickApi 踢下线单个会话
// @Summary      踢下线指定会话
// @Description  被踢会话及其在各站点上的子令牌一并失效；因存在最长60秒的正向缓存，最迟60秒生效
// @Tags         统一访问认证-会话
// @Produce      json
// @Param        id  query  string  true  "会话ID"
// @Success      200  {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accesssession/kick [get]
func (w *WafAccessSessionApi) KickApi(c *gin.Context) {
	var req request.WafAccessSessionKickReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAccessSessionService.KickApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("已下线（最迟60秒内全网生效）", c)
}

// KickByAccountApi 按账号批量踢下线
// @Summary      踢下线指定账号的全部会话
// @Tags         统一访问认证-会话
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessSessionKickByAccountReq  true  "账号ID"
// @Success      200   {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accesssession/kickbyaccount [post]
func (w *WafAccessSessionApi) KickByAccountApi(c *gin.Context) {
	var req request.WafAccessSessionKickByAccountReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	cnt, err := wafAccessSessionService.KickByAccountApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"count": cnt}, "已下线（最迟60秒内全网生效）", c)
}

// KickAllApi 踢下线全部会话
// @Summary      踢下线全部在线会话
// @Description  应急手段：疑似凭据泄露或策略配错时，一次性让所有人重新登录
// @Tags         统一访问认证-会话
// @Produce      json
// @Success      200  {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accesssession/kickall [get]
func (w *WafAccessSessionApi) KickAllApi(c *gin.Context) {
	cnt := wafAccessSessionService.KickAllApi()
	response.OkWithDetailed(gin.H{"count": cnt}, "已全部下线（最迟60秒内全网生效）", c)
}

// ─────────────────────────── 审计日志 ───────────────────────────

type WafAccessAuditApi struct {
}

// GetListApi 获取访问认证审计日志
// @Summary      获取统一访问认证审计日志
// @Tags         统一访问认证-审计
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAccessAuditSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/accessaudit/list [post]
func (w *WafAccessAuditApi) GetListApi(c *gin.Context) {
	var req request.WafAccessAuditSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, err := wafAccessAuditService.GetListApi(req)
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
