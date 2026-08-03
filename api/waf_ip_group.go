package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/utils"

	"github.com/gin-gonic/gin"
)

type WafIPGroupApi struct {
}

// AddApi 新增IP组
// @Summary      新增IP组
// @Description  新增一个可跨站点复用的IP组
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupAddReq  true  "IP组信息"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/add [post]
func (w *WafIPGroupApi) AddApi(c *gin.Context) {
	var req request.WafIPGroupAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean, err := wafIPGroupService.AddApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 新组还没有条目，但要先把空匹配集登记进快照，
	// 否则规则里 RF.IPInGroup 引用它时会走「组不存在」分支，语义上不如「组为空」清晰
	wafIPGroupService.RebuildGroupMatcher(bean.GroupCode)
	response.OkWithDetailed(bean, "添加成功", c)
}

// GetListApi 获取IP组列表
// @Summary      获取IP组列表
// @Description  分页查询IP组列表，含每组的条目数
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/list [post]
func (w *WafIPGroupApi) GetListApi(c *gin.Context) {
	var req request.WafIPGroupSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, _ := wafIPGroupService.GetListApi(req)
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// GetOptionsApi 获取IP组下拉选项
// @Summary      获取IP组下拉选项
// @Description  返回全部IP组(不分页)，供黑/白名单表单选择引用
// @Tags         网站防护-IP组
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/options [get]
func (w *WafIPGroupApi) GetOptionsApi(c *gin.Context) {
	response.OkWithDetailed(wafIPGroupService.GetOptionsApi(), "获取成功", c)
}

// GetDetailApi 获取IP组详情
// @Summary      获取IP组详情
// @Tags         网站防护-IP组
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/detail [get]
func (w *WafIPGroupApi) GetDetailApi(c *gin.Context) {
	var req request.WafIPGroupDetailReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafIPGroupService.GetDetailApi(req), "获取成功", c)
}

// ModifyApi 编辑IP组
// @Summary      编辑IP组
// @Description  只允许修改名称与备注；组短码创建后不可变(黑白名单与规则都在引用它)
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupEditReq  true  "IP组信息"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/edit [post]
func (w *WafIPGroupApi) ModifyApi(c *gin.Context) {
	var req request.WafIPGroupEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean, err := wafIPGroupService.ModifyApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 改名要刷新快照里的名称索引，否则规则里按新名字引用查不到、按旧名字还能查到
	wafIPGroupService.RebuildGroupMatcher(bean.GroupCode)
	response.OkWithMessage("编辑成功", c)
}

// GetRefsApi 查询IP组的引用情况
// @Summary      查询IP组的引用情况
// @Description  返回该组被多少条黑/白名单引用、涉及哪些站点，供删除前确认
// @Tags         网站防护-IP组
// @Produce      json
// @Param        group_code  query     string  true  "组短码"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/refs [get]
func (w *WafIPGroupApi) GetRefsApi(c *gin.Context) {
	var req request.WafIPGroupRefsReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafIPGroupService.GetRefsApi(req.GroupCode), "获取成功", c)
}

// DelApi 删除IP组
// @Summary      删除IP组
// @Description  默认拒绝删除被引用的组；force=1 时级联删除引用它的黑/白名单条目
// @Tags         网站防护-IP组
// @Produce      json
// @Param        id     query     string  true   "记录ID"
// @Param        force  query     int     false  "1=级联删除引用条目"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/del [get]
func (w *WafIPGroupApi) DelApi(c *gin.Context) {
	var req request.WafIPGroupDelReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	affectedHosts, err := wafIPGroupService.DelApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 引用行已被级联删除，逐站点刷新内存名单去脏
	notifyIPListHosts(affectedHosts)
	response.OkWithMessage("删除成功", c)
}

// ValidateApi 校验IP写法
// @Summary      校验IP写法
// @Description  校验单IP/CIDR/通配符/区间的写法是否合法，供前端即时反馈
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupValidateReq  true  "待校验的IP"
// @Success      200   {object}  response.Response  "校验完成"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroup/validate [post]
func (w *WafIPGroupApi) ValidateApi(c *gin.Context) {
	var req request.WafIPGroupValidateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if utils.IsCatchAllIPPattern(req.Ip) {
		response.OkWithDetailed(gin.H{
			"valid":   false,
			"message": "该写法会匹配所有IP，风险过高；如确需全匹配请显式填写 0.0.0.0/0 或 ::/0",
		}, "校验完成", c)
		return
	}
	ok, msg := utils.IsValidIPPattern(req.Ip)
	response.OkWithDetailed(gin.H{"valid": ok, "message": msg}, "校验完成", c)
}
