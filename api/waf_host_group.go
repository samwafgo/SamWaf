package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafHostGroupApi struct {
}

// AddApi 新增网站分组
// @Summary      新增网站分组
// @Description  新增一个网站分组（仅用于管理端的组织与批量选择，不承载防护配置）
// @Tags         网站防护-网站分组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGroupAddReq  true  "分组信息"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/add [post]
func (w *WafHostGroupApi) AddApi(c *gin.Context) {
	var req request.WafHostGroupAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean, err := wafHostGroupService.AddApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(bean, "添加成功", c)
}

// ModifyApi 编辑网站分组
// @Summary      编辑网站分组
// @Description  只允许修改名称、颜色与备注，分组短码不可变
// @Tags         网站防护-网站分组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGroupEditReq  true  "分组信息"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/edit [post]
func (w *WafHostGroupApi) ModifyApi(c *gin.Context) {
	var req request.WafHostGroupEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean, err := wafHostGroupService.ModifyApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(bean, "编辑成功", c)
}

// DelApi 删除网站分组
// @Summary      删除网站分组
// @Description  组内网站不会被删除，只是回落到「未分组」
// @Tags         网站防护-网站分组
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/del [get]
func (w *WafHostGroupApi) DelApi(c *gin.Context) {
	var req request.WafHostGroupDelReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if req.Id == "" {
		response.FailWithMessage("参数不完整", c)
		return
	}
	affected, err := wafHostGroupService.DelApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(affected, "删除成功", c)
}

// GetDetailApi 获取网站分组详情
// @Summary      获取网站分组详情
// @Tags         网站防护-网站分组
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/detail [get]
func (w *WafHostGroupApi) GetDetailApi(c *gin.Context) {
	var req request.WafHostGroupDetailReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafHostGroupService.GetDetailApi(req), "获取成功", c)
}

// GetListApi 获取网站分组列表
// @Summary      获取网站分组列表
// @Description  分页查询网站分组，含每组的网站数
// @Tags         网站防护-网站分组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGroupSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/list [post]
func (w *WafHostGroupApi) GetListApi(c *gin.Context) {
	var req request.WafHostGroupSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, _ := wafHostGroupService.GetListApi(req)
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// GetAllApi 获取全部网站分组
// @Summary      获取全部网站分组
// @Description  不分页，供网站列表左栏与网站表单下拉使用，额外带「未分组」与「全部」计数
// @Tags         网站防护-网站分组
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/all [get]
func (w *WafHostGroupApi) GetAllApi(c *gin.Context) {
	response.OkWithDetailed(wafHostGroupService.GetOptionsApi(), "获取成功", c)
}

// SortApi 网站分组排序
// @Summary      网站分组排序
// @Description  提交完整的分组ID顺序，按数组下标写排序权重
// @Tags         网站防护-网站分组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGroupSortReq  true  "分组ID顺序"
// @Success      200   {object}  response.Response  "排序成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/sort [post]
func (w *WafHostGroupApi) SortApi(c *gin.Context) {
	var req request.WafHostGroupSortReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if len(req.Ids) > 200 {
		response.FailWithMessage("排序内容过多", c)
		return
	}
	if err := wafHostGroupService.SortApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("排序成功", c)
}

// AssignApi 批量移动网站到分组
// @Summary      批量移动网站到分组
// @Description  group_code 为空表示移出分组；全局网站不参与分组，会被自动剔除
// @Tags         网站防护-网站分组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGroupAssignReq  true  "网站与目标分组"
// @Success      200   {object}  response.Response  "移动成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/hostgroup/assign [post]
func (w *WafHostGroupApi) AssignApi(c *gin.Context) {
	var req request.WafHostGroupAssignReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	// 分组只是管理端的组织维度，不参与请求期判定，
	// 因此这里不需要通知引擎刷新主机（见 model/host_group.go）。
	affected, err := wafHostGroupService.AssignApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(affected, "移动成功", c)
}
