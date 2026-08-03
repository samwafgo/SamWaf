package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafIPGroupItemApi struct {
}

// 说明：所有写接口在成功后都要重建对应组的匹配集（ipset 全局原子快照）。
// 这一次原子替换就让所有引用该组的站点(含全局网站)与自定义规则同时生效，
// 不需要给任何站点下发通道消息，也不会重建路由表。

// AddApi 新增IP组条目
// @Summary      新增IP组条目
// @Description  向指定IP组添加一条IP(支持单IP/CIDR/通配符/区间)
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupItemAddReq  true  "条目信息"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/add [post]
func (w *WafIPGroupItemApi) AddApi(c *gin.Context) {
	var req request.WafIPGroupItemAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafIPGroupItemService.AddApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	wafIPGroupService.RebuildGroupMatcher(req.GroupCode)
	response.OkWithMessage("添加成功", c)
}

// BatchAddApi 批量新增IP组条目
// @Summary      批量新增IP组条目
// @Description  多行文本批量录入，每行一个IP；空行与#开头的注释行忽略，非法行不阻断其余行
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupItemBatchAddReq  true  "批量录入内容"
// @Success      200   {object}  response.Response  "添加完成"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/batch/add [post]
func (w *WafIPGroupItemApi) BatchAddApi(c *gin.Context) {
	var req request.WafIPGroupItemBatchAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	result, err := wafIPGroupItemService.BatchAddApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 整批入库完成后只重建一次，不要逐行重建
	if result.Success > 0 {
		wafIPGroupService.RebuildGroupMatcher(req.GroupCode)
	}
	response.OkWithDetailed(result, "添加完成", c)
}

// GetListApi 获取IP组条目列表
// @Summary      获取IP组条目列表
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupItemSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/list [post]
func (w *WafIPGroupItemApi) GetListApi(c *gin.Context) {
	var req request.WafIPGroupItemSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, _ := wafIPGroupItemService.GetListApi(req)
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// GetDetailApi 获取IP组条目详情
// @Summary      获取IP组条目详情
// @Tags         网站防护-IP组
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/detail [get]
func (w *WafIPGroupItemApi) GetDetailApi(c *gin.Context) {
	var req request.WafIPGroupItemDetailReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafIPGroupItemService.GetDetailApi(req), "获取成功", c)
}

// ModifyApi 编辑IP组条目
// @Summary      编辑IP组条目
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupItemEditReq  true  "条目信息"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/edit [post]
func (w *WafIPGroupItemApi) ModifyApi(c *gin.Context) {
	var req request.WafIPGroupItemEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	groupCode, err := wafIPGroupItemService.ModifyApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	wafIPGroupService.RebuildGroupMatcher(groupCode)
	response.OkWithMessage("编辑成功", c)
}

// DelApi 删除IP组条目
// @Summary      删除IP组条目
// @Tags         网站防护-IP组
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/del [get]
func (w *WafIPGroupItemApi) DelApi(c *gin.Context) {
	var req request.WafIPGroupItemDelReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	groupCode, err := wafIPGroupItemService.DelApi(req)
	if err != nil {
		response.FailWithMessage("删除失败", c)
		return
	}
	wafIPGroupService.RebuildGroupMatcher(groupCode)
	response.OkWithMessage("删除成功", c)
}

// BatchDelApi 批量删除IP组条目
// @Summary      批量删除IP组条目
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupItemBatchDelReq  true  "ID列表"
// @Success      200   {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/batch/del [post]
func (w *WafIPGroupItemApi) BatchDelApi(c *gin.Context) {
	var req request.WafIPGroupItemBatchDelReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	groupCodes, err := wafIPGroupItemService.BatchDelApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	for _, code := range groupCodes {
		wafIPGroupService.RebuildGroupMatcher(code)
	}
	response.OkWithMessage("删除成功", c)
}

// DelAllApi 清空IP组条目
// @Summary      清空IP组条目
// @Description  清空指定IP组内的全部IP，组本身保留
// @Tags         网站防护-IP组
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafIPGroupItemDelAllReq  true  "组短码"
// @Success      200   {object}  response.Response  "清空成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipgroupitem/delall [post]
func (w *WafIPGroupItemApi) DelAllApi(c *gin.Context) {
	var req request.WafIPGroupItemDelAllReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafIPGroupItemService.DelAllApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	wafIPGroupService.RebuildGroupMatcher(req.GroupCode)
	response.OkWithMessage("清空成功", c)
}
