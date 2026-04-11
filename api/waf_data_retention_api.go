package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafDataRetentionApi struct{}

// GetListApi 获取数据保留策略列表
// @Summary      获取数据保留策略列表
// @Tags         数据保留策略
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafDataRetentionSearchReq  true  "分页参数"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /wafhost/dataretention/list [post]
func (w *WafDataRetentionApi) GetListApi(c *gin.Context) {
	var req request.WafDataRetentionSearchReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	policies, err := wafDataRetentionService.GetAllPolicies()
	if err != nil {
		response.FailWithMessage("获取失败:"+err.Error(), c)
		return
	}
	total := int64(len(policies))
	response.OkWithDetailed(response.PageResult{
		List:      policies,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// GetDetailApi 获取策略详情
// @Summary      获取数据保留策略详情
// @Tags         数据保留策略
// @Accept       json
// @Produce      json
// @Param        id  query  string  true  "记录ID"
// @Success      200  {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /wafhost/dataretention/detail [get]
func (w *WafDataRetentionApi) GetDetailApi(c *gin.Context) {
	var req request.WafDataRetentionDetailReq
	err := c.ShouldBind(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean, err := wafDataRetentionService.GetPolicyById(req.Id)
	if err != nil {
		response.FailWithMessage("获取失败:"+err.Error(), c)
		return
	}
	response.OkWithDetailed(bean, "获取成功", c)
}

// ModifyApi 编辑数据保留策略
// @Summary      编辑数据保留策略
// @Tags         数据保留策略
// @Accept       json
// @Produce      json
// @Param        data  body  request.WafDataRetentionEditReq  true  "策略参数"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /wafhost/dataretention/edit [post]
func (w *WafDataRetentionApi) ModifyApi(c *gin.Context) {
	var req request.WafDataRetentionEditReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	err = wafDataRetentionService.UpdatePolicyById(req)
	if err != nil {
		response.FailWithMessage("编辑失败:"+err.Error(), c)
		return
	}
	response.OkWithMessage("编辑成功", c)
}
