package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafPrivateGroupApi struct {
}

// AddApi 新增私有分组
// @Summary      新增私有分组
// @Description  新增一个私有信息分组
// @Tags         私有分组管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafPrivateGroupAddReq  true  "分组配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privategroup/add [post]
func (w *WafPrivateGroupApi) AddApi(c *gin.Context) {
	var req request.WafPrivateGroupAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		cnt := wafPrivateGroupService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafPrivateGroupService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前记录已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取私有分组详情
// @Summary      获取私有分组详情
// @Description  根据ID获取私有分组详情
// @Tags         私有分组管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "分组ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privategroup/detail [get]
func (w *WafPrivateGroupApi) GetDetailApi(c *gin.Context) {
	var req request.WafPrivateGroupDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafPrivateGroupService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取私有分组列表
// @Summary      获取私有分组列表
// @Description  分页查询私有分组列表
// @Tags         私有分组管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafPrivateGroupSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privategroup/list [post]
func (w *WafPrivateGroupApi) GetListApi(c *gin.Context) {
	var req request.WafPrivateGroupSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		PrivateGroup, total, _ := wafPrivateGroupService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      PrivateGroup,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListByBelongCloudApi 按云环境查询私有分组列表
// @Summary      按云环境查询私有分组列表
// @Description  根据所属云环境分页查询私有分组列表
// @Tags         私有分组管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafPrivateGroupSearchByCloudReq  true  "查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privategroup/listbybelongcloud [post]
func (w *WafPrivateGroupApi) GetListByBelongCloudApi(c *gin.Context) {
	var req request.WafPrivateGroupSearchByCloudReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		PrivateGroup, total, _ := wafPrivateGroupService.GetListByBelongCloudApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      PrivateGroup,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelApi 删除私有分组
// @Summary      删除私有分组
// @Description  根据ID删除私有分组
// @Tags         私有分组管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "分组ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privategroup/del [get]
func (w *WafPrivateGroupApi) DelApi(c *gin.Context) {
	var req request.WafPrivateGroupDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafPrivateGroupService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyApi 编辑私有分组
// @Summary      编辑私有分组
// @Description  修改私有分组信息
// @Tags         私有分组管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafPrivateGroupEditReq  true  "分组配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privategroup/edit [post]
func (w *WafPrivateGroupApi) ModifyApi(c *gin.Context) {
	var req request.WafPrivateGroupEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafPrivateGroupService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
