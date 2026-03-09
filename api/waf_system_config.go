package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/waftask"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSystemConfigApi struct {
}

func (w *WafSystemConfigApi) AddApi(c *gin.Context) {
	var req request.WafSystemConfigAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSystemConfigService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafSystemConfigService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前数据已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSystemConfigApi) GetDetailApi(c *gin.Context) {
	var req request.WafSystemConfigDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSystemConfigService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取系统配置列表
// @Summary      获取系统配置列表
// @Description  分页查询系统配置项列表
// @Tags         系统配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSystemConfigSearchReq  true  "查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /systemconfig/list [post]
func (w *WafSystemConfigApi) GetListApi(c *gin.Context) {
	var req request.WafSystemConfigSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafSystemConfigService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      beans,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSystemConfigApi) DelApi(c *gin.Context) {
	var req request.WafSystemConfigDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSystemConfigService.DelApi(req)
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

// ModifyApi 更新系统配置
// @Summary      更新系统配置
// @Description  修改系统配置项的值
// @Tags         系统配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSystemConfigEditReq  true  "配置参数"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /systemconfig/edit [post]
func (w *WafSystemConfigApi) ModifyApi(c *gin.Context) {
	var req request.WafSystemConfigEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSystemConfigService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			waftask.TaskLoadSetting(true)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyByItemApi 通过item更新系统配置
// @Summary      通过item更新系统配置
// @Description  通过配置项的 item 键名修改对应的 value 值
// @Tags         系统配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSystemConfigEditByItemReq  true  "配置参数"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /systemconfig/updateitem [post]
func (w *WafSystemConfigApi) ModifyByItemApi(c *gin.Context) {
	var req request.WafSystemConfigEditByItemReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	if req.Item == "" {
		response.FailWithMessage("item 不能为空", c)
		return
	}

	err = wafSystemConfigService.ModifyByItemApi(req)
	if err != nil {
		response.FailWithMessage("编辑发生错误: "+err.Error(), c)
	} else {
		waftask.TaskLoadSetting(true)
		response.OkWithMessage("编辑成功", c)
	}
}

func (w *WafSystemConfigApi) GetDetailByItemApi(c *gin.Context) {
	var req request.WafSystemConfigDetailByItemReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSystemConfigService.GetDetailByItemApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
