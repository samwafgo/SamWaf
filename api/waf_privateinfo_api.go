package api

import (
	"SamWaf/common/zlog"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"os"
)

type WafPrivateInfoApi struct {
}

// AddApi 新增私有信息
// @Summary      新增私有信息
// @Description  新增一条私有配置信息（如 API Key、密码等敏感数据）
// @Tags         私有信息管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafPrivateInfoAddReq  true  "私有信息配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privateinfo/add [post]
func (w *WafPrivateInfoApi) AddApi(c *gin.Context) {
	var req request.WafPrivateInfoAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		cnt := wafPrivateInfoService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafPrivateInfoService.AddApi(req)
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

// GetDetailApi 获取私有信息详情
// @Summary      获取私有信息详情
// @Description  根据ID获取私有信息详情，敏感值字段自动脱敏
// @Tags         私有信息管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privateinfo/detail [get]
func (w *WafPrivateInfoApi) GetDetailApi(c *gin.Context) {
	var req request.WafPrivateInfoDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafPrivateInfoService.GetDetailApi(req)

		// 在返回前端前脱敏处理
		if bean.PrivateKey != "" {
			bean.PrivateValue = "****"
		}

		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取私有信息列表
// @Summary      获取私有信息列表
// @Description  分页查询私有信息列表，敏感值字段自动脱敏
// @Tags         私有信息管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafPrivateInfoSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privateinfo/list [post]
func (w *WafPrivateInfoApi) GetListApi(c *gin.Context) {
	var req request.WafPrivateInfoSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		PrivateInfo, total, _ := wafPrivateInfoService.GetListApi(req)

		// 在返回前端前脱敏处理
		for i := range PrivateInfo {
			PrivateInfo[i].PrivateValue = "****"
		}

		response.OkWithDetailed(response.PageResult{
			List:      PrivateInfo,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelApi 删除私有信息
// @Summary      删除私有信息
// @Description  根据ID删除私有信息，同时清除对应的环境变量
// @Tags         私有信息管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privateinfo/del [get]
func (w *WafPrivateInfoApi) DelApi(c *gin.Context) {
	var req request.WafPrivateInfoDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		info := wafPrivateInfoService.GetDetailByIdApi(req.Id)
		key := info.PrivateKey
		err = wafPrivateInfoService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			err := os.Unsetenv(key)
			if err == nil {
				zlog.Info(fmt.Sprintf("ENV `%s` REMOVED", key))
			}
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyApi 编辑私有信息
// @Summary      编辑私有信息
// @Description  修改私有信息，若值为"****"则保留原值不更新
// @Tags         私有信息管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafPrivateInfoEditReq  true  "私有信息配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/privateinfo/edit [post]
func (w *WafPrivateInfoApi) ModifyApi(c *gin.Context) {
	var req request.WafPrivateInfoEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if req.PrivateValue == "****" {
			err = wafPrivateInfoService.ModifyWithOutValueApi(req)
		} else {
			err = wafPrivateInfoService.ModifyApi(req)
		}

		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
