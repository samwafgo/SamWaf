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
