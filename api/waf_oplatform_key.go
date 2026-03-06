package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafOPlatformKeyApi struct{}

func (w *WafOPlatformKeyApi) AddApi(c *gin.Context) {
	var req request.WafOPlatformKeyAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	if req.KeyName == "" {
		response.FailWithMessage("Key名称不能为空", c)
		return
	}
	id, apiKey, err := wafOPlatformKeyService.AddApi(req)
	if err != nil {
		response.FailWithMessage("添加失败:"+err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"id": id, "api_key": apiKey}, "添加成功", c)
}

func (w *WafOPlatformKeyApi) ModifyApi(c *gin.Context) {
	var req request.WafOPlatformKeyEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	if err := wafOPlatformKeyService.ModifyApi(req); err != nil {
		response.FailWithMessage("修改失败:"+err.Error(), c)
		return
	}
	response.OkWithMessage("修改成功", c)
}

func (w *WafOPlatformKeyApi) DelApi(c *gin.Context) {
	var req request.WafOPlatformKeyDelReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	if err := wafOPlatformKeyService.DelApi(req); err != nil {
		response.FailWithMessage("删除失败:"+err.Error(), c)
		return
	}
	response.OkWithMessage("删除成功", c)
}

func (w *WafOPlatformKeyApi) GetDetailApi(c *gin.Context) {
	var req request.WafOPlatformKeyDetailReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	bean := wafOPlatformKeyService.GetDetailApi(req)
	response.OkWithData(bean, c)
}

func (w *WafOPlatformKeyApi) GetListApi(c *gin.Context) {
	var req request.WafOPlatformKeySearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	if req.PageSize == 0 {
		req.PageSize = 10
	}
	if req.PageIndex == 0 {
		req.PageIndex = 1
	}
	list, total, err := wafOPlatformKeyService.GetListApi(req)
	if err != nil {
		response.FailWithMessage("查询失败", c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "查询成功", c)
}

func (w *WafOPlatformKeyApi) ResetSecretApi(c *gin.Context) {
	var req request.WafOPlatformKeyResetSecretReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	newApiKey, err := wafOPlatformKeyService.ResetApiKey(req)
	if err != nil {
		response.FailWithMessage("重置失败:"+err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"api_key": newApiKey}, "重置成功", c)
}
