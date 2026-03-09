package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/wafonekey"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafOneKeyModApi struct {
}

// GetDetailApi 获取一键修改记录详情
// @Summary      获取一键修改记录详情
// @Description  根据ID获取一键修改记录详情
// @Tags         一键修改
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/onekeymod/detail [get]
func (w *WafOneKeyModApi) GetDetailApi(c *gin.Context) {
	var req request.WafOneKeyModDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafOneKeyModService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取一键修改记录列表
// @Summary      获取一键修改记录列表
// @Description  分页查询一键修改历史记录列表
// @Tags         一键修改
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafOneKeyModSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/onekeymod/list [post]
func (w *WafOneKeyModApi) GetListApi(c *gin.Context) {
	var req request.WafOneKeyModSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafOneKeyModService.GetListApi(req)
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

// DelApi 删除一键修改记录
// @Summary      删除一键修改记录
// @Description  根据ID删除一键修改历史记录
// @Tags         一键修改
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/onekeymod/del [get]
func (w *WafOneKeyModApi) DelApi(c *gin.Context) {
	var req request.WafOneKeyModDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafOneKeyModService.DelApi(req)
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

// DoOneKeyModifyApi 执行一键修改
// @Summary      执行一键修改
// @Description  对指定文件路径执行一键批量修改操作
// @Tags         一键修改
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafDoOneKeyModReq  true  "一键修改参数"
// @Success      200   {object}  response.Response  "修改成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/onekeymod/doModify [post]
func (w *WafOneKeyModApi) DoOneKeyModifyApi(c *gin.Context) {
	var req request.WafDoOneKeyModReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err, s := wafonekey.OneKeyModifyBt(req.FilePath)
		if err != nil {
			response.FailWithMessage("修改失败 "+err.Error(), c)
		} else {
			response.OkWithMessage(s, c)
		}

	} else {
		response.FailWithMessage("修改失败", c)
	}
}

// RestoreApi 还原一键修改
// @Summary      还原一键修改
// @Description  根据ID还原指定的一键修改记录到原始状态
// @Tags         一键修改
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "还原成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/onekeymod/restore [get]
func (w *WafOneKeyModApi) RestoreApi(c *gin.Context) {
	var req request.WafOneKeyModRestoreReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafonekey.RestoreOneKeyMod(req.Id)
		if err != nil {
			response.FailWithMessage("还原失败 "+err.Error(), c)
		} else {
			response.OkWithMessage("还原成功 请重启在宝塔面板上进行Nginx重启", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
