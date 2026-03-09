package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSslExpireApi struct {
}

// AddApi 新增SSL到期监控
// @Summary      新增SSL到期监控
// @Description  新增一个SSL证书到期监控配置
// @Tags         SSL到期监控
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSslExpireAddReq  true  "监控配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/sslexpire/add [post]
func (w *WafSslExpireApi) AddApi(c *gin.Context) {
	var req request.WafSslExpireAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		cnt := wafSslExpireService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafSslExpireService.AddApi(req)
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

// GetDetailApi 获取SSL到期监控详情
// @Summary      获取SSL到期监控详情
// @Description  根据ID获取SSL证书到期监控详情
// @Tags         SSL到期监控
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/sslexpire/detail [get]
func (w *WafSslExpireApi) GetDetailApi(c *gin.Context) {
	var req request.WafSslExpireDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSslExpireService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取SSL到期监控列表
// @Summary      获取SSL到期监控列表
// @Description  分页查询SSL证书到期监控列表
// @Tags         SSL到期监控
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSslExpireSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/sslexpire/list [post]
func (w *WafSslExpireApi) GetListApi(c *gin.Context) {
	var req request.WafSslExpireSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		SslExpire, total, _ := wafSslExpireService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      SslExpire,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelApi 删除SSL到期监控
// @Summary      删除SSL到期监控
// @Description  根据ID删除SSL证书到期监控配置
// @Tags         SSL到期监控
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/sslexpire/del [get]
func (w *WafSslExpireApi) DelApi(c *gin.Context) {
	var req request.WafSslExpireDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSslExpireService.DelApi(req)
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

// ModifyApi 编辑SSL到期监控
// @Summary      编辑SSL到期监控
// @Description  修改SSL证书到期监控配置
// @Tags         SSL到期监控
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSslExpireEditReq  true  "监控配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/sslexpire/edit [post]
func (w *WafSslExpireApi) ModifyApi(c *gin.Context) {
	var req request.WafSslExpireEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSslExpireService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// NowCheckExpireApi 立即检测SSL到期情况
// @Summary      立即检测SSL到期情况
// @Description  立即触发一次SSL证书到期检测任务
// @Tags         SSL到期监控
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "发起SSL检测任务成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/sslexpire/nowcheck [get]
func (w *WafSslExpireApi) NowCheckExpireApi(c *gin.Context) {
	if global.GWAF_RUNTIME_SSL_EXPIRE_CHECK {
		response.FailWithMessage("当前检测程序正在进行中", c)
		return
	}

	global.GWAF_RUNTIME_SSL_EXPIRE_CHECK = true
	global.GWAF_CHAN_SSL_EXPIRE_CHECK <- 1
	response.OkWithMessage("发起SSL检测任务成功", c)
}

// SyncHostApi 同步主机信息到SSL监控
// @Summary      同步主机信息到SSL监控
// @Description  将已配置的主机信息批量同步到SSL到期监控列表
// @Tags         SSL到期监控
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "发起同步任务成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/sslexpire/sync_host [get]
func (w *WafSslExpireApi) SyncHostApi(c *gin.Context) {
	if global.GWAF_RUNTIME_SSL_SYNC_HOST {
		response.FailWithMessage("当前正在进行中", c)
		return
	}
	global.GWAF_RUNTIME_SSL_SYNC_HOST = true
	global.GWAF_CHAN_SYNC_HOST_TO_SSL_EXPIRE <- 1
	response.OkWithMessage("发起同步任务成功", c)
}
