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

// NowCheckExpireApi 现在检测过期情况
func (w *WafSslExpireApi) NowCheckExpireApi(c *gin.Context) {
	if global.GWAF_RUNTIME_SSL_EXPIRE_CHECK {
		response.FailWithMessage("当前检测程序正在进行中", c)
		return
	}

	global.GWAF_RUNTIME_SSL_EXPIRE_CHECK = true
	global.GWAF_CHAN_SSL_EXPIRE_CHECK <- 1
	response.OkWithMessage("发起SSL检测任务成功", c)
}

// SyncHostApi 同步已存在主机信息
func (w *WafSslExpireApi) SyncHostApi(c *gin.Context) {
	if global.GWAF_RUNTIME_SSL_SYNC_HOST {
		response.FailWithMessage("当前正在进行中", c)
		return
	}
	global.GWAF_RUNTIME_SSL_SYNC_HOST = true
	global.GWAF_CHAN_SYNC_HOST_TO_SSL_EXPIRE <- 1
	response.OkWithMessage("发起同步任务成功", c)
}
