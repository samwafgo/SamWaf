package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
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

func (w *WafPrivateInfoApi) AddApi(c *gin.Context) {
	var req request.WafPrivateInfoAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		cnt := wafPrivateInfoService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafPrivateInfoService.AddApi(req)
			if err == nil {
				w.Notify()
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
			w.Notify()
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafPrivateInfoApi) Notify() {
	global.GWAF_CHAN_RELOAD_ENV <- 1
}
