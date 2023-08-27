package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafHostAPi struct {
}

func (w *WafHostAPi) AddApi(c *gin.Context) {
	var req request.WafHostAddReq
	err := c.ShouldBind(&req)
	if err == nil {
		//端口从未在本系统加过，检测端口是否被其他应用占用
		if wafHostService.CheckPortExistApi(req.Port) == 0 && utils.PortCheck(req.Port) == false {
			response.FailWithMessage("端口被其他应用占用不能使用", c)
			return
		}
		err = wafHostService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafHostService.AddApi(req)
			if err == nil {

				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前网站和端口已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafHostAPi) GetDetailApi(c *gin.Context) {
	var req request.WafHostDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafHost := wafHostService.GetDetailApi(req)
		response.OkWithDetailed(wafHost, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafHostAPi) GetListApi(c *gin.Context) {
	var req request.WafHostSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafHosts, total, _ := wafHostService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafHosts,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafHostAPi) GetAllListApi(c *gin.Context) {
	wafHosts := wafHostService.GetAllHostApi()
	allHostRep := make([]response2.AllHostRep, len(wafHosts)) // 创建数组
	for i, _ := range wafHosts {

		if wafHosts[i].Ssl == 1 {
			allHostRep[i] = response2.AllHostRep{
				Host: wafHosts[i].Host + "(SSL)",
				Code: wafHosts[i].Code,
			}
		} else {
			allHostRep[i] = response2.AllHostRep{
				Host: wafHosts[i].Host,
				Code: wafHosts[i].Code,
			}
		}

	}
	response.OkWithDetailed(allHostRep, "获取成功", c)
}
func (w *WafHostAPi) DelHostApi(c *gin.Context) {
	var req request.WafHostDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafHostService.DelHostApi(req)
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

func (w *WafHostAPi) ModifyHostApi(c *gin.Context) {
	var req request.WafHostEditReq
	err := c.ShouldBind(&req)
	if err == nil {
		//端口从未在本系统加过，检测端口是否被其他应用占用
		if wafHostService.CheckPortExistApi(req.Port) == 0 && utils.PortCheck(req.Port) == false {
			response.FailWithMessage("端口被其他应用占用不能使用", c)
			return
		}
		err = wafHostService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafHostAPi) ModifyGuardStatusApi(c *gin.Context) {
	var req request.WafHostGuardStatusReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafHostService.ModifyGuardStatusApi(req)
		if err != nil {
			response.FailWithMessage("更新状态发生错误", c)
		} else {
			wafHost := wafHostService.GetDetailByCodeApi(req.CODE)
			//发送状态改变通知
			global.GWAF_CHAN_HOST <- wafHost
			response.OkWithMessage("状态更新成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到waf引擎实时生效(TODO 此处如果是删除 应该是解除所有相关的，如果是新增编辑等？)
*/
func (w *WafHostAPi) NotifyWaf(host_code string) {
	/*var idpUrls []model.Hosts
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&idpUrls)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeHost,
		Content:  idpUrls,
	}
	global.GWAF_CHAN_MSG <- chanInfo*/
}
