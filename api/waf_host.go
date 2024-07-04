package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafHostAPi struct {
}

func (w *WafHostAPi) AddApi(c *gin.Context) {
	var req request.WafHostAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		//端口从未在本系统加过，检测端口是否被其他应用占用
		_, svrOk := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ServerOnline[req.Port]
		if !svrOk && utils.PortCheck(req.Port) == false {
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.PushBack(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "端口被其他应用占用不能使用,如果使用的宝塔请在Samwaf系统管理-一键修改进行操作",
				Success:         "true",
			})
			//return
			req.START_STATUS = 1 //设置成不能启动
		}
		err = wafHostService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			hostCode, err := wafHostService.AddApi(req)
			if err == nil {
				w.NotifyWaf(hostCode, nil)
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
	err := c.ShouldBindJSON(&req)
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
		host, err := wafHostService.DelHostApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyDelWaf(host)
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafHostAPi) ModifyHostApi(c *gin.Context) {
	var req request.WafHostEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafHostOld := wafHostService.GetDetailByCodeApi(req.CODE)
		//端口从未在本系统加过，检测端口是否被其他应用占用

		_, svrOk := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ServerOnline[req.Port]
		if !svrOk && utils.PortCheck(req.Port) == false {
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.PushBack(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "端口被其他应用占用不能使用,如果使用的宝塔请在Samwaf系统管理-一键修改进行操作",
				Success:         "true",
			})
			req.START_STATUS = 1 //设置成不能启动
		}
		err = wafHostService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			w.NotifyWaf(req.CODE, wafHostOld)
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
修改启动状态
*/
func (w *WafHostAPi) ModifyStartStatusApi(c *gin.Context) {
	var req request.WafHostStartStatusReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafHostOld := wafHostService.GetDetailByCodeApi(req.CODE)

		_, svrOk := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ServerOnline[wafHostOld.Port]

		if req.START_STATUS == 0 && !svrOk && utils.PortCheck(wafHostOld.Port) == false {
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.PushBack(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "端口被其他应用占用不能使用,如果使用的宝塔请在Samwaf系统管理-一键修改进行操作",
				Success:         "true",
			})
			response.FailWithMessage("端口被其他应用占用不能开启", c)
			return
		} else {
			err = wafHostService.ModifyStartStatusApi(req)
			if err != nil {
				response.FailWithMessage("更新状态发生错误", c)
			} else {
				//发送状态改变通知
				w.NotifyWaf(req.CODE, wafHostOld)
				response.OkWithMessage("状态更新成功", c)
			}
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafHostAPi) NotifyWaf(hostCode string, oldHostInterface interface{}) {

	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Where("code = ? ", hostCode).Find(&hosts)
	var chanInfo = spec.ChanCommonHost{
		HostCode:   hostCode,
		Type:       enums.ChanTypeHost,
		Content:    hosts,
		OldContent: oldHostInterface,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

func (w *WafHostAPi) NotifyDelWaf(hosts model.Hosts) {
	//1.如果这个port里面没有了主机 那可以直接停掉服务
	//2.除了第一个情况之外的，把所有他的主机信息和关联信息都干掉

	var chanInfo = spec.ChanCommonHost{
		HostCode: hosts.Code,
		Type:     enums.ChanTypeDelHost,
		Content:  hosts,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
