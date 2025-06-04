package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strings"
)

type WafSslOrderApi struct {
}

func (w *WafSslOrderApi) AddApi(c *gin.Context) {
	var req request.WafSslorderaddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		hostBean := wafHostService.GetDetailByCodeApi(req.HostCode)
		if hostBean.Id == "" {
			response.FailWithMessage("查找主机未找到", c)
			return
		}
		//检测是否有80端口
		if req.ApplyMethod == "http01" && w.check80Port(hostBean) == false {
			response.FailWithMessage("未在主机上找到80端口配置，请在绑定更多端口里面增加80端口，再进行发起", c)
			return
		}
		//检测是否*的情况
		if req.ApplyMethod == "http01" && hostBean.Host == "*" {
			response.FailWithMessage("未指定域名情况不能使用http文件验证方式", c)
			return
		}
		addResult, err := wafSslOrderService.AddApi(req)
		if err == nil {
			w.NotifyWaf(enums.ChanSslOrderSubmitted, addResult)
			response.OkWithMessage("添加成功", c)
		} else {
			response.FailWithMessage("添加失败", c)
		}
		return

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSslOrderApi) GetDetailApi(c *gin.Context) {
	var req request.WafSslorderdetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSslOrderService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSslOrderApi) GetListApi(c *gin.Context) {
	var req request.WafSslordersearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafSslOrderService.GetListApi(req)
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
func (w *WafSslOrderApi) DelApi(c *gin.Context) {
	var req request.WafSslorderdeleteReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSslOrderService.DelApi(req)
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

func (w *WafSslOrderApi) ModifyApi(c *gin.Context) {
	var req request.WafSslordereditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		existingOrder := wafSslOrderService.GetDetailById(req.Id)
		if existingOrder.Id == "" {
			response.FailWithMessage("SSL订单不存在", c)
			return
		}

		if existingOrder.ApplyStatus != "success" {
			response.FailWithMessage("上次证书申请未成功，无法续期。请点击新建发起申请", c)
			return
		}
		if len(existingOrder.ResultPrivateKey) == 0 || len(existingOrder.ResultCertificate) == 0 {
			response.FailWithMessage("上次证书未找到，无法续期。请点击新建发起申请", c)
			return
		}
		isExpired, _, _, err := existingOrder.ExpirationMessage()
		if err != nil {
			response.FailWithMessage("无法获取证书到期信息："+err.Error()+",请点击新建发起申请", c)
			return
		}
		if isExpired {
			response.FailWithMessage("证书已过期，无法续期，请点击新建发起申请", c)
			return
		}

		err = wafSslOrderService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("续期发生错误", c)
		} else {
			//发起续期
			renewAdd, err := wafSslOrderService.RenewAdd(req.Id)
			if err == nil {
				w.NotifyWaf(enums.ChanSslOrderrenew, renewAdd)
				response.OkWithMessage("续期成功", c)
			} else {
				response.FailWithMessage("续期失败", c)
			}
		}
	} else {
		response.FailWithMessage("续期解析失败", c)
	}
}

/*
*
发送SSL证书订单通知
*/
func (w *WafSslOrderApi) NotifyWaf(chanType int, bean model.SslOrder) {
	var chanInfo = spec.ChanSslOrder{
		Type:    chanType,
		Content: bean,
	}
	global.GWAF_CHAN_SSLOrder <- chanInfo
}

// 检测是否有80端口
func (w *WafSslOrderApi) check80Port(hosts model.Hosts) bool {
	splitPort := strings.Split(hosts.BindMorePort, ",")

	for _, port := range splitPort {
		if port == "80" {
			return true
		}
	}
	if hosts.Port == 80 {
		return true
	}
	return false
}
