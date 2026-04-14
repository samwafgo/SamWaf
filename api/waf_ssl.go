package api

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSslConfigApi struct{}

// AddSslConfigApi 新增SSL证书
// @Summary      新增SSL证书
// @Description  上传并保存SSL证书（PEM格式的证书和私钥）
// @Tags         SSL-证书配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.SslConfigAddReq  true  "SSL证书配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /sslconfig/add [post]
func (s *WafSslConfigApi) AddSslConfigApi(c *gin.Context) {
	var req request.SslConfigAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSslConfigService.AddApi(req)
		if err == nil {
			response.OkWithMessage("添加成功", c)
		} else {
			response.FailWithMessage("添加失败:"+err.Error(), c)
		}
		return
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetSslConfigDetailApi 获取SSL证书详情
// @Summary      获取SSL证书详情
// @Description  根据ID获取SSL证书详情
// @Tags         SSL-证书配置
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "证书ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /sslconfig/detail [get]
func (s *WafSslConfigApi) GetSslConfigDetailApi(c *gin.Context) {
	var req request.SslConfigDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSslConfigService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetSslConfigListApi 获取SSL证书列表
// @Summary      获取SSL证书列表
// @Description  分页查询SSL证书列表
// @Tags         SSL-证书配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.SslConfigSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /sslconfig/list [post]
func (s *WafSslConfigApi) GetSslConfigListApi(c *gin.Context) {
	var req request.SslConfigSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		sslList, total, _ := wafSslConfigService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      sslList,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelSslConfigApi 删除SSL证书
// @Summary      删除SSL证书
// @Description  根据ID删除SSL证书
// @Tags         SSL-证书配置
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "证书ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /sslconfig/del [get]
func (s *WafSslConfigApi) DelSslConfigApi(c *gin.Context) {
	var req request.SslConfigDeleteReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSslConfigService.DelApi(req)
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

// ModifySslConfigApi 编辑SSL证书
// @Summary      编辑SSL证书
// @Description  修改SSL证书内容
// @Tags         SSL-证书配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.SslConfigEditReq  true  "SSL证书配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /sslconfig/edit [post]
func (s *WafSslConfigApi) ModifySslConfigApi(c *gin.Context) {
	var req request.SslConfigEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		oldSslBean := wafSslConfigService.GetDetailInner(req.Id)
		err = wafSslConfigService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			newSslBean := wafSslConfigService.GetDetailInner(req.Id)
			if oldSslBean.SerialNo != newSslBean.SerialNo {
				s.NotifySslUpdate(oldSslBean, newSslBean)
			}
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// NotifySslUpdate 通知到SSL引擎使其配置实时生效
func (s *WafSslConfigApi) NotifySslUpdate(oldConfig model.SslConfig, newConfig model.SslConfig) {
	innerLogName := "NotifySslUpdate"
	for _, hosts := range wafHostService.GetHostBySSLConfigId(oldConfig.Id) {
		//1.更新主机信息 2.发送主机通知
		err := wafHostService.UpdateSSLInfo(newConfig.CertContent, newConfig.KeyContent, hosts.Code)
		if err != nil {
			zlog.Error(innerLogName, "ssl host update:", err.Error())
			continue
		}

		hosts.Certfile = newConfig.CertContent
		hosts.Keyfile = newConfig.KeyContent
		var chanInfo = spec.ChanCommonHost{
			HostCode:   hosts.Code,
			Type:       enums.ChanTypeSSL,
			Content:    hosts,
			OldContent: hosts,
		}
		global.GWAF_CHAN_MSG <- chanInfo
	}
}
