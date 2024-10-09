package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSslConfigApi struct{}

// AddSslConfigApi 添加SSL证书
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
			s.NotifySslUpdate(req.Id)
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifySslConfigApi 编辑SSL证书
func (s *WafSslConfigApi) ModifySslConfigApi(c *gin.Context) {
	var req request.SslConfigEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSslConfigService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			s.NotifySslUpdate(req.Id)
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到SSL引擎使其配置实时生效
*/
func (s *WafSslConfigApi) NotifySslUpdate(id string) {
	global.GWAF_CHAN_SSL <- id
}
