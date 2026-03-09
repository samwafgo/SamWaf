package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafAllowIpApi struct {
}

// AddApi 新增IP白名单
// @Summary      新增IP白名单
// @Description  为指定网站新增一条IP白名单记录（白名单IP绕过WAF检测）
// @Tags         网站防护-IP白名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAllowIpAddReq  true  "IP白名单配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/allowip/add [post]
func (w *WafAllowIpApi) AddApi(c *gin.Context) {
	var req request.WafAllowIpAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafIpAllowService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafIpAllowService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前网站的IP已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取IP白名单详情
// @Summary      获取IP白名单详情
// @Description  根据ID获取IP白名单记录详情
// @Tags         网站防护-IP白名单
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/allowip/detail [get]
func (w *WafAllowIpApi) GetDetailApi(c *gin.Context) {
	var req request.WafAllowIpDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpAllowService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取IP白名单列表
// @Summary      获取IP白名单列表
// @Description  分页查询IP白名单列表
// @Tags         网站防护-IP白名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAllowIpSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/allowip/list [post]
func (w *WafAllowIpApi) GetListApi(c *gin.Context) {
	var req request.WafAllowIpSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafIpWhites, total, _ := wafIpAllowService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafIpWhites,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAllowIpApi 删除IP白名单
// @Summary      删除IP白名单
// @Description  根据ID删除IP白名单记录
// @Tags         网站防护-IP白名单
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/allowip/del [get]
func (w *WafAllowIpApi) DelAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpAllowService.GetDetailByIdApi(req.Id)
		err = wafIpAllowService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyWaf(bean.HostCode)
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyAllowIpApi 编辑IP白名单
// @Summary      编辑IP白名单
// @Description  修改IP白名单记录
// @Tags         网站防护-IP白名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAllowIpEditReq  true  "IP白名单配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/allowip/edit [post]
func (w *WafAllowIpApi) ModifyAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafIpAllowService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafAllowIpApi) NotifyWaf(host_code string) {
	var ipWhites []model.IPAllowList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&ipWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeAllowIP,
		Content:  ipWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// BatchDelAllowIpApi 批量删除IP白名单
func (w *WafAllowIpApi) BatchDelAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpAllowService.GetHostCodesByIds(req.Ids)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafIpAllowService.BatchDelApi(req)
		if err != nil {
			response.FailWithMessage("批量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			response.OkWithMessage(fmt.Sprintf("成功删除 %d 条记录", len(req.Ids)), c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAllAllowIpApi 删除指定网站的所有IP白名单
func (w *WafAllowIpApi) DelAllAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpAllowService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafIpAllowService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有IP白名单", c)
			} else {
				response.OkWithMessage("成功删除所有IP白名单", c)
			}
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
