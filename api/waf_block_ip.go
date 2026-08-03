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

type WafBlockIpApi struct {
}

// AddApi 新增IP黑名单
// @Summary      新增IP黑名单
// @Description  为指定网站新增一条IP黑名单记录
// @Tags         网站防护-IP黑名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafBlockIpAddReq  true  "IP黑名单配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipblock/add [post]
func (w *WafBlockIpApi) AddApi(c *gin.Context) {
	var req request.WafBlockIpAddReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	// 封禁层级：""/waf=WAF应用层(默认) | system=系统防火墙 | both=两者
	layer := req.TargetLayer
	if layer == "" {
		layer = "waf"
	}

	// 系统防火墙层封禁
	if layer == "system" || layer == "both" {
		fwReq := request.WafFirewallIPBlockAddReq{
			HostCode:  req.HostCode,
			IP:        req.Ip,
			Reason:    "手动加入黑名单",
			BlockType: "manual",
			Remarks:   req.Remarks,
		}
		if ferr := wafFirewallIPBlockService.AddApi(fwReq); ferr != nil {
			response.FailWithMessage("系统防火墙封禁失败: "+ferr.Error(), c)
			return
		}
		if layer == "system" {
			response.OkWithMessage("已在系统防火墙层面封禁", c)
			return
		}
	}

	// WAF 应用层封禁(默认 / both)
	err = wafIpBlockService.CheckIsExistApi(req)
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		if aerr := wafIpBlockService.AddApi(req); aerr != nil {
			response.FailWithMessage("添加失败", c)
			return
		}
		w.NotifyWaf(req.HostCode)
		response.OkWithMessage("添加成功", c)
		return
	}
	// WAF 层已存在：若同时已成功加系统层(both)，视为成功；否则提示已存在
	if layer == "both" {
		response.OkWithMessage("系统层已封禁；WAF层该IP已存在", c)
		return
	}
	response.FailWithMessage("当前网站的IP已经存在", c)
}

// GetRecommendLayerApi 返回推荐的封禁层级(供前端"加黑名单"弹窗下拉预选)
func (w *WafBlockIpApi) GetRecommendLayerApi(c *gin.Context) {
	hostCode := c.Query("host_code")
	layer, reason := wafFirewallIPBlockService.RecommendBlockLayer(hostCode)
	response.OkWithDetailed(gin.H{"layer": layer, "reason": reason}, "获取成功", c)
}

// GetDetailApi 获取IP黑名单详情
// @Summary      获取IP黑名单详情
// @Description  根据ID获取IP黑名单记录详情
// @Tags         网站防护-IP黑名单
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipblock/detail [get]
func (w *WafBlockIpApi) GetDetailApi(c *gin.Context) {
	var req request.WafBlockIpDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpBlockService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取IP黑名单列表
// @Summary      获取IP黑名单列表
// @Description  分页查询IP黑名单列表
// @Tags         网站防护-IP黑名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafBlockIpSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipblock/list [post]
func (w *WafBlockIpApi) GetListApi(c *gin.Context) {
	var req request.WafBlockIpSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafIpWhites, total, _ := wafIpBlockService.GetListApi(req)
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

// DelBlockIpApi 删除IP黑名单
// @Summary      删除IP黑名单
// @Description  根据ID删除IP黑名单记录
// @Tags         网站防护-IP黑名单
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipblock/del [get]
func (w *WafBlockIpApi) DelBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpBlockService.GetDetailByIdApi(req.Id)
		err = wafIpBlockService.DelApi(req)
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

// ModifyBlockIpApi 编辑IP黑名单
// @Summary      编辑IP黑名单
// @Description  修改IP黑名单记录
// @Tags         网站防护-IP黑名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafBlockIpEditReq  true  "IP黑名单配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ipblock/edit [post]
func (w *WafBlockIpApi) ModifyBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		//编辑前先取旧记录，拿到可能被本次编辑改掉的旧 host_code(issue #898)
		bean := wafIpBlockService.GetDetailByIdApi(req.Id)
		err = wafIpBlockService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			notifyWafHostChanged(w.NotifyWaf, bean.HostCode, req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// BatchDelBlockIpApi 批量删除IP黑名单
func (w *WafBlockIpApi) BatchDelBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpBlockService.GetHostCodesByIds(req.Ids)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafIpBlockService.BatchDelApi(req)
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

// DelAllBlockIpApi 删除指定网站的所有IP黑名单
func (w *WafBlockIpApi) DelAllBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpBlockService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafIpBlockService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有IP黑名单", c)
			} else {
				response.OkWithMessage("成功删除所有IP黑名单", c)
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
func (w *WafBlockIpApi) NotifyWaf(host_code string) {
	var ipWhites []model.IPBlockList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&ipWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeBlockIP,
		Content:  ipWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
