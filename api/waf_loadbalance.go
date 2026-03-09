package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafLoadBalanceApi struct {
}

// AddApi 新增负载均衡节点
// @Summary      新增负载均衡节点
// @Description  为指定网站新增一条后端负载均衡节点配置
// @Tags         网站防护-负载均衡
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafLoadBalanceAddReq  true  "负载均衡节点配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/loadbalance/add [post]
func (w *WafLoadBalanceApi) AddApi(c *gin.Context) {
	var req request.WafLoadBalanceAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafLoadBalanceService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafLoadBalanceService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前负载IP+端口已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取负载均衡节点详情
// @Summary      获取负载均衡节点详情
// @Description  根据ID获取负载均衡节点配置详情
// @Tags         网站防护-负载均衡
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "节点ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/loadbalance/detail [get]
func (w *WafLoadBalanceApi) GetDetailApi(c *gin.Context) {
	var req request.WafLoadBalanceDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafLoadBalanceService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取负载均衡节点列表
// @Summary      获取负载均衡节点列表
// @Description  分页查询负载均衡节点列表
// @Tags         网站防护-负载均衡
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafLoadBalanceSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/loadbalance/list [post]
func (w *WafLoadBalanceApi) GetListApi(c *gin.Context) {
	var req request.WafLoadBalanceSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		list, total, _ := wafLoadBalanceService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      list,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelLoadBalanceApi 删除负载均衡节点
// @Summary      删除负载均衡节点
// @Description  根据ID删除负载均衡后端节点
// @Tags         网站防护-负载均衡
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "节点ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/loadbalance/del [get]
func (w *WafLoadBalanceApi) DelLoadBalanceApi(c *gin.Context) {
	var req request.WafLoadBalanceDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafLoadBalanceService.GetDetailByIdApi(req.Id)
		err = wafLoadBalanceService.DelApi(req)
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

// ModifyApi 编辑负载均衡节点
// @Summary      编辑负载均衡节点
// @Description  修改负载均衡后端节点配置
// @Tags         网站防护-负载均衡
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafLoadBalanceEditReq  true  "负载均衡节点配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/loadbalance/edit [post]
func (w *WafLoadBalanceApi) ModifyApi(c *gin.Context) {
	var req request.WafLoadBalanceEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafLoadBalanceService.ModifyApi(req)
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
func (w *WafLoadBalanceApi) NotifyWaf(host_code string) {

	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeLoadBalance,
		Content:  nil,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
