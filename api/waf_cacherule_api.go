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
)

type WafCacheRuleApi struct {
}

// AddApi 新增缓存规则
// @Summary      新增缓存规则
// @Description  为指定网站新增一条缓存规则
// @Tags         网站防护-缓存规则
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafCacheRuleAddReq  true  "缓存规则配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/cacherule/add [post]
func (w *WafCacheRuleApi) AddApi(c *gin.Context) {
	var req request.WafCacheRuleAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		cnt := wafCacheRuleService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafCacheRuleService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
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

// GetDetailApi 获取缓存规则详情
// @Summary      获取缓存规则详情
// @Description  根据ID获取缓存规则详情
// @Tags         网站防护-缓存规则
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "规则ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/cacherule/detail [get]
func (w *WafCacheRuleApi) GetDetailApi(c *gin.Context) {
	var req request.WafCacheRuleDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafCacheRuleService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取缓存规则列表
// @Summary      获取缓存规则列表
// @Description  分页查询缓存规则列表
// @Tags         网站防护-缓存规则
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafCacheRuleSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/cacherule/list [post]
func (w *WafCacheRuleApi) GetListApi(c *gin.Context) {
	var req request.WafCacheRuleSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		CacheRule, total, _ := wafCacheRuleService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      CacheRule,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelApi 删除缓存规则
// @Summary      删除缓存规则
// @Description  根据ID删除缓存规则
// @Tags         网站防护-缓存规则
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "规则ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/cacherule/del [get]
func (w *WafCacheRuleApi) DelApi(c *gin.Context) {
	var req request.WafCacheRuleDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafCacheRuleService.GetDetailByIdApi(req.Id)
		if bean.Id == "" {
			response.FailWithMessage("未找到信息", c)
			return
		}
		err = wafCacheRuleService.DelApi(req)
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

// ModifyApi 编辑缓存规则
// @Summary      编辑缓存规则
// @Description  修改缓存规则配置
// @Tags         网站防护-缓存规则
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafCacheRuleEditReq  true  "缓存规则配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/cacherule/edit [post]
func (w *WafCacheRuleApi) ModifyApi(c *gin.Context) {
	var req request.WafCacheRuleEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafCacheRuleService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// NotifyWaf  通知到waf引擎实时生效
func (w *WafCacheRuleApi) NotifyWaf(host_code string) {
	var list []model.CacheRule
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&list)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeCacheRule,
		Content:  list,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
