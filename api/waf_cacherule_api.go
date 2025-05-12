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
