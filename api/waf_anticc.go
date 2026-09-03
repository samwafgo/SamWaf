package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// WafAntiCCApi 旧版单条 CC 配置接口。
//
// Deprecated: 已由多规则接口 /api/v1/wafhost/anticcrule/* 取代。
// 存量配置在数据库迁移时已转换成等价规则，这些接口保留一个版本周期供老前端过渡，
// 之后随旧表一并下线。新功能一律走多规则接口。
type WafAntiCCApi struct {
}

// AddApi 新增CC防护规则
// @Summary      新增CC防护规则
// @Description  为指定网站新增一条CC防护规则（防止CC攻击）
// @Tags         网站防护-CC防护
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAntiCCAddReq  true  "CC防护规则配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/anticc/add [post]
func (w *WafAntiCCApi) AddApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafAntiCCAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 检查是否启用了前置规则
		if req.IsEnableRule {
			// 检查规则内容是否为空
			if req.RuleContent == "" {
				response.FailWithMessage("前置规则内容不能为空", c)
				return
			}
			// 检查规则内容是否合法
			err = ruleHelper.CheckRuleAvailable(req.RuleContent)
			if err != nil {
				response.FailWithMessage("前置规则校验失败", c)
				return
			}
		}

		err = wafAntiCCService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafAntiCCService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败 "+err.Error(), c)
			}
			return
		} else {
			response.FailWithMessage("当前网站的Url已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败"+err.Error(), c)
	}
}

// GetDetailApi 获取CC防护规则详情
// @Summary      获取CC防护规则详情
// @Description  根据ID获取CC防护规则详情
// @Tags         网站防护-CC防护
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "规则ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/anticc/detail [get]
func (w *WafAntiCCApi) GetDetailApi(c *gin.Context) {
	var req request.WafAntiCCDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAntiCCService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取CC防护规则列表
// @Summary      获取CC防护规则列表
// @Description  分页查询CC防护规则列表
// @Tags         网站防护-CC防护
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAntiCCSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/anticc/list [post]
func (w *WafAntiCCApi) GetListApi(c *gin.Context) {
	var req request.WafAntiCCSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafAntiCCService.GetListApi(req)
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

func (w *WafAntiCCApi) GetBanIpListApi(c *gin.Context) {
	banIpList := global.GCACHE_WAFCACHE.ListAvailableKeysWithPrefix(enums.CACHE_CCVISITBAN_PRE)
	beans := make([]response2.CcIpRep, 0, len(banIpList))

	// 站点码换显示名：界面上「仅本站点」得说清楚是哪个站点，只给一串 code 没法用。
	// 带端口（同一域名常有多条记录，各是一个独立站点），与站点下拉的显示名保持一致
	hostNames := map[string]string{}
	for _, h := range wafHostService.GetAllHostApi() {
		hostNames[h.Code] = HostDisplayName(h)
	}

	// 遍历 banIpList，将每个 IP 信息添加到 beans 中
	for cacheKey, duration := range banIpList {
		scope, hostCode, banIp, ok := model.ParseCCBanKey(cacheKey)
		if !ok {
			continue
		}

		// 带上秒：封禁时长常常不足一分钟，只显示到分会让"还剩 50 秒"和"已经到期"看起来一样
		remainTime := fmt.Sprintf("%02d时%02d分%02d秒",
			int(duration.Hours()), int(duration.Minutes())%60, int(duration.Seconds())%60)

		region := utils.GetCountry(banIp)
		// 将信息添加到 beans 中
		beans = append(beans, response2.CcIpRep{
			IP:         banIp,
			RemainTime: remainTime,
			Region:     fmt.Sprintf("%v", region),
			Scope:      scope,
			HostCode:   hostCode,
			HostName:   hostNames[hostCode],
		})
	}

	// 计算总条目数
	total := len(beans)
	// 返回带分页信息的响应（假设 req.PageIndex 和 req.PageSize 已在请求中解析）
	response.OkWithDetailed(response.PageResult{
		List:      beans,
		Total:     int64(total),
		PageIndex: 1,
		PageSize:  999999,
	}, "获取成功", c)
}

// RemoveCCBanIPApi 移除被封禁的IP
func (w *WafAntiCCApi) RemoveCCBanIPApi(c *gin.Context) {
	var req request.WafAntiCCRemoveBanIpReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 同一个 IP 可能同时存在全局封禁、各站点封禁以及升级前的旧格式键，逐一清理
		removed := false
		for cacheKey := range global.GCACHE_WAFCACHE.ListAvailableKeysWithPrefix(enums.CACHE_CCVISITBAN_PRE) {
			_, _, banIp, ok := model.ParseCCBanKey(cacheKey)
			if ok && banIp == req.Ip {
				global.GCACHE_WAFCACHE.Remove(cacheKey)
				removed = true
			}
		}
		if removed {
			global.GWAF_CHAN_CLEAR_CC_IP <- req.Ip
			response.OkWithMessage(req.Ip+" 移除成功", c)
		} else {
			response.FailWithMessage("键值未找到或以过期", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAntiCCApi 删除CC防护规则
// @Summary      删除CC防护规则
// @Description  根据ID删除CC防护规则
// @Tags         网站防护-CC防护
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "规则ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/anticc/del [get]
func (w *WafAntiCCApi) DelAntiCCApi(c *gin.Context) {
	var req request.WafAntiCCDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAntiCCService.GetDetailByIdApi(req.Id)
		err = wafAntiCCService.DelApi(req)
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

// ModifyAntiCCApi 编辑CC防护规则
// @Summary      编辑CC防护规则
// @Description  修改CC防护规则配置
// @Tags         网站防护-CC防护
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAntiCCEditReq  true  "CC防护规则配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/anticc/edit [post]
func (w *WafAntiCCApi) ModifyAntiCCApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafAntiCCEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 检查是否启用了前置规则
		if req.IsEnableRule {
			// 检查规则内容是否为空
			if req.RuleContent == "" {
				response.FailWithMessage("前置规则内容不能为空", c)
				return
			}
			// 检查规则内容是否合法
			err = ruleHelper.CheckRuleAvailable(req.RuleContent)
			if err != nil {
				response.FailWithMessage("前置规则校验失败", c)
				return
			}
		}

		//编辑前先取旧记录，拿到可能被本次编辑改掉的旧 host_code(issue #898)
		bean := wafAntiCCService.GetDetailByIdApi(req.Id)
		err = wafAntiCCService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			notifyWafHostChanged(w.NotifyWaf, bean.HostCode, req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败"+err.Error(), c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafAntiCCApi) NotifyWaf(host_code string) {
	var antiCC model.AntiCC
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Limit(1).Find(&antiCC)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeAnticc,
		Content:  antiCC,
	}
	global.GWAF_CHAN_MSG <- chanInfo

}
