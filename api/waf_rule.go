package api

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"SamWaf/wafenginecore/wafhttpcore"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafRuleAPi struct {
}

// AddApi 新增WAF规则
// @Summary      新增WAF规则
// @Description  新增一条WAF防护规则
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleAddReq  true  "规则配置"
// @Success      200   {object}  response.Response{data=string}  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/add [post]
func (w *WafRuleAPi) AddApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafRuleAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		var ruleTool = model.RuleTool{}
		ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
		if err != nil {
			response.FailWithMessage("规则解析错误", c)
			return
		}
		var ruleCode = uuid.GenUUID()
		if req.IsManualRule == 1 {
			ruleCodeFormDRL, err := ruleHelper.ExtractRuleName(req.RuleJson)
			if err != nil {
				response.FailWithMessage(err.Error(), c)
			}
			if ruleCodeFormDRL != "{SamWafUUID}" {
				ruleCode = ruleCodeFormDRL
			}
		} else {
			//手工编码情况下 前端准备好的
			ruleCode = req.RuleCode
		}
		if ruleInfo.RuleBase.RuleDomainCode == "请选择网站" {
			response.FailWithMessage("请选择网站", c)
			return
		}
		count := wafRuleService.CheckIsExistApi(ruleInfo.RuleBase.RuleName, ruleInfo.RuleBase.RuleDomainCode)
		if count > 0 {
			response.FailWithMessage("当前规则已存在", c)
			return
		}
		chsName := ruleInfo.RuleBase.RuleName

		if req.IsManualRule == 1 {
			existBean := wafRuleService.GetDetailByCodeApi(ruleCode)
			if existBean.RuleCode != "" {
				response.FailWithMessage("当前编码已存在，请刷新页面重新尝试", c)
				return
			}
		}
		ruleInfo.RuleBase.RuleName = strings.Replace(ruleCode, "-", "", -1)

		var ruleContent = ruleTool.GenRuleInfo(ruleInfo, chsName)
		if req.IsManualRule == 1 {
			ruleContent = ruleInfo.RuleContent
			//检查规则是否合法
			err = ruleHelper.CheckRuleAvailable(ruleContent)
			if err != nil {
				response.FailWithMessage("规则校验失败", c)
				return
			}
		}

		err = wafRuleService.AddApi(req, ruleCode, chsName, ruleInfo.RuleBase.RuleDomainCode, ruleContent)
		if err == nil {
			w.NotifyWaf(ruleInfo.RuleBase.RuleDomainCode)
			response.OkWithMessage("添加成功", c)
			return
		} else {

			response.FailWithMessage("添加失败", c)
			return
		}
	} else {
		response.FailWithMessage("解析失败", c)
		return
	}
}

// GetDetailApi 获取WAF规则详情
// @Summary      获取WAF规则详情
// @Description  根据 code 获取单条WAF规则详情
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "规则唯一编码"
// @Success      200   {object}  response.Response{data=model.Rules}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/detail [get]
func (w *WafRuleAPi) GetDetailApi(c *gin.Context) {
	var req request.WafRuleDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafHost := wafRuleService.GetDetailApi(req)
		response.OkWithDetailed(wafHost, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取WAF规则列表
// @Summary      获取WAF规则列表
// @Description  分页查询WAF防护规则列表
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/list [post]
func (w *WafRuleAPi) GetListApi(c *gin.Context) {
	var req request.WafRuleSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafRules, total, _ := wafRuleService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafRules,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafRuleAPi) GetListByHostCodeApi(c *gin.Context) {
	var req request.WafRuleSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafRules, total, _ := wafRuleService.GetListByHostCodeApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafRules,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelRuleApi 删除WAF规则
// @Summary      删除WAF规则
// @Description  根据 code 删除WAF防护规则
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "规则唯一编码"
// @Success      200   {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/del [get]
func (w *WafRuleAPi) DelRuleApi(c *gin.Context) {
	var req request.WafRuleDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafRule := wafRuleService.GetDetailByCodeApi(req.CODE)
		err = wafRuleService.DelRuleApi(req)
		//TODO 通知引擎重新加载某个网站的规则信息
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
			return
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyWaf(wafRule.HostCode)
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyRuleApi 编辑WAF规则
// @Summary      编辑WAF规则
// @Description  修改已有WAF防护规则配置
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleEditReq  true  "规则配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/edit [post]
func (w *WafRuleAPi) ModifyRuleApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafRuleEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		var ruleTool = model.RuleTool{}
		rule := wafRuleService.GetDetailByCodeApi(req.CODE)

		if req.IsManualRule == 1 {
			ruleCodeFormDRL, err := ruleHelper.ExtractRuleName(req.RuleJson)
			if err != nil {
				response.FailWithMessage(err.Error(), c)
			}
			if rule.RuleCode != ruleCodeFormDRL {
				zlog.Debug(fmt.Sprintf("原始的规则码 %v， 需要替换的规则码 %v", rule.RuleCode, ruleCodeFormDRL))
				beforeJson := req.RuleJson
				req.RuleJson = strings.Replace(req.RuleJson, ruleCodeFormDRL, strings.Replace(rule.RuleCode, "-", "", -1), -1)
				zlog.Debug(fmt.Sprintf("原始信息 %v 替换后信息 %v ", beforeJson, req.RuleJson))

			}
		}
		ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
		if err != nil {
			response.FailWithMessage("解析错误", c)
			return
		}

		var ruleName = ruleInfo.RuleBase.RuleName //中文名
		ruleInfo.RuleBase.RuleName = strings.Replace(rule.RuleCode, "-", "", -1)
		var ruleContent = ruleTool.GenRuleInfo(ruleInfo, ruleName)
		if req.IsManualRule == 1 {
			ruleContent = ruleInfo.RuleContent
			//检查规则是否合法
			err = ruleHelper.CheckRuleAvailable(ruleContent)
			if err != nil {
				response.FailWithMessage("规则校验失败", c)
				return
			}
		}

		err = wafRuleService.ModifyApi(req, ruleName, ruleInfo.RuleBase.RuleDomainCode, ruleContent)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			w.NotifyWaf(ruleInfo.RuleBase.RuleDomainCode)
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
func (w *WafRuleAPi) NotifyWaf(host_code string) {
	var ruleconfig []model.Rules
	global.GWAF_LOCAL_DB.Where("host_code = ?  and rule_status=1", host_code).Find(&ruleconfig)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeRule,
		Content:  ruleconfig,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// BatchDelRuleApi 批量删除规则
func (w *WafRuleAPi) BatchDelRuleApi(c *gin.Context) {
	var req request.WafRuleBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafRuleService.GetHostCodesByCodes(req.Codes)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafRuleService.BatchDelApi(req)
		if err != nil {
			response.FailWithMessage("批量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			response.OkWithMessage(fmt.Sprintf("成功删除 %d 条记录", len(req.Codes)), c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAllRuleApi 删除指定网站的所有规则
func (w *WafRuleAPi) DelAllRuleApi(c *gin.Context) {
	var req request.WafRuleDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafRuleService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafRuleService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全部删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有规则", c)
			} else {
				response.OkWithMessage("成功删除所有规则", c)
			}
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// WafRulePreViewReq 规则格式预览
func (w *WafRuleAPi) FormatRuleApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafRulePreViewReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	var ruleTool = model.RuleTool{}
	ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
	if err != nil {
		response.FailWithMessage("规则解析错误", c)
		return
	}

	// 与新增/编辑保持一致，先校验网站选择
	if ruleInfo.RuleBase.RuleDomainCode == "请选择网站" && req.FormSource != "builder" {
		response.FailWithMessage("请选择网站", c)
		return
	}

	chsName := ruleInfo.RuleBase.RuleName
	ruleInfo.RuleBase.RuleName = strings.Replace(req.RuleCode, "-", "", -1)
	var ruleContent = ruleTool.GenRuleInfo(ruleInfo, chsName)

	// 手工模式走合法性校验
	if req.IsManualRule == 1 {
		ruleContent = ruleInfo.RuleContent
		err = ruleHelper.CheckRuleAvailable(ruleContent)
		if err != nil {
			response.FailWithMessage("规则校验失败", c)
			return
		}
	}

	// 返回格式化内容，供前端展示
	response.OkWithDetailed(gin.H{
		"rule_content": ruleContent,
	}, "获取成功", c)
}

// ModifyRuleStatusApi 修改WAF规则状态
// @Summary      修改WAF规则状态
// @Description  启用或禁用WAF防护规则
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleStatusReq  true  "状态参数"
// @Success      200   {object}  response.Response  "状态更新成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/rulestatus [get]
func (w *WafRuleAPi) ModifyRuleStatusApi(c *gin.Context) {
	var req request.WafRuleStatusReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafRuleService.ModifyRuleStatusApi(req)
		if err != nil {
			response.FailWithMessage("更新状态发生错误", c)
		} else {
			wafRule := wafRuleService.GetDetailByCodeApi(req.CODE)
			//通知引擎重新加载某个网站的规则信息
			w.NotifyWaf(wafRule.HostCode)
			response.OkWithMessage("状态更新成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// TestRuleApi 测试规则是否匹配模拟请求
// 处理逻辑与 wafengine.go ServeHTTP 中的 WebLog 构建保持一致
func (w *WafRuleAPi) TestRuleApi(c *gin.Context) {
	var req request.WafRuleTestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}

	// 1. 生成规则内容（与 AddApi/ModifyRuleApi 逻辑一致）
	var ruleContent string
	if req.IsManualRule == 1 {
		ruleContent = req.RuleContent
	} else {
		var ruleTool = model.RuleTool{}
		ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
		if err != nil {
			response.FailWithMessage("规则解析错误", c)
			return
		}
		chsName := ruleInfo.RuleBase.RuleName
		ruleInfo.RuleBase.RuleName = strings.Replace(req.RuleCode, "-", "", -1)
		ruleContent = ruleTool.GenRuleInfo(ruleInfo, chsName)
	}

	// 2. 初始化规则引擎并加载规则
	ruleHelper := &utils.RuleHelper{}
	ruleHelper.InitRuleEngine()
	err := ruleHelper.LoadRuleString(ruleContent)
	if err != nil {
		response.FailWithMessage("规则加载失败: "+err.Error(), c)
		return
	}

	// 3. 通过IP解析地理位置（与 wafengine.go 第353行一致）
	region := utils.GetCountry(req.TestSrcIP)
	// region 返回格式: [国家, ISP, 省份, 城市, ...]
	country := ""
	province := ""
	city := ""
	if len(region) > 0 {
		country = region[0]
	}
	if len(region) > 2 {
		province = region[2]
	}
	if len(region) > 3 {
		city = region[3]
	}

	// 4. URL解码处理（与 wafengine.go 第358行一致）
	decodedRawQuery := ""
	decodedURL := req.TestURL
	if strings.Contains(req.TestURL, "?") {
		parts := strings.SplitN(req.TestURL, "?", 2)
		if len(parts) == 2 {
			decodedRawQuery = wafhttpcore.WafHttpCoreUrlEncode(parts[1], 10)
			decodedURL = parts[0] + "?" + decodedRawQuery
		}
	}

	// 5. 构建 WebLog（字段与 wafengine.go 第360-395行保持一致）
	weblog := &innerbean.WebLog{
		SRC_IP:     req.TestSrcIP,
		HOST:       req.TestHost,
		URL:        decodedURL,
		RawQuery:   decodedRawQuery,
		METHOD:     req.TestMethod,
		USER_AGENT: req.TestUserAgent,
		REFERER:    req.TestReferer,
		HEADER:     req.TestHeader,
		COOKIES:    req.TestCookies,
		BODY:       req.TestBody,
		COUNTRY:    country,
		PROVINCE:   province,
		CITY:       city,
	}

	// 6. 执行规则匹配
	ruleMatches, err := ruleHelper.Match("MF", weblog)
	if err != nil {
		response.FailWithMessage("规则匹配失败: "+err.Error(), c)
		return
	}

	// 7. 构建响应
	var matchedRules []string
	for _, r := range ruleMatches {
		matchedRules = append(matchedRules, r.RuleDescription)
	}

	response.OkWithDetailed(gin.H{
		"is_match":        len(ruleMatches) > 0,
		"matched_rules":   matchedRules,
		"parsed_country":  country,
		"parsed_province": province,
		"parsed_city":     city,
	}, "测试完成", c)
}
