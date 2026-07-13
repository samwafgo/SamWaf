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

// 手工规则文本长度上限，防止超大规则拖垮编译
const maxManualRuleContentLen = 64 * 1024

// checkManualRuleContent 手工模式规则的安全校验
// 除了让 grule 真正编译一遍，还要保证"保存时看到的动作"和"运行时执行的动作"是同一个：
//   - 一段规则内容里只能有一条规则（防止在一条规则后面再塞一条放行规则）
//   - 规则名必须和规则码对得上（防止覆盖到别的规则）
//   - 动作标记只能有一个，Allow 的参数必须是已知的检测模块
func checkManualRuleContent(ruleHelper *utils.RuleHelper, ruleContent string, expectRuleCode string) error {
	if len(ruleContent) > maxManualRuleContentLen {
		return errors.New("规则内容过长")
	}
	//语法校验
	if err := ruleHelper.CheckRuleAvailable(ruleContent); err != nil {
		return errors.New("规则校验失败")
	}
	//一条规则内容只允许定义一条规则
	names := utils.ExtractRuleNamesFromText(ruleContent)
	if len(names) == 0 {
		return errors.New("未找到规则定义")
	}
	if len(names) > 1 {
		return errors.New("一条规则内容里只能定义一条规则")
	}
	//规则名必须与规则码一致
	if expectRuleCode != "" {
		expectName := "R" + strings.Replace(expectRuleCode, "-", "", -1)
		if !strings.EqualFold(names[0], expectName) {
			return fmt.Errorf("规则标识与规则码不一致，应为 %s", expectName)
		}
	}
	//动作校验
	if _, err := utils.ExtractRuleActionForCheck(ruleContent); err != nil {
		return err
	}
	return nil
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

		var ruleContent string
		if req.IsManualRule == 1 {
			ruleContent = ruleInfo.RuleContent
			//检查规则是否合法
			if err = checkManualRuleContent(ruleHelper, ruleContent, ruleCode); err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		} else {
			ruleContent, err = ruleTool.GenRuleInfo(ruleInfo, chsName)
			if err != nil {
				response.FailWithMessage(err.Error(), c)
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
		var ruleContent string
		if req.IsManualRule == 1 {
			ruleContent = ruleInfo.RuleContent
			//检查规则是否合法
			if err = checkManualRuleContent(ruleHelper, ruleContent, rule.RuleCode); err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		} else {
			ruleContent, err = ruleTool.GenRuleInfo(ruleInfo, ruleName)
			if err != nil {
				response.FailWithMessage(err.Error(), c)
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

	var ruleContent string
	if req.IsManualRule == 1 {
		// 手工模式走合法性校验
		ruleContent = ruleInfo.RuleContent
		if err = checkManualRuleContent(ruleHelper, ruleContent, req.RuleCode); err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
	} else {
		ruleContent, err = ruleTool.GenRuleInfo(ruleInfo, chsName)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
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
		ruleContent, err = ruleTool.GenRuleInfo(ruleInfo, chsName)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
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
	var matchedRuleDetails []gin.H
	for _, r := range ruleMatches {
		matchedRules = append(matchedRules, r.RuleDescription)

		//把每条命中规则真正生效的动作返回给前端。规则内容里可能混着用户/攻击者可控的文本，
		//这里展示的是引擎实际认定的动作，保存前点一下测试就能看出规则有没有被写歪。
		action := ruleHelper.GetRuleAction(r.RuleName)
		matchedRuleDetails = append(matchedRuleDetails, gin.H{
			"rule_name":        r.RuleName,
			"rule_description": r.RuleDescription,
			"salience":         r.Salience,
			"action":           action.Action,
			"skip_modules":     action.SkipModules,
		})
	}

	//多条规则命中时，最终生效的动作
	effectiveAction := ""
	var effectiveSkipModules []string
	if len(ruleMatches) > 0 {
		info := ruleHelper.GetRuleAction(ruleMatches[0].RuleName)
		effectiveAction = info.Action
		effectiveSkipModules = info.SkipModules
	}

	response.OkWithDetailed(gin.H{
		"is_match":               len(ruleMatches) > 0,
		"matched_rules":          matchedRules,
		"matched_rule_details":   matchedRuleDetails,
		"effective_action":       effectiveAction,
		"effective_skip_modules": effectiveSkipModules,
		"parsed_country":         country,
		"parsed_province":        province,
		"parsed_city":            city,
	}, "测试完成", c)
}

// AiGenRuleApi 用后台配置的 AI 生成一条自定义规则
// 生成后在服务端做校验（单条规则 + 语法编译 + 动作合法），不通过就把错误喂回模型重试，
// 返回时尽量保证规则可直接编译落地，且不会被注入成放行规则。
// RuleAiPromptApi 返回"复制给AI"的提示词（唯一来源在后端 api/waf_gpt.go，前端直接取用）
func (w *WafRuleAPi) RuleAiPromptApi(c *gin.Context) {
	response.OkWithDetailed(GetRuleAiPrompt(c.Query("lang")), "获取成功", c)
}

func (w *WafRuleAPi) AiGenRuleApi(c *gin.Context) {
	var req request.WafGptRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}
	intent := strings.TrimSpace(req.Intent)
	if intent == "" {
		response.FailWithMessage("请填写你想要的防护需求", c)
		return
	}
	if !IsGPTConfigured() {
		response.FailWithMessage("尚未配置AI密钥，请到【系统配置】填写 gpt_url / gpt_token / gpt_model", c)
		return
	}

	sysPrompt := ruleGenSystemPromptZH
	if strings.HasPrefix(strings.ToLower(req.Lang), "en") {
		sysPrompt = ruleGenSystemPromptEN
	}
	messages := []model.GptMessage{
		{Role: "system", Content: sysPrompt},
		{Role: "user", Content: intent},
	}

	ruleHelper := &utils.RuleHelper{}
	const maxAttempts = 3
	var ruleContent string
	var lastErr string
	valid := false
	attempts := 0

	for attempts < maxAttempts {
		attempts++
		out, err := callGPTOnce(messages)
		if err != nil {
			response.FailWithMessage("AI 请求失败: "+err.Error(), c)
			return
		}
		// 归一化（补动作分号等），再校验
		ruleContent = normalizeGeneratedRule(out)

		// 服务端校验闭环
		if n := utils.CountRuleBlocks(ruleContent); n != 1 {
			lastErr = "必须且只能生成一条规则"
		} else if err := ruleHelper.CheckRuleAvailable(ruleContent); err != nil {
			lastErr = "规则语法有误: " + err.Error()
		} else if _, err := utils.ExtractRuleActionForCheck(ruleContent); err != nil {
			lastErr = err.Error()
		} else {
			valid = true
			lastErr = ""
			break
		}

		// 修复重试：把上次输出和具体错误喂回模型，并强调常见坑
		messages = append(messages,
			model.GptMessage{Role: "assistant", Content: out},
			model.GptMessage{Role: "user", Content: "上面的规则有问题：" + lastErr + "。请修正后只输出规则文本，不要解释。注意：then 里的动作必须以分号结尾(如 RF.Deny(); )，只能有一条规则。"},
		)
	}

	action := utils.RuleActionDeny
	if valid {
		if info, err := utils.ExtractRuleActionForCheck(ruleContent); err == nil && info.Action != "" {
			action = info.Action
		}
	}

	response.OkWithDetailed(gin.H{
		"rule_content": ruleContent, // 生成的规则文本
		"valid":        valid,       // 是否通过服务端校验
		"action":       action,      // 生效动作
		"error":        lastErr,     // 未通过时的原因
		"attempts":     attempts,    // 实际尝试次数
	}, "生成完成", c)
}
