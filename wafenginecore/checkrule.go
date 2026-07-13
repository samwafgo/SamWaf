package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/hyperjumptech/grule-rule-engine/ast"
)

// parseIPFailureThreshold 从规则文本中解析IP失败阈值信息
// 解析类似 "MF.GetIPFailureCount(5) > 10" 的模式
// 返回: minutes, count, 是否找到
func parseIPFailureThreshold(ruleText string) (int64, int64, bool) {
	// 匹配 GetIPFailureCount(数字) > 数字 或 GetIPFailureCount(数字) >= 数字 的模式
	// 在骨架上匹配，避免把字符串字面量里的内容当成真的条件
	re := regexp.MustCompile(`GetIPFailureCount\s*\(\s*(\d+)\s*\)\s*[>=]+\s*(\d+)`)
	matches := re.FindStringSubmatch(utils.BuildGrlSkeleton(ruleText))
	if len(matches) >= 3 {
		minutes, err1 := strconv.ParseInt(matches[1], 10, 64)
		count, err2 := strconv.ParseInt(matches[2], 10, 64)
		if err1 == nil && err2 == nil {
			return minutes, count, true
		}
	}
	return 0, 0, false
}

// pickRuleAction 从命中的规则里挑出最终生效的动作
// grule 的 FetchMatchingRules 已按 salience 降序返回，所以优先级最高的就是第一条。
// 但同 salience 的规则之间顺序是不确定的（来自 map 遍历），所以在最高优先级这一档里
// 按 拦截 > 放行 > 仅记录 取，保证结果稳定且偏安全。
// 多条放行规则的跳过模块取并集。
func pickRuleAction(ruleHelper *utils.RuleHelper, ruleMatchs []*ast.RuleEntry) utils.RuleActionInfo {
	if len(ruleMatchs) == 0 {
		return utils.RuleActionInfo{Action: utils.RuleActionDeny}
	}

	topSalience := ruleMatchs[0].Salience
	final := utils.RuleActionInfo{Action: ""}
	skipSet := make(map[string]bool)

	rank := map[string]int{
		utils.RuleActionDeny:  3,
		utils.RuleActionAllow: 2,
		utils.RuleActionLog:   1,
	}

	for _, v := range ruleMatchs {
		if v.Salience != topSalience {
			break
		}
		info := ruleHelper.GetRuleAction(v.RuleName)
		if info.Action == utils.RuleActionAllow {
			for _, m := range info.SkipModules {
				skipSet[m] = true
			}
		}
		if final.Action == "" || rank[info.Action] > rank[final.Action] {
			final.Action = info.Action
		}
	}
	if final.Action == "" {
		final.Action = utils.RuleActionDeny
	}
	if final.Action == utils.RuleActionAllow {
		for m := range skipSet {
			final.SkipModules = append(final.SkipModules, m)
		}
	}
	return final
}

// ruleMatchResult 单侧（局部/全局）规则的命中结果
type ruleMatchResult struct {
	Matched bool
	Action  utils.RuleActionInfo
	Title   string
}

// matchRules 执行一组规则并解析出动作
func matchRules(ruleHelper *utils.RuleHelper, weblogbean *innerbean.WebLog, titlePrefix string) ruleMatchResult {
	out := ruleMatchResult{}
	if ruleHelper == nil || ruleHelper.KnowledgeBase == nil {
		return out
	}
	ruleMatchs, err := ruleHelper.Match("MF", weblogbean)
	if err != nil {
		zlog.Debug("规则 ", err)
		return out
	}
	if len(ruleMatchs) == 0 {
		return out
	}

	rulestr := ""
	for _, v := range ruleMatchs {
		rulestr = rulestr + v.RuleDescription + ","

		minutes, count, found := parseIPFailureThreshold(v.GrlText)
		if found {
			// 记录阈值信息
			weblogbean.RecordIPFailureThreshold(minutes, count)
		}
	}

	out.Matched = true
	out.Action = pickRuleAction(ruleHelper, ruleMatchs)
	out.Title = titlePrefix + rulestr
	return out
}

/*
*
检测rule
*/
func (waf *WafEngine) CheckRule(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}

	logTitle := ""
	allowTitle := ""
	skipSet := make(map[string]bool)

	//规则判断 （局部）
	if hostTarget.Rule != nil {
		localResult := matchRules(hostTarget.Rule, weblogbean, "")
		if localResult.Matched {
			switch localResult.Action.Action {
			case utils.RuleActionDeny:
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = localResult.Title
				result.Content = "您的访问被阻止触发规则"
				return result
			case utils.RuleActionAllow:
				allowTitle = localResult.Title
				for _, m := range localResult.Action.SkipModules {
					skipSet[m] = true
				}
				//放行且跳过后续所有检测，全局规则也不用再看了
				if localResult.Action.SkipAll() {
					result.JumpGuardResult = true
					result.IsRuleAllow = true
					result.SkipModules = []string{utils.RuleSkipAll}
					result.Title = allowTitle
					return result
				}
			case utils.RuleActionLog:
				weblogbean.RISK_LEVEL = 1
				logTitle = localResult.Title
			}
		}
	}

	//规则判断 （全局网站）
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	if globalHost != nil && globalHost.Host.GUARD_STATUS == 1 && globalHost.Rule != nil {
		globalResult := matchRules(globalHost.Rule, weblogbean, "【全局】")
		if globalResult.Matched {
			switch globalResult.Action.Action {
			case utils.RuleActionDeny:
				//全局拦截优先级最高，可以覆盖局部的放行/仅记录
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = globalResult.Title
				result.Content = "您的访问被阻止触发规则"
				return result
			case utils.RuleActionAllow:
				if allowTitle == "" {
					allowTitle = globalResult.Title
				} else {
					allowTitle = allowTitle + globalResult.Title
				}
				for _, m := range globalResult.Action.SkipModules {
					skipSet[m] = true
				}
				if globalResult.Action.SkipAll() {
					result.JumpGuardResult = true
					result.IsRuleAllow = true
					result.SkipModules = []string{utils.RuleSkipAll}
					result.Title = allowTitle
					return result
				}
			case utils.RuleActionLog:
				weblogbean.RISK_LEVEL = 1
				if logTitle == "" {
					logTitle = globalResult.Title
				} else {
					logTitle = logTitle + globalResult.Title
				}
			}
		}
	}

	//放行优先于仅记录
	if allowTitle != "" {
		result.IsRuleAllow = true
		result.Title = allowTitle
		for m := range skipSet {
			result.SkipModules = append(result.SkipModules, m)
		}
		return result
	}
	if logTitle != "" {
		result.IsLogOnly = true
		result.Title = logTitle
		return result
	}
	return result
}
