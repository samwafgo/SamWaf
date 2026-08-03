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
	"sort"
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
	// TopSalience 本侧命中规则里的最高优先级，用于和另一侧仲裁
	TopSalience int
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
	// grule 的 FetchMatchingRules 已按 salience 降序返回，第一条即最高优先级
	out.TopSalience = ruleMatchs[0].Salience
	return out
}

// arbitrate 在站点规则和全局规则的命中结果之间裁决最终动作
//
// salience 只在单个 KnowledgeBase 内排序，而站点和全局是两个独立的规则引擎，
// 所以跨作用域的优先级必须在这里显式仲裁，否则用户在界面上填的"优先级"跨作用域就是空的。
//
//	1. 只有一侧命中 → 用那一侧
//	2. 两侧都命中 → salience 高的一侧胜出
//	3. salience 相同 → 按 拦截 > 放行 > 仅记录 取，保证偏安全，也和历史行为一致
//	   （老配置站点和全局默认都是 salience 10，此时全局拦截依旧压过站点放行）
//
// 两侧同为放行且同优先级时，跳过模块取并集、Title 拼接。
func arbitrate(local, globalR ruleMatchResult) ruleMatchResult {
	if !local.Matched {
		return globalR
	}
	if !globalR.Matched {
		return local
	}

	if local.TopSalience > globalR.TopSalience {
		return local
	}
	if globalR.TopSalience > local.TopSalience {
		return globalR
	}

	// 同优先级：按动作强弱兜底
	rank := map[string]int{
		utils.RuleActionDeny:  3,
		utils.RuleActionAllow: 2,
		utils.RuleActionLog:   1,
	}
	if rank[local.Action.Action] > rank[globalR.Action.Action] {
		return local
	}
	if rank[globalR.Action.Action] > rank[local.Action.Action] {
		return globalR
	}

	// 动作也相同：合并两侧信息
	merged := ruleMatchResult{
		Matched:     true,
		Action:      utils.RuleActionInfo{Action: local.Action.Action},
		Title:       local.Title + globalR.Title,
		TopSalience: local.TopSalience,
	}
	if merged.Action.Action == utils.RuleActionAllow {
		skipSet := make(map[string]bool)
		for _, m := range local.Action.SkipModules {
			skipSet[m] = true
		}
		for _, m := range globalR.Action.SkipModules {
			skipSet[m] = true
		}
		for m := range skipSet {
			merged.Action.SkipModules = append(merged.Action.SkipModules, m)
		}
		sort.Strings(merged.Action.SkipModules)
	}
	return merged
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

	//规则判断 （局部）
	localResult := ruleMatchResult{}
	if hostTarget.Rule != nil {
		localResult = matchRules(hostTarget.Rule, weblogbean, "")
	}

	//规则判断 （全局网站）
	//两侧都要跑完再仲裁：局部先命中就 return 的话，全局那条优先级更高的规则永远没机会生效
	globalResult := ruleMatchResult{}
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	if globalHost != nil && globalHost.Host.GUARD_STATUS == 1 && globalHost.Rule != nil {
		globalResult = matchRules(globalHost.Rule, weblogbean, "【全局】")
	}

	final := arbitrate(localResult, globalResult)
	if !final.Matched {
		return result
	}

	switch final.Action.Action {
	case utils.RuleActionDeny:
		weblogbean.RISK_LEVEL = 1
		result.IsBlock = true
		result.Title = final.Title
		result.Content = "您的访问被阻止触发规则"
	case utils.RuleActionAllow:
		result.IsRuleAllow = true
		result.Title = final.Title
		if final.Action.SkipAll() {
			//放行且跳过后续所有检测，直通后端
			result.JumpGuardResult = true
			result.SkipModules = []string{utils.RuleSkipAll}
		} else {
			result.SkipModules = final.Action.SkipModules
		}
	case utils.RuleActionLog:
		weblogbean.RISK_LEVEL = 1
		result.IsLogOnly = true
		result.Title = final.Title
	}
	return result
}
