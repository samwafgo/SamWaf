package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// parseIPFailureThreshold 从规则文本中解析IP失败阈值信息
// 解析类似 "MF.GetIPFailureCount(5) > 10" 的模式
// 返回: minutes, count, 是否找到
func parseIPFailureThreshold(ruleText string) (int64, int64, bool) {
	// 匹配 GetIPFailureCount(数字) > 数字 或 GetIPFailureCount(数字) >= 数字 的模式
	re := regexp.MustCompile(`GetIPFailureCount\s*\(\s*(\d+)\s*\)\s*[>=]+\s*(\d+)`)
	matches := re.FindStringSubmatch(ruleText)
	if len(matches) >= 3 {
		minutes, err1 := strconv.ParseInt(matches[1], 10, 64)
		count, err2 := strconv.ParseInt(matches[2], 10, 64)
		if err1 == nil && err2 == nil {
			return minutes, count, true
		}
	}
	return 0, 0, false
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
	if hostTarget.Rule != nil {
		if hostTarget.Rule.KnowledgeBase != nil {
			ruleMatchs, err := hostTarget.Rule.Match("MF", weblogbean)
			if err == nil {
				if len(ruleMatchs) > 0 {
					rulestr := ""
					for _, v := range ruleMatchs {
						rulestr = rulestr + v.RuleDescription + ","

						minutes, count, found := parseIPFailureThreshold(v.GrlText)
						if found {
							// 记录阈值信息
							weblogbean.RecordIPFailureThreshold(minutes, count)
						}

					}
					weblogbean.RISK_LEVEL = 1

					result.IsBlock = true
					result.Title = rulestr
					result.Content = "您的访问被阻止触发规则"
					return result
				}
			} else {
				zlog.Debug("规则 ", err)
			}
		}
	}
	//规则判断 （全局网站）
	if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Host.GUARD_STATUS == 1 && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Rule != nil {
		if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Rule.KnowledgeBase != nil {
			ruleMatchs, err := waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Rule.Match("MF", weblogbean)
			if err == nil {
				if len(ruleMatchs) > 0 {
					rulestr := ""
					for _, v := range ruleMatchs {
						rulestr = rulestr + v.RuleDescription + ","
					}
					// 尝试从规则数据中解析阈值信息
					// 遍历规则数据，查找包含 GetIPFailureCount 的规则
					for _, ruleData := range waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].RuleData {
						if ruleData.RuleContent != "" {
							minutes, count, found := parseIPFailureThreshold(ruleData.RuleContent)
							if found {
								// 记录阈值信息
								weblogbean.RecordIPFailureThreshold(minutes, count)
								break // 找到第一个匹配的规则即可
							}
						}
					}
					weblogbean.RISK_LEVEL = 1

					result.IsBlock = true
					result.Title = "【全局】" + rulestr
					result.Content = "您的访问被阻止触发规则"
					return result
				}
			} else {
				zlog.Debug("规则 ", err)
			}
		}
	}
	return result
}
