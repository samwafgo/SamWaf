package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
)

/*
*
AI智能检测

补现有规则引擎（正则 / libinjection / OWASP CRS）的盲区：变形绕过、混淆、未知 payload。
推理走纯 Go 内嵌 GBDT（wafai.Detector + dmitryikh/leaves），失败安全：
模型未加载/打分异常一律放行，绝不影响业务转发。

进入条件（在 wafengine 检测链中由调用方判断）：
  - 全局开关 global.GCONFIG_AI_ENABLE == 1
  - 站点开关 hostDefense.DEFENSE_AI == 1

工作模式 global.GCONFIG_AI_MODE：
  - "observe"：仅记录命中（达到观察阈值即在日志标注 AI 分数），不拦截
  - "block"  ：达到模型建议拦截阈值则拦截，介于观察/拦截阈值之间则仅记录
*/
func (waf *WafEngine) CheckAI(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}

	detector := global.GWAF_AI_DETECTOR
	if detector == nil || !detector.IsLoaded() {
		return result
	}

	// 取请求关键字段做特征：path 与 query 分离，body 用解密后的明文
	path := ""
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	body := weblogbean.BODY
	if body == "" {
		body = weblogbean.POST_FORM
	}

	pred := detector.PredictRequest(weblogbean.METHOD, path, weblogbean.RawQuery, body, weblogbean.USER_AGENT)
	if !pred.Loaded {
		// 失败安全：未命中
		return result
	}

	// 低于观察阈值：忽略（不记录分数，避免污染正常日志）
	if pred.Score < pred.ObserveThreshold {
		return result
	}

	// RULE 用稳定的类别标签（不含分数），便于"按规则汇总"统计；分数单独存 AI_SCORE 列
	title := "AI检测:" + pred.Category
	weblogbean.RISK_LEVEL = 2
	weblogbean.AI_SCORE = pred.Score

	// block 模式且达到拦截阈值 -> 拦截（由 handleBlock 走 EchoErrorInfo 记录为"阻止"）
	if global.GCONFIG_AI_MODE == "block" && pred.Score >= pred.BlockThreshold {
		result.IsBlock = true
		result.Title = title
		result.Content = "请正确访问"
		return result
	}

	// 观察命中（observe 模式，或 block 模式下分数在[观察,拦截)之间）：
	// 标记为"仅记录"，让请求照常放行，但在访问日志里可按 log_only_mode 筛出、
	// 并通过 ai_score 列排序/查看——对标 AWS WAF Count / Cloudflare log 动作。
	weblogbean.RULE = title
	weblogbean.LogOnlyMode = 1
	return result
}
