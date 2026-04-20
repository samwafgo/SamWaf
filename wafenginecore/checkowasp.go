package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafowasp"
	"net/http"
	"net/url"
	"strconv"
)

// CheckOwasp OWASP CRS 检测。
//
// 注意：本函数假设调用方已经判断过 OWASP 是否启用（参考 wafengine.go 调用处），
// 内部不再解析 DEFENSE_JSON，避免热路径上重复 JSON 反序列化。
func (waf *WafEngine) CheckOwasp(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}

	// 优先取 manager 当前实例（支持热重载原子切换），回退到旧的 GWAF_OWASP 句柄
	var inst *wafowasp.WafOWASP
	if global.GWAF_OWASP_MANAGER != nil {
		inst = global.GWAF_OWASP_MANAGER.Current()
	}
	if inst == nil {
		inst = global.GWAF_OWASP
	}
	if inst == nil {
		// 没有可用实例：热重载失败或初始化未完成。记一条 warn，避免静默放行
		zlog.Warn("CheckOwasp", "OWASP WAF 实例未就绪，本次检测被跳过")
		return result
	}
	if !inst.IsActive {
		// manager 被 SetActive(false) 或显式关闭后，ProcessRequest 自身也会短路，这里提前记录便于诊断
		if wafowasp.IsDebugEnabled() {
			zlog.Debug("CheckOwasp", "OWASP 实例 IsActive=false，本次检测被跳过")
		}
		return result
	}

	isInteeruption, interruption, err := inst.ProcessRequest(r, weblogbean)
	if err != nil {
		// Coraza 处理异常：记录错误但不影响请求（fail-open），避免把引擎故障误判为攻击
		zlog.Error("CheckOwasp ProcessRequest err", map[string]interface{}{
			"error":  err.Error(),
			"method": r.Method,
			"uri":    r.URL.RequestURI(),
		})
		return result
	}

	// 防御：理论上 Coraza 保证 isInterrupted ↔ interruption!=nil 一致，
	// 但出于健壮性考虑，只要任一命中即视为拦截
	if isInteeruption || interruption != nil {
		ruleID := 0
		if interruption != nil {
			ruleID = interruption.RuleID
		}
		result.IsBlock = true
		result.Title = "OWASP:" + strconv.Itoa(ruleID)
		result.Content = "访问不合法"
		weblogbean.RISK_LEVEL = 2

		zlog.Info("CheckOwasp blocked", map[string]interface{}{
			"rule_id": ruleID,
			"method":  r.Method,
			"uri":     r.URL.RequestURI(),
			"src_ip":  weblogbean.SRC_IP,
			"host":    r.Host,
		})
		return result
	}

	// 未拦截：debug 模式下记录一下执行痕迹，方便核对是否真的进入 OWASP 检测
	if wafowasp.IsDebugEnabled() {
		zlog.Debug("CheckOwasp pass", map[string]interface{}{
			"method": r.Method,
			"uri":    r.URL.RequestURI(),
			"host":   r.Host,
		})
	}
	return result
}
