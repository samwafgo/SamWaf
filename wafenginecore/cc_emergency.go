package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"time"
)

// emergencyGraceSeconds 紧急模式下通过一次挑战后的免挑战时长。
//
// 取 30 分钟：紧急模式是「被打的时候先把闸门放下来」，不是常态防护。
// 太短会让真实访客在一次会话里被反复拦，太长又等于开了个长期后门——
// 攻击持续期间，攻击者拿到的凭证也只在这段时间内有效。
const emergencyGraceSeconds = 1800

// isEmergencyOn 本次请求是否处于紧急模式。
//
// 站点自己开了，或者全局网站开了，都算。全局那一档是给「一次被打一片」准备的：
// 逐个站点去点开关，正是最不该在这种时候做的事。
func (waf *WafEngine) isEmergencyOn(hostTarget, globalHost *wafenginmodel.HostSafe) bool {
	now := time.Now().Unix()
	if hostTarget != nil && hostTarget.Host.IsEmergencyActive(now) {
		return true
	}
	return globalHost != nil && globalHost.Host.IsEmergencyActive(now)
}

// applyEmergencyCaptcha 紧急模式下把本次请求标记为「需完成人机验证」。
//
// 与 CC 规则的人机验证动作走同一套闸门与凭证，因此：
//   - 「永不挑战的路径」对它同样生效——App/API 客户端跑不了 JS 挑战，出口在那里；
//   - 一次页面加载的几十个子请求只会被挑战一次；
//   - 这里不返回拦截结果，挑战由检测链后面的验证码闸门统一发起。
//
// 它不看阈值、不看规则命中，是站点级总闸；也不改动任何一条 CC 规则——
// 把规则的动作改掉再改回来，中间出任何岔子都恢复不回原样，
// 而这个开关多半是在被打的时候按下的。
func (waf *WafEngine) applyEmergencyCaptcha(r *http.Request, weblogbean *innerbean.WebLog, hostTarget *wafenginmodel.HostSafe) {
	if hostTarget == nil || weblogbean == nil {
		return
	}
	hostCode := hostTarget.Host.Code
	ip := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)
	if ip == "" {
		// 与 CC 规则动作同一套兜底：按 IPMode 取不到时退回来源 IP。
		// 取不到就直接不管，等于紧急模式对这批请求静默失效。
		ip = weblogbean.SRC_IP
	}
	if ip == "" {
		return
	}
	if isCCCaptchaInGrace(hostCode, ip) {
		weblogbean.RULE = "CC紧急模式-免挑战期内放行"
		return
	}
	// 与 CC 规则动作同一处理：上一轮要求过验证、这次带着有效凭证来了，就地换成免挑战期。
	// 少了这一步，下面的作废会把访客刚拿到的凭证删掉，形成「怎么点都点不完」的挑战循环。
	if IsCCCaptchaRequired(hostCode, ip) && hasCaptchaPass(r, ip) {
		GrantCCCaptchaGrace(hostCode, ip)
		weblogbean.RULE = "CC紧急模式-本轮已通过"
		return
	}
	weblogbean.RULE = "CC紧急模式"
	revokeCaptchaPass(r, ip)
	RequireCaptcha(hostCode, ip, emergencyGraceSeconds, "紧急模式")
}
