package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"time"
)

/*
*
检测cc
*/
func (waf *WafEngine) CheckCC(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	globalHostSafe := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]

	// 紧急模式排在所有 CC 规则之前：它是站点级总闸，「先挑战再说」，
	// 不看阈值也不看规则命中。这里只落标记不返回拦截，挑战由后面的验证码闸门发起。
	if waf.isEmergencyOn(hostTarget, globalHostSafe) {
		waf.applyEmergencyCaptcha(r, weblogbean, hostTarget)
	}

	// 多规则优先：配置了多规则的站点走规则集，未配置的回退到旧的单条配置
	if res, handled := waf.checkCCByRules(r, weblogbean, hostTarget, globalHostSafe); handled {
		return res
	}

	// 根据IP模式选择使用的IP（从 Host 级别读取）
	clientIP := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)
	// cc 防护 (局部检测)
	if hostTarget.PluginIpRateLimiter != nil {
		isCheckCC := false
		if hostTarget.AntiCCBean.IsEnableRule {
			if hostTarget.PluginIpRateLimiter.Rule != nil {
				if hostTarget.PluginIpRateLimiter.Rule.KnowledgeBase != nil {
					ruleMatchs, err := hostTarget.PluginIpRateLimiter.Rule.Match("MF", weblogbean)
					if err == nil {
						if len(ruleMatchs) > 0 {
							isCheckCC = true
							zlog.Debug("CheckCC ruleMatchs: %v", ruleMatchs)
						}
					}
				}
			}
		} else {
			isCheckCC = true
		}
		// isCheckCC 只决定「本请求要不要纳入局部CC计数」。
		// 前置规则没命中时仍要继续走全局CC：局部规则的作用范围是本站点，不该顺带把全局防护也一起关掉。
		if isCheckCC {
			if !hostTarget.PluginIpRateLimiter.Allow(clientIP) {
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = "【局部】触发IP频次访问限制"
				result.Content = "您的访问被阻止超量了"
				banCC(hostTarget, hostTarget.Host.Code, clientIP, hostTarget.AntiCCBean.LockIPMinutes)
				return result
			}
			// 局部CC已检测且未封禁，若配置了跳过全局CC则直接返回
			if hostTarget.AntiCCBean.SkipGlobalCC {
				return result
			}
		}
	}

	// cc 防护 （全局检测）
	//注意：全局网站可能还没登记进路由快照（未初始化/正在重载），必须判空，否则解引用 panic
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	if globalHost != nil && globalHost.Host.GUARD_STATUS == 1 && globalHost.PluginIpRateLimiter != nil {
		// 全局CC同样按被访问站点的IP模式取客户端标识：IPMode 描述的是该站点部署在什么后面，
		// 属于部署事实；全局网站不承载流量，它的这个值取不到实际意义。
		// 两者不一致时，同一个请求会在站点规则与全局规则里按两个不同的 IP 计数。
		globalClientIP := clientIP
		if !globalHost.PluginIpRateLimiter.Allow(globalClientIP) {
			weblogbean.RISK_LEVEL = 1
			result.IsBlock = true
			result.Title = "【全局】触发IP频次访问限制"
			result.Content = "您的访问被阻止超量了"
			banCC(hostTarget, globalHost.Host.Code, globalClientIP, globalHost.AntiCCBean.LockIPMinutes)
			return result
		}
	}
	return result
}

// banCC 把客户端写入 CC 封禁期。
//
// 「仅记录模式」下不落封禁：该模式的语义是只记录不阻断，而封禁一旦写入，
// 后续请求会在封禁拦截点被挡下，两者必须保持一致。
//
// 作用域固定为 global（一处触发、全部站点生效），与既有行为一致。
// 多规则改造后改为按规则配置的 BanScope 决定，新建规则默认只封本站点。
func banCC(hostTarget *wafenginmodel.HostSafe, hostCode, clientIP string, lockMinutes int) {
	banCCWithScope(hostTarget, model.CCBanScopeGlobal, hostCode, clientIP, lockMinutes*60)
}

// banCCWithScope 按指定作用域与时长写入封禁期。
//
// 「仅记录模式」下不落封禁：该模式的语义是只记录不阻断，而封禁一旦写入，
// 后续请求会在封禁拦截点被挡下，两者必须保持一致。
func banCCWithScope(hostTarget *wafenginmodel.HostSafe, scope, hostCode, clientIP string, seconds int) {
	if hostTarget != nil && hostTarget.Host.LogOnlyMode == 1 {
		zlog.Debug("CC仅记录模式，跳过封禁写入", clientIP)
		return
	}
	if seconds <= 0 || clientIP == "" || global.GCACHE_WAFCACHE == nil {
		return
	}
	cacheKey := model.BuildCCBanKey(scope, hostCode, clientIP)
	// 值沿用「分钟数」，封禁列表与提醒都按这个口径展示
	global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, seconds/60, time.Duration(seconds)*time.Second)
}
