package wafenginecore

import (
	"SamWaf/common/diagstat"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/cccounter"
	"SamWaf/wafenginecore/ccrule"
	"SamWaf/wafenginecore/ccstats"
	"net/http"
	"time"
)

// GCCCounter 是 CC 多规则的进程内计数器。
//
// 计数在每请求热路径上，默认必须是进程内实现：走网络的共享后端会把 WAF 自己变成瓶颈。
// 多节点需要共享阈值时另接后端，且要如实提示往返代价。
var GCCCounter = cccounter.New(0, 0)

func init() {
	// 把计量值挂进运行诊断：内存有天花板这条约束必须在运行期看得见，
	// 否则「被打时会不会撑爆」只能靠猜。
	diagstat.Register("cc_counter", GCCCounter.Stats)
	diagstat.Register("cc_hits", ccstats.Default.Stats)
}

// checkCCByRules 按多规则执行 CC 检测。
//
// 规则按优先级升序执行：不匹配就看下一条；匹配但没超阈值也看下一条；
// 超了阈值就执行动作——观察类记录后继续，其余动作立即结束检测。
// 返回 handled=false 表示本站点没有可用的多规则配置，调用方回退到旧的单条配置逻辑。
func (waf *WafEngine) checkCCByRules(
	r *http.Request,
	weblogbean *innerbean.WebLog,
	hostTarget *wafenginmodel.HostSafe,
	globalHost *wafenginmodel.HostSafe,
) (result detection.Result, handled bool) {

	rules := hostTarget.CCRules
	// 全局站点的规则排在本站点之后，形成「本站点规则 → 全局规则」的执行顺序
	var globalRules []*ccrule.CompiledRule
	if globalHost != nil && globalHost != hostTarget && globalHost.Host.GUARD_STATUS == 1 {
		globalRules = globalHost.CCRules
	}
	if len(rules) == 0 && len(globalRules) == 0 {
		return result, false
	}

	// 取 IP 一律按被访问站点的 IPMode，全局规则也一样：
	// IPMode 描述的是「这个站点部署在什么后面」，属于部署事实；全局网站不承载流量，
	// 它的这个值取不到实际意义。两套规则用同一个 IP，计数/封禁/验证码的身份才是一致的。
	clientIP := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)

	if res, done := waf.runCCRuleSet(r, weblogbean, hostTarget, rules, clientIP, hostTarget.Host.Code); done {
		return res, true
	}
	if len(globalRules) > 0 {
		if res, done := waf.runCCRuleSet(r, weblogbean, hostTarget, globalRules, clientIP, globalHost.Host.Code); done {
			return res, true
		}
	}
	return result, true
}

// runCCRuleSet 顺序执行一组规则。done=true 表示已产生终止性动作，无需再看后续规则。
func (waf *WafEngine) runCCRuleSet(
	r *http.Request,
	weblogbean *innerbean.WebLog,
	hostTarget *wafenginmodel.HostSafe,
	rules []*ccrule.CompiledRule,
	clientIP string,
	ruleHostCode string,
) (detection.Result, bool) {

	var result detection.Result
	for _, cr := range rules {
		if cr == nil || cr.Rule.IsEnable != 1 {
			continue
		}
		// 引用响应期字段的规则要等响应回来才能判定，请求期跳过
		if cr.NeedsResponsePhase() {
			continue
		}
		if !cr.InCountScope(r) || !cr.Matches(r, weblogbean) {
			continue
		}
		// 已验证爬虫豁免：不计数也不判定，直接看下一条规则。
		// 放在计数之前而不是动作之前——计进去再豁免，阈值仍会被爬虫的流量顶起来，
		// 后面的普通访客会因为一个已经放行的来源而被误伤。
		if ccBotExempt(cr, weblogbean) {
			continue
		}

		dimValue, fellBack := cr.DimValue(r, weblogbean, clientIP)
		if fellBack {
			zlog.Debug("CC规则统计维度取不到值，已回退按IP统计", cr.Rule.RuleName)
		}

		res := GCCCounter.Incr(cr.Rule.Id, dimValue, cr.Rule.WindowSec)
		if res.Degraded {
			// 维度基数失控（典型是拿可伪造字段当维度），降级为按 IP 统计后重试一次。
			// 归堆的键跟着换成 IP，看板上才不会把降级前后的量算到两个不同的来源上。
			dimValue = clientIP
			res = GCCCounter.Incr(cr.Rule.Id, dimValue, cr.Rule.WindowSec)
		}
		if res.Rejected {
			// 计数键总量到顶，本次放弃计数而不是继续吃内存
			continue
		}

		threshold := int64(cr.Rule.Threshold + cr.Rule.Burst)
		if threshold <= 0 || res.Count <= threshold {
			continue
		}

		// 记一次触发。只在超过阈值这一步记，不记「匹配」：
		// 匹配每个请求都会发生，为它加锁计数等于给正常流量上税。
		ccstats.Default.Record(cr.Rule.Id, cr.Rule.Action, dimValue)

		hit, stop := waf.applyCCAction(r, cr, weblogbean, hostTarget, clientIP, ruleHostCode)
		if stop {
			return hit, true
		}
		// 观察类动作：记录之后继续看后续规则
		result = hit
	}
	return result, false
}

// applyCCAction 执行规则动作。stop=true 表示应立即结束 CC 检测。
func (waf *WafEngine) applyCCAction(
	r *http.Request,
	cr *ccrule.CompiledRule,
	weblogbean *innerbean.WebLog,
	hostTarget *wafenginmodel.HostSafe,
	clientIP string,
	ruleHostCode string,
) (detection.Result, bool) {

	rule := cr.Rule
	// 日志里带上规则短码，管理员照着 CC 规则列表就能对上是哪条规则；
	// 短码只进后台日志，给访客看的页面上一律用每请求随机的访问识别码
	label := rule.RuleName
	if rule.RuleCode != "" {
		label = rule.RuleName + "[" + rule.RuleCode + "]"
	}
	title := "触发CC防护规则:" + label

	switch rule.Action {
	case model.CCActionObserve:
		// 只记录不阻断，且不中断后续规则——观察模式的意义就是把候选规则一起看完
		weblogbean.RULE = "CC观察:" + label
		zlog.Debug("CC规则命中(观察)", rule.RuleName, clientIP)
		return detection.Result{}, false

	case model.CCActionCaptcha:
		// 这里只落「需要验证」标记，不返回拦截结果。
		//
		// 验证码闸门在检测链的更后面（wafengine.go 的验证码检测），由它统一发起挑战、
		// 识别放行凭证。若在这里就判定拦截，请求会在闸门之前被结束掉：挑战页发不出去，
		// 已经通过验证的访客再次超过阈值时也会被当成普通拦截挡下。
		//
		// 标记用的 IP 必须与闸门取 IP 的口径一致（都按本站点的 IPMode 取），
		// 否则全局规则命中时写下的键闸门查不到。
		weblogbean.RISK_LEVEL = 1
		captchaIP := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)
		if captchaIP == "" {
			captchaIP = clientIP
		}
		// 免挑战期内不重复挑战：验证通过后计数窗口不会立刻清零，
		// 不给这段缓冲的话，通过验证的访客下一个请求就会被再次挑战，陷入死循环。
		//
		// 文案必须与「本次要求验证」区分开：两条路径都不阻断本次请求，
		// 日志上分不开的话，看到「人机验证」却没弹出挑战，只能理解成功能坏了。
		if isCCCaptchaInGrace(hostTarget.Host.Code, captchaIP) {
			weblogbean.RULE = "CC人机验证-免挑战期内放行:" + label
			return detection.Result{}, true
		}
		// 上一轮要求过验证，而访客这次带着有效凭证来了：这一轮挑战已经完成，就地换成免挑战期。
		//
		// 这一步不能留给后面的验证码闸门做。闸门发放免挑战期的条件是「访客带着有效凭证出现」，
		// 而 CC 检测跑在闸门之前，下面那行作废会把凭证删掉，闸门于是永远看不到它——
		// 结果是访客每完成一次挑战、下一个请求又被挑战，直到计数窗口自己漏空。
		if IsCCCaptchaRequired(hostTarget.Host.Code, captchaIP) && hasCaptchaPass(r, captchaIP) {
			GrantCCCaptchaGrace(hostTarget.Host.Code, captchaIP)
			weblogbean.RULE = "CC人机验证-本轮已通过:" + label
			return detection.Result{}, true
		}
		// 撤销当前持有的通行凭证。站点级凭证的有效期以小时计（默认 24 小时），
		// 沿用它意味着这个动作只是一次性关卡：过一次之后在凭证有效期内再怎么超量都不会被要求验证。
		weblogbean.RULE = "CC人机验证:" + label
		revokeCaptchaPass(r, captchaIP)
		RequireCaptcha(hostTarget.Host.Code, captchaIP, rule.ActionSeconds, "CC规则 "+label)
		return detection.Result{}, true

	case model.CCActionBan:
		weblogbean.RISK_LEVEL = 1
		scope := rule.BanScope
		if scope != model.CCBanScopeHost {
			scope = model.CCBanScopeGlobal
		}
		banCCWithScope(hostTarget, scope, ruleHostCode, clientIP, rule.ActionSeconds)
		return detection.Result{
			IsBlock: true,
			Title:   title,
			Content: "您的访问被阻止超量了",
		}, true

	default: // CCActionDeny
		weblogbean.RISK_LEVEL = 1
		return detection.Result{
			IsBlock: true,
			Title:   title,
			Content: "您的访问被阻止超量了",
		}, true
	}
}

// ccCaptchaDefaultSeconds 规则没填持续时间时的兜底值
const ccCaptchaDefaultSeconds = 300

// RequireCaptcha 要求该客户端在本站点完成一次人机验证。
//
// 这是给「触发来源」用的统一入口：CC 规则是目前唯一的来源，后续自定义规则等接进来
// 只需要调用它并传一个自己的 source。挑战怎么发、凭证怎么认，都由验证码闸门统一负责。
//
// 键里存的是「持续时间」秒数：闸门在客户端通过验证后据此换算同等长度的免挑战期，
// 而闸门拿不到规则本身，所以必须把秒数一起带上。
//
// source 只用于日志归因（如 "CC规则 CC-EJ2GJ5"），单独存一个键：
// 「需验证」键的取值格式保持不变，升级瞬间由旧版本写下、尚未过期的标记才不会失效。
func RequireCaptcha(hostCode, clientIP string, seconds int, source string) {
	if global.GCACHE_WAFCACHE == nil || clientIP == "" {
		return
	}
	if seconds <= 0 {
		seconds = ccCaptchaDefaultSeconds
	}
	ttl := time.Duration(seconds) * time.Second
	global.GCACHE_WAFCACHE.SetWithTTl(ccCaptchaRequiredKey(hostCode, clientIP), seconds, ttl)
	if source != "" {
		global.GCACHE_WAFCACHE.SetWithTTl(ccCaptchaSourceKey(hostCode, clientIP), source, ttl)
	}
}

func ccCaptchaSourceKey(hostCode, clientIP string) string {
	return "CACHE_CC_CAPTCHA_SRC_" + hostCode + "|" + clientIP
}

// CaptchaRequireSource 取本次验证是谁要求的，用于日志归因。
// 取不到就返回空串——闸门此前根本不知道触发来源，出问题只能猜。
func CaptchaRequireSource(hostCode, clientIP string) string {
	if global.GCACHE_WAFCACHE == nil || clientIP == "" {
		return ""
	}
	if v, err := global.GCACHE_WAFCACHE.GetString(ccCaptchaSourceKey(hostCode, clientIP)); err == nil {
		return v
	}
	return ""
}

func ccCaptchaGraceKey(hostCode, clientIP string) string {
	return "CACHE_CC_CAPTCHA_GRACE_" + hostCode + "|" + clientIP
}

// isCCCaptchaInGrace 该客户端是否处于「刚通过验证」的免挑战期。
func isCCCaptchaInGrace(hostCode, clientIP string) bool {
	if global.GCACHE_WAFCACHE == nil || clientIP == "" {
		return false
	}
	return global.GCACHE_WAFCACHE.IsKeyExist(ccCaptchaGraceKey(hostCode, clientIP))
}

// GrantCCCaptchaGrace 客户端带着有效凭证出现在闸门前，说明这一轮验证已经通过：
// 清掉「需验证」标记，换成同等长度的免挑战期。免挑战期结束后再超阈值会重新挑战，
// 因此这个动作是可重复的关卡，不是一次性的。
func GrantCCCaptchaGrace(hostCode, clientIP string) {
	if global.GCACHE_WAFCACHE == nil || clientIP == "" {
		return
	}
	seconds := ccCaptchaDefaultSeconds
	if v, err := global.GCACHE_WAFCACHE.GetInt(ccCaptchaRequiredKey(hostCode, clientIP)); err == nil && v > 0 {
		seconds = v
	}
	global.GCACHE_WAFCACHE.Remove(ccCaptchaRequiredKey(hostCode, clientIP))
	global.GCACHE_WAFCACHE.Remove(ccCaptchaSourceKey(hostCode, clientIP))
	global.GCACHE_WAFCACHE.SetWithTTl(
		ccCaptchaGraceKey(hostCode, clientIP), 1, time.Duration(seconds)*time.Second)
}

// revokeCaptchaPass 作废该客户端当前持有的验证码通行凭证，使其必须重新完成挑战。
func revokeCaptchaPass(r *http.Request, clientIP string) {
	if global.GCACHE_WAFCACHE == nil || r == nil || clientIP == "" {
		return
	}
	if cookie, err := r.Cookie("samwaf_captcha_token"); err == nil && cookie.Value != "" {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_CAPTCHA_PASS + cookie.Value + clientIP)
	}
	if token := r.Header.Get("X-SamWaf-Captcha-Token"); token != "" {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_CAPTCHA_PASS + token + clientIP)
	}
}

func ccCaptchaRequiredKey(hostCode, clientIP string) string {
	return "CACHE_CC_CAPTCHA_REQUIRED_" + hostCode + "|" + clientIP
}

// IsCCCaptchaRequired 该客户端是否处于「需完成人机验证」状态。
func IsCCCaptchaRequired(hostCode, clientIP string) bool {
	if global.GCACHE_WAFCACHE == nil || clientIP == "" {
		return false
	}
	return global.GCACHE_WAFCACHE.IsKeyExist(ccCaptchaRequiredKey(hostCode, clientIP))
}

// ccBotExempt 判断本次请求是否因「已验证爬虫豁免」而不参与这条规则的计数。
//
// 三个条件缺一不可：
//   - 规则开了豁免
//   - 动作不是「观察」——观察本来就不阻断，豁免了反而看不到爬虫的真实流量
//   - 爬虫身份走完了完整验证闭环（BotVerifyStrong）。仅反向 DNS 匹配上、
//     正向确认不了的不算：豁免的把握程度不能超过身份验证的把握程度
func ccBotExempt(cr *ccrule.CompiledRule, weblogbean *innerbean.WebLog) bool {
	if cr == nil || cr.Rule == nil || weblogbean == nil {
		return false
	}
	if cr.Rule.BotExempt != 1 || cr.Rule.Action == model.CCActionObserve {
		return false
	}
	return weblogbean.IsBot == 1 && weblogbean.RISK_LEVEL == 0 && weblogbean.BotVerifyStrong == 1
}
