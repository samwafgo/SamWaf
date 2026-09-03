package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"SamWaf/wafenginecore/ccrule"
	"SamWaf/webplugin"
	"fmt"

	"golang.org/x/time/rate"
)

// BuildIPRateLimiter 按 AntiCC 配置构造 IP 限流器。
//
// 冷启动(LoadHost)与热更新(ApplyAntiCCConfig)共用本函数，保证两条路径算出的阈值一致。
// 注意 AntiCC.Rate 的语义是「时间窗口(秒)」而不是速率：平均速率模式下每秒速率为 Limit/Rate。
// 同包的 AST 用例会拦住绕过本函数直接构造限流器的写法。
//
// antiCC.Id 为空表示未配置 CC 防护，返回 nil。
func BuildIPRateLimiter(antiCC model.AntiCC, hostName string) *webplugin.IPRateLimiter {
	if antiCC.Id == "" {
		return nil
	}

	// 时间窗口为 0 会让速率计算除零、滑动窗口退化成「任何请求都过期」。
	// 兜底成 1 秒，并留日志提示配置有问题，而不是静默失效。
	window := antiCC.Rate
	if window <= 0 {
		zlog.Warn(fmt.Sprintf("CC防护时间窗口配置非法(%v)，按1秒处理 主机%v", antiCC.Rate, hostName))
		window = 1
	}

	var limiter *webplugin.IPRateLimiter
	if antiCC.LimitMode == "window" {
		limiter = webplugin.NewWindowIPRateLimiter(window, antiCC.Limit)
		zlog.Debug(fmt.Sprintf("初始化CC防护(滑动窗口模式) 主机%v 时间窗口(秒)%v 最大请求数%v",
			hostName, window, antiCC.Limit))
	} else {
		ratePerSecond := rate.Limit(float64(antiCC.Limit) / float64(window))
		limiter = webplugin.NewIPRateLimiter(ratePerSecond, antiCC.Limit)
		zlog.Debug(fmt.Sprintf("初始化CC防护(平均速率模式) 主机%v 时间窗口(秒)%v 最大请求数%v 每秒速率%v",
			hostName, window, antiCC.Limit, float64(antiCC.Limit)/float64(window)))
	}

	if antiCC.IsEnableRule {
		limiter.Rule = &utils.RuleHelper{}
		limiter.Rule.InitRuleEngine()
		limiter.Rule.LoadRuleString(antiCC.RuleContent)
	}
	return limiter
}

// LoadCompiledCCRules 读取并编译某个网站的 CC 多规则，按优先级升序返回。
//
// 编译发生在这里而不是请求期：正则编译、条件解析都是一次性成本，
// 放进热路径会按请求量重复付出。编译不过的规则直接跳过并告警——
// 让一条写坏的规则拖垮整站的加载不划算。
func LoadCompiledCCRules(hostCode string) []*ccrule.CompiledRule {
	if hostCode == "" || global.GWAF_LOCAL_DB == nil {
		return nil
	}
	var rules []model.AntiCCRule
	if err := global.GWAF_LOCAL_DB.Where("host_code = ? and is_enable = 1", hostCode).
		Order("priority asc").Find(&rules).Error; err != nil {
		zlog.Error("加载CC规则失败", err)
		return nil
	}
	out := make([]*ccrule.CompiledRule, 0, len(rules))
	for i := range rules {
		compiled, err := ccrule.Compile(&rules[i])
		if err != nil {
			zlog.Warn(fmt.Sprintf("CC规则编译失败已跳过 规则名%v 原因%v", rules[i].RuleName, err))
			continue
		}
		out = append(out, compiled)
	}
	return out
}

// ApplyCCRules 热更新某个网站的 CC 规则集，走 copy-on-write 原子发布。
func (waf *WafEngine) ApplyCCRules(hostCode string) {
	compiled := LoadCompiledCCRules(hostCode)
	waf.UpdateHost(hostCode, func(hostSafe *wafenginmodel.HostSafe) {
		hostSafe.CCRules = compiled
	})
	zlog.Debug(fmt.Sprintf("CC规则热更新完成 主机%v 规则数%v", hostCode, len(compiled)))
}
