package wafai

import "strings"

// 规则弱标签：把 SamWaf 日志里的规则命中转换为训练标签。
// 与 SamWafAI samwafai/data/labeling.py 保持一致的判定逻辑。
//
// 只把"载荷型"攻击规则的命中当作正样本；CC/IP黑白名单/防盗链/验证码等
// 行为型或策略型拦截与请求载荷内容无关，全部丢弃，避免污染训练。

// payloadRuleKeywords RULE 标题包含这些关键字 -> 载荷型攻击（正样本）
var payloadRuleKeywords = []struct {
	kw         string
	attackType string
}{
	{"sql", "sqli"}, {"注入", "sqli"},
	{"xss", "xss"}, {"跨站", "xss"},
	{"rce", "rce"}, {"命令执行", "rce"}, {"代码执行", "rce"},
	{"扫描", "scan"}, {"scan", "scan"},
	{"穿越", "traversal"}, {"traversal", "traversal"},
	{"owasp", "owasp"},
}

// excludeRuleKeywords RULE 标题包含这些关键字 -> 非载荷型，直接丢弃
var excludeRuleKeywords = []string{
	"cc", "频次", "rate limit",
	"ip", "黑名单", "白名单",
	"防盗链", "盗链",
	"验证码", "captcha",
	"敏感词",
	"bot", "爬虫", "蜘蛛",
	"url黑", "url白", "禁止url", "路径禁止",
	"应用",
	"ai检测", // AI 自己产生的命中不能再回灌当弱标签，避免自我强化
}

var blockActions = []string{"禁止", "阻止"}

// highConfidenceAttackTypes 高置信攻击类型：命中即基本可判定为真攻击（误报率低），
// 未经人工确认也可作为训练正样本。
//   - sqli/xss：libinjection 词法分析，精度高。
//   - owasp：OWASP CRS 规则集。
//   - rce：检测仅匹配 phpinfo()/call_user_func_array/invokefunction 等极具体签名，正常流量几乎不出现，误报极低。
//   - traversal：匹配 ../、..\、%2e%2e 等穿越特征，正常流量很少出现，误报低。
//
// scan 由 User-Agent 判定（curl/python-requests 等合法工具也会命中），误报高，仍排除在高置信外，
// 未经人工确认不当攻击；自定义规则同理。
var highConfidenceAttackTypes = map[string]bool{
	"sqli":      true,
	"xss":       true,
	"owasp":     true,
	"rce":       true,
	"traversal": true,
}

// IsHighConfidenceAttackType 该攻击类型是否高置信（可在无人工确认时信任为正样本）。
func IsHighConfidenceAttackType(attackType string) bool {
	return highConfidenceAttackTypes[attackType]
}

// WeakLabelVerdict 弱标签判定结果。
type WeakLabelVerdict int

const (
	VerdictDrop   WeakLabelVerdict = iota // 丢弃（不用于训练）
	VerdictAttack                         // 载荷型攻击正样本
	VerdictNormal                         // 正常负样本
)

// WeakLabel 根据日志的 action/rule/logOnlyMode 给出弱标签。
func WeakLabel(action, rule string, logOnlyMode int) (WeakLabelVerdict, string) {
	ruleL := strings.ToLower(strings.TrimSpace(rule))
	blocked := false
	for _, a := range blockActions {
		if strings.TrimSpace(action) == a {
			blocked = true
			break
		}
	}
	if logOnlyMode == 1 && ruleL != "" {
		blocked = true
	}

	if !blocked {
		if ruleL == "" {
			return VerdictNormal, ""
		}
		return VerdictDrop, ""
	}

	for _, p := range payloadRuleKeywords {
		if strings.Contains(ruleL, p.kw) {
			return VerdictAttack, p.attackType
		}
	}
	for _, kw := range excludeRuleKeywords {
		if strings.Contains(ruleL, kw) {
			return VerdictDrop, ""
		}
	}
	return VerdictDrop, ""
}
