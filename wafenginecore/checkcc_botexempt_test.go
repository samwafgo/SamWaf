package wafenginecore

import (
	"testing"

	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafenginecore/ccrule"
)

func exemptRule(action string, botExempt int) *ccrule.CompiledRule {
	return &ccrule.CompiledRule{
		Rule: &model.AntiCCRule{RuleName: "t", Action: action, BotExempt: botExempt},
	}
}

func TestCCBotExempt(t *testing.T) {
	strongBot := &innerbean.WebLog{IsBot: 1, RISK_LEVEL: 0, BotVerifyStrong: 1}
	weakBot := &innerbean.WebLog{IsBot: 1, RISK_LEVEL: 0, BotVerifyStrong: 0}
	fakeBot := &innerbean.WebLog{IsBot: 1, RISK_LEVEL: 1, BotVerifyStrong: 0}
	human := &innerbean.WebLog{IsBot: 0, RISK_LEVEL: 0}

	cases := []struct {
		name string
		rule *ccrule.CompiledRule
		log  *innerbean.WebLog
		want bool
	}{
		{"开了豁免+完整验证的爬虫 → 豁免", exemptRule(model.CCActionBan, 1), strongBot, true},
		{"仅反向匹配、正向确认不了 → 不豁免（把握程度不够）", exemptRule(model.CCActionBan, 1), weakBot, false},
		{"伪装爬虫 → 不豁免", exemptRule(model.CCActionBan, 1), fakeBot, false},
		{"普通访客 → 不豁免", exemptRule(model.CCActionBan, 1), human, false},
		{"没开豁免 → 不豁免", exemptRule(model.CCActionBan, 0), strongBot, false},
		{"观察动作 → 不豁免（否则看不到爬虫真实流量）", exemptRule(model.CCActionObserve, 1), strongBot, false},
		{"人机验证动作 → 同样豁免", exemptRule(model.CCActionCaptcha, 1), strongBot, true},
	}
	for _, c := range cases {
		if got := ccBotExempt(c.rule, c.log); got != c.want {
			t.Errorf("%s: 期望 %v，实际 %v", c.name, c.want, got)
		}
	}
}
