package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"testing"
)

// buildRuleHelper 用一段 GRL 文本构建一个可用的规则引擎
func buildRuleHelper(t *testing.T, ruleContent string) *utils.RuleHelper {
	t.Helper()
	rh := &utils.RuleHelper{}
	rh.InitRuleEngine()
	rule := model.Rules{
		RuleCode:    "Rtest001",
		RuleName:    "test",
		RuleContent: ruleContent,
		RuleStatus:  1,
	}
	if _, err := rh.LoadRules([]model.Rules{rule}); err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	return rh
}

// TestPickRuleAction 验证命中后动作的选取逻辑（含 salience 优先级和同级冲突兜底）
func TestPickRuleAction_ThroughEngine(t *testing.T) {
	t.Run("deny默认", func(t *testing.T) {
		rh := buildRuleHelper(t, `
rule Rtest001 "拦截" salience 10 {
    when MF.URL == "/admin"
    then RF.Deny();
}`)
		matchs, _ := rh.Match("MF", &innerbean.WebLog{URL: "/admin"})
		if len(matchs) == 0 {
			t.Fatal("应命中规则")
		}
		info := pickRuleAction(rh, matchs)
		if info.Action != utils.RuleActionDeny {
			t.Fatalf("动作应为 deny, 实际 %s", info.Action)
		}
	})

	t.Run("allow跳过模块", func(t *testing.T) {
		rh := buildRuleHelper(t, `
rule Rtest001 "放行" salience 10 {
    when MF.SRC_IP == "1.2.3.4"
    then RF.Allow("CC", "AI");
}`)
		matchs, _ := rh.Match("MF", &innerbean.WebLog{SRC_IP: "1.2.3.4"})
		info := pickRuleAction(rh, matchs)
		if info.Action != utils.RuleActionAllow {
			t.Fatalf("动作应为 allow, 实际 %s", info.Action)
		}
		if len(info.SkipModules) != 2 {
			t.Fatalf("应跳过2个模块, 实际 %v", info.SkipModules)
		}
	})

	t.Run("log", func(t *testing.T) {
		rh := buildRuleHelper(t, `
rule Rtest001 "记录" salience 10 {
    when MF.METHOD == "PUT"
    then RF.Log();
}`)
		matchs, _ := rh.Match("MF", &innerbean.WebLog{METHOD: "PUT"})
		info := pickRuleAction(rh, matchs)
		if info.Action != utils.RuleActionLog {
			t.Fatalf("动作应为 log, 实际 %s", info.Action)
		}
	})

	t.Run("老规则无动作标记默认deny", func(t *testing.T) {
		rh := buildRuleHelper(t, `
rule Rtest001 "老规则" salience 10 {
    when MF.URL == "/old"
    then Retract("Rtest001");
}`)
		matchs, _ := rh.Match("MF", &innerbean.WebLog{URL: "/old"})
		info := pickRuleAction(rh, matchs)
		if info.Action != utils.RuleActionDeny {
			t.Fatalf("老规则应默认 deny, 实际 %s", info.Action)
		}
	})
}

// TestPickRuleAction_SalienceConflict 同优先级冲突时按 deny > allow > log 兜底
func TestPickRuleAction_SalienceConflict(t *testing.T) {
	rh := buildRuleHelper(t, `
rule Rallow "放行" salience 10 {
    when MF.URL == "/x"
    then RF.Allow();
}
rule Rdeny "拦截" salience 10 {
    when MF.URL == "/x"
    then RF.Deny();
}`)
	matchs, _ := rh.Match("MF", &innerbean.WebLog{URL: "/x"})
	if len(matchs) != 2 {
		t.Fatalf("应命中2条规则, 实际 %d", len(matchs))
	}
	info := pickRuleAction(rh, matchs)
	// 同 salience 一放行一拦截，安全起见取拦截
	if info.Action != utils.RuleActionDeny {
		t.Fatalf("同级冲突应偏向拦截, 实际 %s", info.Action)
	}
}

// TestParseIPFailureThreshold_NotFooledByString 阈值解析不被字符串字面量干扰
func TestParseIPFailureThreshold_NotFooledByString(t *testing.T) {
	// 真实条件
	if _, _, ok := parseIPFailureThreshold(`when MF.GetIPFailureCount(5) > 10 then`); !ok {
		t.Fatal("正常条件应能解析出阈值")
	}
	// 藏在字符串里的假条件不该被解析
	if _, _, ok := parseIPFailureThreshold(`when MF.URL.Contains("GetIPFailureCount(5) > 10") == true then`); ok {
		t.Fatal("字符串里的假条件不该被解析成阈值")
	}
}
