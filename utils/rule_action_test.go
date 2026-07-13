package utils

import (
	"strings"
	"testing"
)

// ---------- 动作解析基础用例 ----------

func TestExtractRuleActions_Basic(t *testing.T) {
	cases := []struct {
		name       string
		ruleText   string
		wantAction string
		wantSkips  []string
	}{
		{
			name: "没有动作标记默认拦截（老规则形态，带Retract）",
			ruleText: `rule Rabc123 "老规则" salience 10 {
    when
        MF.URL.Contains("/admin") == true
    then
        Retract("Rabc123");
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "显式Deny",
			ruleText: `rule Rabc123 "拦截" salience 10 {
    when
        MF.URL.Contains("/admin") == true
    then
        RF.Deny();
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "Deny和Retract共存",
			ruleText: `rule Rabc123 "拦截" salience 10 {
    when
        MF.URL.Contains("/admin") == true
    then
        RF.Deny();
        Retract("Rabc123");
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "Log",
			ruleText: `rule Rabc123 "仅记录" salience 10 {
    when
        MF.URL.Contains("/api") == true
    then
        RF.Log();
}`,
			wantAction: RuleActionLog,
		},
		{
			name: "Allow无参",
			ruleText: `rule Rabc123 "放行" salience 10 {
    when
        MF.SRC_IP == "1.2.3.4"
    then
        RF.Allow();
}`,
			wantAction: RuleActionAllow,
		},
		{
			name: "Allow带模块参数",
			ruleText: `rule Rabc123 "放行" salience 10 {
    when
        MF.SRC_IP == "1.2.3.4"
    then
        RF.Allow("CC", "AI");
}`,
			wantAction: RuleActionAllow,
			wantSkips:  []string{"AI", "CC"},
		},
		{
			name: "Allow参数大小写不敏感",
			ruleText: `rule Rabc123 "放行" salience 10 {
    when
        MF.SRC_IP == "1.2.3.4"
    then
        RF.Allow("cc", "sqli");
}`,
			wantAction: RuleActionAllow,
			wantSkips:  []string{"CC", "SQLI"},
		},
		{
			name: "AllowAll",
			ruleText: `rule Rabc123 "全放行" salience 10 {
    when
        MF.SRC_IP == "1.2.3.4"
    then
        RF.AllowAll();
}`,
			wantAction: RuleActionAllow,
			wantSkips:  []string{"ALL"},
		},
		{
			name: "Allow(\"ALL\") 等价 AllowAll",
			ruleText: `rule Rabc123 "全放行" salience 10 {
    when
        MF.SRC_IP == "1.2.3.4"
    then
        RF.Allow("ALL");
}`,
			wantAction: RuleActionAllow,
			wantSkips:  []string{"ALL"},
		},
		{
			name: "写法带多余空格",
			ruleText: `rule Rabc123 "放行" salience 10 {
    when
        MF.SRC_IP == "1.2.3.4"
    then
        RF . Allow ( "CC" ) ;
}`,
			wantAction: RuleActionAllow,
			wantSkips:  []string{"CC"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions := ExtractRuleActions(tc.ruleText)
			info, ok := actions["Rabc123"]
			if !ok {
				// 没解析到动作等价于默认拦截
				info = RuleActionInfo{Action: RuleActionDeny}
			}
			if info.Action != tc.wantAction {
				t.Fatalf("动作不对: 期望 %s, 实际 %s", tc.wantAction, info.Action)
			}
			if strings.Join(info.SkipModules, ",") != strings.Join(tc.wantSkips, ",") {
				t.Fatalf("跳过模块不对: 期望 %v, 实际 %v", tc.wantSkips, info.SkipModules)
			}
		})
	}
}

// ---------- 安全用例：字符串字面量和注释不能骗过动作解析 ----------

// 这一组是这次改动的核心安全保证：
// 规则文本里混着用户/攻击者可控的内容（比如从攻击日志一键建规则时，UA 原文会被拼进 Contains 里）。
// 如果动作解析被字符串里的假标记骗过去，就会出现"保存时看到的是拦截、运行时按放行执行"的认知差。
func TestExtractRuleActions_NotFooledByStringsAndComments(t *testing.T) {
	cases := []struct {
		name       string
		ruleText   string
		wantAction string
	}{
		{
			name: "when条件的字符串里藏着假的AllowAll",
			ruleText: `rule Rabc123 "拦截" salience 10 {
    when
        MF.USER_AGENT.Contains("then RF.AllowAll();") == true
    then
        RF.Deny();
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "then里字符串参数中藏着假的AllowAll",
			ruleText: `rule Rabc123 "拦截" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        RF.Deny();
        Retract("Rabc123 RF.AllowAll();");
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "转义引号逃逸尝试",
			ruleText: `rule Rabc123 "拦截" salience 10 {
    when
        MF.USER_AGENT.Contains("bad\") RF.AllowAll(); //") == true
    then
        RF.Deny();
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "行注释里的动作不生效",
			ruleText: `rule Rabc123 "拦截" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        // RF.AllowAll();
        RF.Deny();
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "块注释里的动作不生效",
			ruleText: `rule Rabc123 "拦截" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        /* RF.Allow("ALL"); */
        RF.Deny();
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "规则描述里藏动作",
			ruleText: `rule Rabc123 "拦截 RF.AllowAll();" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        RF.Deny();
}`,
			wantAction: RuleActionDeny,
		},
		{
			name: "when里的字符串包含then关键字",
			ruleText: `rule Rabc123 "放行" salience 10 {
    when
        MF.URL.Contains("then") == true
    then
        RF.Allow();
}`,
			wantAction: RuleActionAllow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions := ExtractRuleActions(tc.ruleText)
			info, ok := actions["Rabc123"]
			if !ok {
				info = RuleActionInfo{Action: RuleActionDeny}
			}
			if info.Action != tc.wantAction {
				t.Fatalf("动作被骗了: 期望 %s, 实际 %s (skips=%v)", tc.wantAction, info.Action, info.SkipModules)
			}
		})
	}
}

func TestBuildGrlSkeleton_KeepsLength(t *testing.T) {
	src := `rule Rx "描述" salience 10 {
    when
        MF.URL.Contains("a\"b") == true // 注释
    then
        /* 块注释 */ RF.Deny();
}`
	skeleton := BuildGrlSkeleton(src)
	if len(skeleton) != len(src) {
		t.Fatalf("骨架长度必须与原文一致: 原文 %d, 骨架 %d", len(src), len(skeleton))
	}
	if strings.Contains(skeleton, "注释") {
		t.Fatal("注释内容应该被抹掉")
	}
	if !strings.Contains(skeleton, "RF.Deny();") {
		t.Fatal("代码部分应该保留")
	}
}

// ---------- 多条规则 ----------

func TestExtractRuleActions_MultipleRules(t *testing.T) {
	ruleText := `
rule Rone "放行" salience 100 {
    when
        MF.SRC_IP == "1.1.1.1"
    then
        RF.Allow("CC");
}

rule Rtwo "拦截" salience 10 {
    when
        MF.URL.Contains("/admin") == true
    then
        RF.Deny();
}

rule Rthree "仅记录" salience 5 {
    when
        MF.METHOD == "PUT"
    then
        RF.Log();
}`
	actions := ExtractRuleActions(ruleText)
	if actions["Rone"].Action != RuleActionAllow || strings.Join(actions["Rone"].SkipModules, ",") != "CC" {
		t.Fatalf("Rone 解析错误: %+v", actions["Rone"])
	}
	if actions["Rtwo"].Action != RuleActionDeny {
		t.Fatalf("Rtwo 解析错误: %+v", actions["Rtwo"])
	}
	if actions["Rthree"].Action != RuleActionLog {
		t.Fatalf("Rthree 解析错误: %+v", actions["Rthree"])
	}
}

// ---------- 保存期严格校验 ----------

func TestExtractRuleActionForCheck(t *testing.T) {
	t.Run("多个不同动作报错", func(t *testing.T) {
		ruleText := `rule Rabc123 "x" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        RF.Allow();
        RF.Deny();
}`
		if _, err := ExtractRuleActionForCheck(ruleText); err == nil {
			t.Fatal("同时写 Allow 和 Deny 应该报错")
		}
	})

	t.Run("重复写同一个动作允许", func(t *testing.T) {
		ruleText := `rule Rabc123 "x" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        RF.Deny();
        RF.Deny();
}`
		info, err := ExtractRuleActionForCheck(ruleText)
		if err != nil {
			t.Fatalf("重复写同一动作不应报错: %v", err)
		}
		if info.Action != RuleActionDeny {
			t.Fatalf("动作应为 deny, 实际 %s", info.Action)
		}
	})

	t.Run("非法模块名报错", func(t *testing.T) {
		ruleText := `rule Rabc123 "x" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        RF.Allow("NOT_A_MODULE");
}`
		_, err := ExtractRuleActionForCheck(ruleText)
		if err == nil {
			t.Fatal("非法模块名应该报错")
		}
		if !strings.Contains(err.Error(), "NOT_A_MODULE") {
			t.Fatalf("错误信息应包含非法模块名: %v", err)
		}
	})

	t.Run("注释掉的动作不影响校验", func(t *testing.T) {
		ruleText := `rule Rabc123 "x" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        // RF.Allow();
        RF.Deny();
}`
		info, err := ExtractRuleActionForCheck(ruleText)
		if err != nil {
			t.Fatalf("不应报错: %v", err)
		}
		if info.Action != RuleActionDeny {
			t.Fatalf("动作应为 deny, 实际 %s", info.Action)
		}
	})
}

func TestCountRuleBlocks(t *testing.T) {
	//一条规则内容里塞两条规则，第二条偷偷放行——保存时必须能识别出来
	ruleText := `rule Rabc123 "正常规则" salience 10 {
    when
        MF.URL.Contains("/admin") == true
    then
        RF.Deny();
}
rule Revil "偷偷放行" salience 999 {
    when
        MF.SRC_IP == "6.6.6.6"
    then
        RF.AllowAll();
}`
	if got := CountRuleBlocks(ruleText); got != 2 {
		t.Fatalf("应识别出 2 条规则, 实际 %d", got)
	}

	//字符串里写 rule 不算规则
	single := `rule Rabc123 "x" salience 10 {
    when
        MF.URL.Contains("rule Revil") == true
    then
        RF.Deny();
}`
	if got := CountRuleBlocks(single); got != 1 {
		t.Fatalf("字符串里的 rule 不该被算成规则, 实际 %d", got)
	}
}
