package model_test

import (
	"SamWaf/model"
	"SamWaf/utils"
	"strings"
	"testing"
)

// buildRule 用界面编排的方式生成一条规则
func buildRule(t *testing.T, action string, skips []string, remark string, conditions ...model.RelationDetail) (string, error) {
	t.Helper()
	ruleTool := model.RuleTool{}
	ruleInfo := model.RuleInfo{
		RuleAction:      action,
		RuleActionSkips: skips,
		RuleBase: model.RuleBase{
			Salience: 10,
			RuleName: "abc123",
		},
		RuleCondition: model.RuleCondition{
			RelationDetail: conditions,
			RelationSymbol: "&&",
		},
	}
	return ruleTool.GenRuleInfo(ruleInfo, remark)
}

func strCond(attr, judge, val string) model.RelationDetail {
	return model.RelationDetail{
		FactName:  "MF",
		Attr:      attr,
		AttrType:  "string",
		AttrJudge: judge,
		AttrVal:   val,
		AttrVal2:  "true",
	}
}

// ---------- 动作语句生成 ----------

func TestGenRuleInfo_Action(t *testing.T) {
	cases := []struct {
		name     string
		action   string
		skips    []string
		wantStmt string
	}{
		{"默认(老数据无动作)", "", nil, "RF.Deny();"},
		{"拦截", "deny", nil, "RF.Deny();"},
		{"仅记录", "log", nil, "RF.Log();"},
		{"放行", "allow", nil, "RF.Allow();"},
		{"放行并跳过指定模块", "allow", []string{"CC", "AI"}, `RF.Allow("CC", "AI");`},
		{"放行并跳过全部", "allow", []string{"ALL"}, "RF.AllowAll();"},
		{"非法模块名被丢弃", "allow", []string{"CC", "NOT_A_MODULE"}, `RF.Allow("CC");`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content, err := buildRule(t, tc.action, tc.skips, "测试规则", strCond("URL", "system.Contains", "/admin"))
			if err != nil {
				t.Fatalf("生成规则失败: %v", err)
			}
			if !strings.Contains(content, tc.wantStmt) {
				t.Fatalf("期望包含动作语句 %s，实际规则:\n%s", tc.wantStmt, content)
			}
		})
	}
}

// ---------- 注入对抗（核心） ----------

// 这是本次改动最重要的安全保证。
// 从攻击日志一键新建规则时，拼进 Contains(...) 里的是攻击者构造的 UA/URL 原文。
// 攻击者只要发一个 UA 形如 `x") RF.AllowAll(); //` 的请求，诱导管理员点"加入规则"，
// 生成的规则就会从"拦截"变成"放行"。下面这些用例保证这条路走不通。
func TestGenRuleInfo_InjectionFromAttackerControlledValue(t *testing.T) {
	payloads := []string{
		`x") RF.AllowAll(); //`,
		`x") RF.Allow("ALL"); Retract("Rabc123"); //`,
		"x\") \n RF.AllowAll(); \n //",
		`x"} rule Revil "偷偷放行" salience 999 { when MF.SRC_IP == "6.6.6.6" then RF.AllowAll(); }`,
		`x\") RF.AllowAll(); //`,
		`x\\") RF.AllowAll(); //`,
	}

	ruleHelper := &utils.RuleHelper{}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			content, err := buildRule(t, "deny", nil, "拦截可疑UA", strCond("USER_AGENT", "system.Contains", payload))
			if err != nil {
				t.Fatalf("生成规则失败: %v", err)
			}

			// 1. 生成的规则必须还能编译（转义正确，没把语法搞坏）
			if err := ruleHelper.CheckRuleAvailable(content); err != nil {
				t.Fatalf("转义后的规则无法编译: %v\n规则内容:\n%s", err, content)
			}

			// 2. 只能有一条规则（payload 里的 rule 定义不能真的生效）
			if n := utils.CountRuleBlocks(content); n != 1 {
				t.Fatalf("payload 注入出了额外的规则块(%d条):\n%s", n, content)
			}

			// 3. 最关键：动作必须还是拦截，绝不能被 payload 改成放行
			actions := utils.ExtractRuleActions(content)
			info, ok := actions["Rabc123"]
			if !ok {
				info = utils.RuleActionInfo{Action: utils.RuleActionDeny}
			}
			if info.Action != utils.RuleActionDeny {
				t.Fatalf("规则动作被注入改写成了 %s（应为 deny）:\n%s", info.Action, content)
			}
		})
	}
}

// 规则名（备注）同样是用户可控的，也可能是从日志复制来的内容
func TestGenRuleInfo_InjectionFromRemark(t *testing.T) {
	ruleHelper := &utils.RuleHelper{}
	content, err := buildRule(t, "deny", nil, `恶意备注" salience 999 { when true then RF.AllowAll(); } //`,
		strCond("URL", "system.Contains", "/admin"))
	if err != nil {
		t.Fatalf("生成规则失败: %v", err)
	}
	if err := ruleHelper.CheckRuleAvailable(content); err != nil {
		t.Fatalf("转义后的规则无法编译: %v\n%s", err, content)
	}
	if n := utils.CountRuleBlocks(content); n != 1 {
		t.Fatalf("备注注入出了额外的规则块(%d条):\n%s", n, content)
	}
	actions := utils.ExtractRuleActions(content)
	if info, ok := actions["Rabc123"]; ok && info.Action != utils.RuleActionDeny {
		t.Fatalf("规则动作被备注注入改写成了 %s:\n%s", info.Action, content)
	}
}

// 非字符串类型的值是裸拼进表达式的，转义救不了，必须靠白名单拦住
func TestGenRuleInfo_NonStringValueMustBeNumeric(t *testing.T) {
	_, err := buildRule(t, "deny", nil, "端口规则", model.RelationDetail{
		FactName:  "MF",
		Attr:      "PORT",
		AttrType:  "int",
		AttrJudge: "==",
		AttrVal:   `1 then RF.AllowAll()`,
	})
	if err == nil {
		t.Fatal("int 类型的值不是数字时必须报错，否则可以直接逃逸出字符串上下文")
	}
}

// ---------- 结构位白名单 ----------

func TestGenRuleInfo_StructureWhiteList(t *testing.T) {
	cases := []struct {
		name string
		cond model.RelationDetail
	}{
		{"非法字段名", model.RelationDetail{FactName: "MF", Attr: `URL; RF.AllowAll()`, AttrType: "string", AttrJudge: "==", AttrVal: "x"}},
		{"非法运算符", model.RelationDetail{FactName: "MF", Attr: "URL", AttrType: "string", AttrJudge: "== \"x\" || true ||", AttrVal: "x"}},
		{"非法事实对象", model.RelationDetail{FactName: "EVIL", Attr: "URL", AttrType: "string", AttrJudge: "==", AttrVal: "x"}},
		{"非法值类型", model.RelationDetail{FactName: "MF", Attr: "URL", AttrType: "raw", AttrJudge: "==", AttrVal: "x"}},
		{"函数判断的结果值非法", model.RelationDetail{FactName: "MF", Attr: "URL", AttrType: "string", AttrJudge: "system.Contains", AttrVal: "x", AttrVal2: `true || RF.AllowAll()`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildRule(t, "deny", nil, "x", tc.cond); err == nil {
				t.Fatal("非法结构位必须报错")
			}
		})
	}
}

func TestGenRuleInfo_InvalidRuleName(t *testing.T) {
	ruleTool := model.RuleTool{}
	ruleInfo := model.RuleInfo{
		RuleBase:      model.RuleBase{Salience: 10, RuleName: `abc" salience 999 { when true then RF.AllowAll(); } //`},
		RuleCondition: model.RuleCondition{RelationDetail: []model.RelationDetail{strCond("URL", "==", "/x")}},
	}
	if _, err := ruleTool.GenRuleInfo(ruleInfo, "x"); err == nil {
		t.Fatal("非法规则标识必须报错")
	}
}

// ---------- 正常规则仍然可用 ----------

func TestGenRuleInfo_NormalRulesStillWork(t *testing.T) {
	ruleHelper := &utils.RuleHelper{}

	// 含中文备注、含引号的普通值
	content, err := buildRule(t, "deny", nil, `禁止访问后台"管理"页`,
		strCond("URL", "system.Contains", "/admin"),
		strCond("USER_AGENT", "system.Contains", "curl"))
	if err != nil {
		t.Fatalf("生成规则失败: %v", err)
	}
	if err := ruleHelper.CheckRuleAvailable(content); err != nil {
		t.Fatalf("正常规则应该能编译: %v\n%s", err, content)
	}
	if !strings.Contains(content, "&&") {
		t.Fatalf("多条件应该用 && 连接:\n%s", content)
	}
}

func TestEscapeGrlString(t *testing.T) {
	cases := map[string]string{
		`abc`:    `abc`,
		`a"b`:    `a\"b`,
		`a\b`:    `a\\b`,
		"a\nb":   `ab`,
		"a\tb":   `ab`,
		`a\") x`: `a\\\") x`,
		"中文":     "中文",
	}
	for in, want := range cases {
		if got := model.EscapeGrlString(in); got != want {
			t.Fatalf("EscapeGrlString(%q) = %q, 期望 %q", in, got, want)
		}
	}
}
