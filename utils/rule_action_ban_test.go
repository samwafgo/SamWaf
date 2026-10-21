package utils

import (
	"strings"
	"testing"
)

// ---------- RF.Ban 动作解析 ----------

func TestExtractRuleActions_Ban(t *testing.T) {
	ruleText := `rule Rban123 "命中封禁10分钟" salience 10 {
    when
        MF.URL.Contains("/wp-admin") == true
    then
        RF.Ban(10);
}`
	actions := ExtractRuleActions(ruleText)
	info, ok := actions["Rban123"]
	if !ok {
		t.Fatalf("未解析到规则动作: %v", actions)
	}
	if info.Action != RuleActionBan {
		t.Fatalf("动作=%s，期望 %s", info.Action, RuleActionBan)
	}
	if info.BanMinutes != 10 {
		t.Fatalf("BanMinutes=%d，期望 10", info.BanMinutes)
	}
}

// 字符串字面量里的 RF.Ban 不得被当成动作（骨架机制）
func TestExtractRuleActions_BanInStringLiteralIgnored(t *testing.T) {
	ruleText := `rule Rfake456 "示例" salience 10 {
    when
        MF.URL.Contains("RF.Ban(10)") == true
    then
        Retract("Rfake456");
}`
	actions := ExtractRuleActions(ruleText)
	info, ok := actions["Rfake456"]
	if ok && info.Action == RuleActionBan {
		t.Fatalf("字符串字面量里的 RF.Ban 被误解析为动作: %+v", info)
	}
}

// 运行期宽容模式：Ban 分钟数非法时降级为普通拦截
func TestExtractRuleActions_BanInvalidMinutesFallsBackToDeny(t *testing.T) {
	cases := []struct {
		name string
		args string
	}{
		{"零分钟", "0"},
		{"负数", "-5"},
		{"非数字", `"abc"`},
		{"空参", ""},
		{"超出时长范围", "153722868"},
	}
	for _, tc := range cases {
		ruleText := `rule Rbad789 "非法" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        RF.Ban(` + tc.args + `);
}`
		actions := ExtractRuleActions(ruleText)
		info, ok := actions["Rbad789"]
		if !ok {
			t.Fatalf("%s: 未解析到规则动作", tc.name)
		}
		if info.Action != RuleActionDeny {
			t.Fatalf("%s: 动作=%s BanMinutes=%d，期望降级为 deny", tc.name, info.Action, info.BanMinutes)
		}
	}
}

// 保存校验严格模式：Ban 分钟数非法必须报错
func TestExtractRuleActionForCheck_BanInvalidMinutesRejected(t *testing.T) {
	cases := []struct {
		name string
		args string
	}{
		{"零分钟", "0"},
		{"负数", "-5"},
		{"非数字", `"abc"`},
		{"空参", ""},
		{"超出时长范围", "153722868"},
	}
	for _, tc := range cases {
		ruleText := `rule Rchk111 "非法" salience 10 {
    when
        MF.URL.Contains("/x") == true
    then
        RF.Ban(` + tc.args + `);
}`
		_, err := ExtractRuleActionForCheck(ruleText)
		if err == nil {
			t.Fatalf("%s: 期望报错但通过", tc.name)
		}
		if !strings.Contains(err.Error(), "RF.Ban") {
			t.Fatalf("%s: 报错信息未提及 RF.Ban: %v", tc.name, err)
		}
	}
}

func TestExtractRuleActionForCheck_BanValid(t *testing.T) {
	ruleText := `rule Rok222 "封禁半小时" salience 10 {
    when
        MF.URL.Contains("/wp-login") == true
    then
        RF.Ban(30);
}`
	info, err := ExtractRuleActionForCheck(ruleText)
	if err != nil {
		t.Fatalf("合法 RF.Ban(30) 校验失败: %v", err)
	}
	if info.Action != RuleActionBan || info.BanMinutes != 30 {
		t.Fatalf("动作=%s BanMinutes=%d，期望 ban/30", info.Action, info.BanMinutes)
	}
}

// 字符串字面量里的 RF.Ban 在严格模式下同样不得报错也不得识别为动作
func TestExtractRuleActionForCheck_BanInStringLiteral(t *testing.T) {
	ruleText := `rule Rlit333 "示例" salience 10 {
    when
        MF.URL.Contains("then RF.Ban(99);") == true
    then
        RF.Deny();
}`
	info, err := ExtractRuleActionForCheck(ruleText)
	if err != nil {
		t.Fatalf("字符串字面量内容导致校验误报: %v", err)
	}
	if info.Action != RuleActionDeny || info.BanMinutes != 0 {
		t.Fatalf("动作=%s BanMinutes=%d，期望 deny/0", info.Action, info.BanMinutes)
	}
}
