package wafai

import "testing"

func TestWeakLabelThreatIPNeverPositive(t *testing.T) {
	// 威胁情报渠道名可由用户自定义，即使包含 sql/xss/scan/rce/owasp 等关键字，
	// 也必须短路丢弃（VerdictDrop），绝不能误当成载荷型攻击正样本污染训练。
	threatRules := []string{
		"威胁情报IP",
		"威胁情报IP:FireHOL Level1",
		"威胁情报IP:SQL扫描源",
		"威胁情报IP:XSS Blacklist",
		"威胁情报IP:RCE Botnet",
		"威胁情报IP:OWASP Feed",
	}
	for _, rule := range threatRules {
		verdict, attackType := WeakLabel("阻止", rule, 0)
		if verdict != VerdictDrop || attackType != "" {
			t.Fatalf("规则 %q 不应被标为正样本，实际 verdict=%v attackType=%q", rule, verdict, attackType)
		}
		// 仅记录观察模式同样必须丢弃
		verdict, attackType = WeakLabel("放行", rule, 1)
		if verdict != VerdictDrop || attackType != "" {
			t.Fatalf("观察模式下规则 %q 也不应被标为正样本，实际 verdict=%v attackType=%q", rule, verdict, attackType)
		}
	}

	// 对照：真正的载荷型规则仍正常判为正样本
	if v, at := WeakLabel("阻止", "SQL注入检测", 0); v != VerdictAttack || at != "sqli" {
		t.Fatalf("SQL注入检测应为 sqli 正样本，实际 verdict=%v attackType=%q", v, at)
	}
	if v, at := WeakLabel("阻止", "OWASP:942100", 0); v != VerdictAttack || at != "owasp" {
		t.Fatalf("OWASP:942100 应为 owasp 正样本，实际 verdict=%v attackType=%q", v, at)
	}
}
