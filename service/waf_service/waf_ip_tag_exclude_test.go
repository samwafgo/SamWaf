package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"strings"
	"testing"
)

// 排除标签配置的输入校验：值来自管理端输入，虽然进 SQL 时一律是绑定参数，
// 仍要把引号/注释符/控制字符/超长/超多挡在配置层（写入时报错、读取时丢弃）。
func TestIsValidAttackTagExcludeItem(t *testing.T) {
	good := []string{
		"ACME证书校验",
		"静态文件访问成功",
		"静态文件安全检查: 文件未找到",
		"OWASP:942100",
		"RCE:存在OS命令注入",
		"敏感词检测：身份证",
		"【全局】触发IP频次访问限制",
		"AI检测:异常请求",
	}
	for _, tag := range good {
		if !IsValidAttackTagExcludeItem(tag) {
			t.Errorf("正常规则名被误判为非法: %q", tag)
		}
	}

	bad := map[string]string{
		"单引号":     "正常' OR '1'='1",
		"双引号":     `正常" OR 1=1`,
		"反引号":     "正常`",
		"分号":      "正常; DROP TABLE ip_tags",
		"反斜杠":     "正常\\x27",
		"行注释":     "正常--",
		"块注释开始":   "正常/*",
		"块注释结束":   "*/正常",
		"井号注释":    "正常#",
		"换行":      "正常\nDROP TABLE ip_tags",
		"制表符":     "正常\tabc",
		"空字符串":    "",
		"UNION注入": "x' UNION SELECT 1,2,3--",
	}
	for name, tag := range bad {
		if IsValidAttackTagExcludeItem(tag) {
			t.Errorf("%s 应判为非法但通过了: %q", name, tag)
		}
	}

	if IsValidAttackTagExcludeItem(strings.Repeat("a", attackTagMaxLen+1)) {
		t.Error("超长标签应判为非法")
	}
}

func TestValidateAttackTagExclude(t *testing.T) {
	if bad, ok := ValidateAttackTagExclude("ACME证书校验,静态文件访问成功"); !ok {
		t.Errorf("默认配置应合法，却卡在 %q", bad)
	}
	if _, ok := ValidateAttackTagExclude(""); !ok {
		t.Error("空配置应合法（等于只排除 正常）")
	}
	if _, ok := ValidateAttackTagExclude("  ACME证书校验 , , 静态文件访问成功  "); !ok {
		t.Error("多余空格和空项应被容忍")
	}

	bad, ok := ValidateAttackTagExclude("ACME证书校验,x'; DROP TABLE ip_tags--")
	if ok {
		t.Error("含注入片段的配置应被拒绝")
	}
	if !strings.Contains(bad, "DROP") {
		t.Errorf("应返回出问题的那一项，实际返回 %q", bad)
	}

	tooMany := make([]string, 0, attackTagExcludeMax+5)
	for i := 0; i < attackTagExcludeMax+5; i++ {
		tooMany = append(tooMany, "标签")
	}
	if _, ok := ValidateAttackTagExclude(strings.Join(tooMany, ",")); ok {
		t.Errorf("超过 %d 项应被拒绝", attackTagExcludeMax)
	}
}

// benignTags 是查询实际用的清单：脏配置要被丢弃而不是让整页查不出来
func TestBenignTagsDropsInvalid(t *testing.T) {
	zlog.InitZLog(false, "console") // benignTags 里有 zlog.Warn
	old := global.GCONFIG_ATTACK_TAG_EXCLUDE
	defer func() { global.GCONFIG_ATTACK_TAG_EXCLUDE = old }()

	global.GCONFIG_ATTACK_TAG_EXCLUDE = "ACME证书校验,x' OR 1=1--,静态文件访问成功"
	tags := benignTags()
	want := map[string]bool{"正常": true, "ACME证书校验": true, "静态文件访问成功": true}
	if len(tags) != len(want) {
		t.Fatalf("期望 %d 个标签，实际 %d 个: %v", len(want), len(tags), tags)
	}
	for _, tag := range tags {
		if !want[tag] {
			t.Errorf("非法标签混进了查询清单: %q", tag)
		}
	}

	// "正常"永远在，且不会因为用户又写一遍而重复
	global.GCONFIG_ATTACK_TAG_EXCLUDE = "正常,正常,ACME证书校验"
	tags = benignTags()
	if len(tags) != 2 || tags[0] != "正常" {
		t.Fatalf("去重后应是 [正常 ACME证书校验]，实际 %v", tags)
	}

	// 条数上限
	many := make([]string, 0, attackTagExcludeMax+10)
	for i := 0; i < attackTagExcludeMax+10; i++ {
		many = append(many, strings.Repeat("标签", 1)+string(rune('A'+i%26))+string(rune('0'+i/26)))
	}
	global.GCONFIG_ATTACK_TAG_EXCLUDE = strings.Join(many, ",")
	if got := len(benignTags()); got > attackTagExcludeMax+1 {
		t.Errorf("清单应被截到 %d 项(含正常)，实际 %d 项", attackTagExcludeMax+1, got)
	}
}

// 条件表达式：空清单要退化成恒真/恒假，不能生成半截 SQL
func TestBenignCondEdgeCases(t *testing.T) {
	if got := benignNotCond(0); got != "1=1" {
		t.Errorf("空清单的 NOT 条件应恒真，实际 %q", got)
	}
	if got := benignIsCond(0); got != "1=0" {
		t.Errorf("空清单的 IS 条件应恒假，实际 %q", got)
	}
	if got := benignNotCond(3); got != "(ip_tag<>? AND ip_tag<>? AND ip_tag<>?)" {
		t.Errorf("NOT 条件拼错: %q", got)
	}
	if got := benignIsCond(2); got != "(ip_tag=? OR ip_tag=?)" {
		t.Errorf("IS 条件拼错: %q", got)
	}
	// 条件里除了占位符不能出现任何标签内容
	if strings.ContainsAny(benignNotCond(5), "'\"`;") {
		t.Error("条件表达式里不该出现引号类字符")
	}
}
