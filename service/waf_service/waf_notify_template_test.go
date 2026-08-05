package waf_service

import (
	"SamWaf/model"
	"strings"
	"testing"
)

// TestRenderDefaultUnchanged 不配模板时，输出必须与升级前逐字一致
func TestRenderDefaultUnchanged(t *testing.T) {
	ev := ruleEvent("www.a.com", "SQL注入检测", "1.2.3.4")
	sub := model.NotifySubscription{MessageType: model.MSG_TYPE_RULE_TRIGGER}

	title, content, used := RenderNotifyMessage(sub, "dingtalk", ev)
	if title != ev.DefaultTitle || content != ev.DefaultContent {
		t.Fatalf("未配模板时应原样输出内置格式\ntitle=%q\ncontent=%q", title, content)
	}
	if used != model.TemplateUsedDefault {
		t.Fatalf("模板来源应为 default，实际 %s", used)
	}
}

// TestRenderCustomTemplate 自定义模板生效
func TestRenderCustomTemplate(t *testing.T) {
	ev := ruleEvent("www.a.com", "SQL注入检测", "1.2.3.4")
	sub := model.NotifySubscription{
		MessageType:     model.MSG_TYPE_RULE_TRIGGER,
		TitleTemplate:   "[{{.Severity}}] {{.Domain}} 告警",
		ContentTemplate: "域名 {{.Domain}} 来源 {{.Ip}} 规则 {{.RuleInfo}}",
	}

	title, content, used := RenderNotifyMessage(sub, "dingtalk", ev)
	if title != "[warn] www.a.com 告警" {
		t.Fatalf("标题模板渲染错误: %q", title)
	}
	if !strings.Contains(content, "www.a.com") || !strings.Contains(content, "1.2.3.4") {
		t.Fatalf("正文模板渲染错误: %q", content)
	}
	if used != model.TemplateUsedCustom {
		t.Fatalf("模板来源应为 custom，实际 %s", used)
	}
}

// TestRenderFallbackOnBadTemplate 模板写错必须降级为默认内容，绝不能让告警消失
func TestRenderFallbackOnBadTemplate(t *testing.T) {
	ev := ruleEvent("www.a.com", "SQL注入检测", "1.2.3.4")
	cases := []string{
		"{{.Domain",                       // 语法错误
		"{{ .Domain | nosuch }}",          // 未注册的函数
		"{{ range .NotSlice }}x{{ end }}", // 类型不匹配
	}
	for _, tpl := range cases {
		sub := model.NotifySubscription{MessageType: model.MSG_TYPE_RULE_TRIGGER, ContentTemplate: tpl}
		_, content, used := RenderNotifyMessage(sub, "dingtalk", ev)
		if used != model.TemplateUsedFallback {
			t.Fatalf("模板 %q 应触发降级，实际 %s", tpl, used)
		}
		if content != ev.DefaultContent {
			t.Fatalf("降级后应回到内置默认内容，实际 %q", content)
		}
	}
}

// TestTemplateVarEscaping 变量是攻击者可控输入，不能破坏消息结构，邮件不能带出可执行内容
func TestTemplateVarEscaping(t *testing.T) {
	evil := "`code` *bold* [link](http://x) <script>alert(1)</script>"
	ev := ruleEvent("www.a.com", evil, "1.2.3.4")
	sub := model.NotifySubscription{
		MessageType:     model.MSG_TYPE_RULE_TRIGGER,
		ContentTemplate: "规则: {{.RuleInfo}}",
	}

	_, imContent, _ := RenderNotifyMessage(sub, "dingtalk", ev)
	if strings.Contains(imContent, "`code`") {
		t.Fatalf("Markdown 反引号未转义: %q", imContent)
	}
	if strings.Contains(imContent, "*bold*") {
		t.Fatalf("Markdown 星号未转义: %q", imContent)
	}

	_, mailContent, _ := RenderNotifyMessage(sub, "email", ev)
	if strings.Contains(mailContent, "<script>") {
		t.Fatalf("邮件渠道未做 HTML 转义: %q", mailContent)
	}
	if !strings.Contains(mailContent, "&lt;script&gt;") {
		t.Fatalf("邮件渠道应输出实体转义结果: %q", mailContent)
	}
}

// TestTemplateVarTruncated 超长变量要被截断，避免单条消息撑爆渠道限制
func TestTemplateVarTruncated(t *testing.T) {
	long := strings.Repeat("A", 5000)
	ev := ruleEvent("www.a.com", long, "1.2.3.4")
	sub := model.NotifySubscription{MessageType: model.MSG_TYPE_RULE_TRIGGER, ContentTemplate: "{{.RuleInfo}}"}

	_, content, _ := RenderNotifyMessage(sub, "dingtalk", ev)
	if len(content) > notifyContentMaxLen+len(notifyTruncatedMark)*2 {
		t.Fatalf("正文未被截断，长度 %d", len(content))
	}
	if !strings.Contains(content, notifyTruncatedMark) {
		t.Fatalf("截断后应带截断提示: %q", content[:80])
	}
}

// TestTruncateTextKeepsUTF8 截断不能把中文切成乱码
func TestTruncateTextKeepsUTF8(t *testing.T) {
	s := strings.Repeat("测试", 100) // 每字 3 字节
	got := truncateText(s, 10)
	trimmed := strings.TrimSuffix(got, notifyTruncatedMark)
	if !utf8Valid(trimmed) {
		t.Fatalf("截断产生了非法 UTF-8: %q", trimmed)
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// TestBuildMergedMessage 单条与多条的合并行为
func TestBuildMergedMessage(t *testing.T) {
	sub := model.NotifySubscription{MessageType: model.MSG_TYPE_RULE_TRIGGER}
	one := []NotifyEvent{ruleEvent("a.com", "规则A", "1.1.1.1")}

	title, content, _ := BuildMergedMessage(sub, "dingtalk", one, 10)
	if strings.Contains(title, "合并") {
		t.Fatalf("单条不应带合并标记: %q", title)
	}
	if content != one[0].DefaultContent {
		t.Fatal("单条内容应与不聚合时逐字一致")
	}

	many := make([]NotifyEvent, 0, 25)
	for i := 0; i < 25; i++ {
		many = append(many, ruleEvent("a.com", "规则A", "1.1.1.1"))
	}
	title2, content2, _ := BuildMergedMessage(sub, "dingtalk", many, 10)
	if !strings.Contains(title2, "合并25条") {
		t.Fatalf("多条应带合并条数: %q", title2)
	}
	if strings.Count(content2, "**[") != 10 {
		t.Fatalf("最多展示 10 条明细，实际 %d", strings.Count(content2, "**["))
	}
	if !strings.Contains(content2, "及其他 15 条") {
		t.Fatalf("应提示剩余条数: %q", content2)
	}
}

// TestSampleEventForEveryMessageType 每个消息类型都要能造出样例（预览/测试/干跑都依赖它）
func TestSampleEventForEveryMessageType(t *testing.T) {
	for _, mt := range AllMessageTypes() {
		ev := SampleNotifyEvent(mt)
		if ev.DefaultTitle == "" || ev.DefaultContent == "" {
			t.Fatalf("消息类型 %s 的样例事件缺少默认标题或正文", mt)
		}
		if len(GetNotifyTemplateVars(mt)) == 0 {
			t.Fatalf("消息类型 %s 没有可用模板变量", mt)
		}
	}
}
