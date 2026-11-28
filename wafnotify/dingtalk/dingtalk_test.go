package dingtalk

import (
	"SamWaf/global"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFormatMarkdownText(t *testing.T) {
	cases := []struct {
		name    string
		title   string
		content string
		want    string
	}{
		{
			name:    "常规标题拼接",
			title:   "[生产WAF] 攻击告警通知",
			content: "**攻击类型:** 目录穿越漏洞",
			want:    "### [生产WAF] 攻击告警通知\n\n**攻击类型:** 目录穿越漏洞",
		},
		{
			name:    "聚合合并标题",
			title:   "攻击告警通知（合并3条）",
			content: "**[1]** 内容",
			want:    "### 攻击告警通知（合并3条）\n\n**[1]** 内容",
		},
		{
			name:    "标题含换行清洗为单行",
			title:   "攻击告警\r\n紧急通知",
			content: "正文",
			want:    "### 攻击告警 紧急通知\n\n正文",
		},
		{
			name:    "空标题透传正文",
			title:   "   \n ",
			content: "**攻击类型:** SQL注入",
			want:    "**攻击类型:** SQL注入",
		},
		{
			name:    "正文已含同名三级标题不重复拼接",
			title:   "攻击告警通知",
			content: "### 攻击告警通知\n\n**攻击类型:** SQL注入",
			want:    "### 攻击告警通知\n\n**攻击类型:** SQL注入",
		},
		{
			name:    "正文已含同名一级标题不重复拼接",
			title:   "攻击告警通知",
			content: "# 攻击告警通知\n正文",
			want:    "# 攻击告警通知\n正文",
		},
		{
			name:    "空正文仅保留标题",
			title:   "测试标题",
			content: "   ",
			want:    "### 测试标题",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatMarkdownText(tc.title, tc.content); got != tc.want {
				t.Fatalf("formatMarkdownText(%q, %q) = %q, want %q", tc.title, tc.content, got, tc.want)
			}
		})
	}
}

func TestDingTalkSendMarkdownIncludesTitleInText(t *testing.T) {
	oldAllowed := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = "127.0.0.1"
	t.Cleanup(func() { global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = oldAllowed })

	var captured DingTalkMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	t.Cleanup(srv.Close)

	notifier := NewDingTalkNotifier(srv.URL, "")
	if err := notifier.SendMarkdown("[prod] 自定义告警标题", "**域名:** xxxx.com\n\n**攻击IP:** 1.2.3.4"); err != nil {
		t.Fatalf("SendMarkdown failed: %v", err)
	}
	if captured.MsgType != "markdown" {
		t.Fatalf("msgtype = %q, want markdown", captured.MsgType)
	}
	gotTitle, _ := captured.Markdown["title"].(string)
	gotText, _ := captured.Markdown["text"].(string)
	if gotTitle != "[prod] 自定义告警标题" {
		t.Fatalf("markdown.title = %q, want %q", gotTitle, "[prod] 自定义告警标题")
	}
	if !strings.HasPrefix(gotText, "### [prod] 自定义告警标题\n\n") {
		t.Fatalf("markdown.text missing title heading: %q", gotText)
	}
	if !strings.Contains(gotText, "**域名:** xxxx.com") {
		t.Fatalf("markdown.text missing body content: %q", gotText)
	}
}
