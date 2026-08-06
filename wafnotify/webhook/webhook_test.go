package webhook

import (
	"encoding/json"
	"strings"
	"testing"
)

// 说明：Send() 会强制走 IsSafeOutboundURL，httptest 起在 127.0.0.1 上必然被拒，
// 所以这里只测「配置校验」和「报文渲染」两段纯逻辑，真实投递用管理端的"测试"按钮验证。

func mustConfig(t *testing.T, cfg Config) *WebhookNotifier {
	t.Helper()
	return &WebhookNotifier{Config: cfg}
}

func TestValidateRejectsUnsafeConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantSub string
	}{
		{"空地址", Config{Method: "POST", ContentType: "application/json"}, "地址不能为空"},
		{"内网地址", Config{URL: "http://127.0.0.1/hook", Method: "POST"}, "不被允许"},
		{"非http协议", Config{URL: "file:///etc/passwd", Method: "POST"}, "不被允许"},
		{"方法不在白名单", Config{URL: "https://203.0.113.10/hook", Method: "TRACE"}, "不支持的请求方法"},
		{"头名非法", Config{URL: "https://203.0.113.10/hook", Method: "POST",
			Headers: []Header{{Key: "X Bad Header", Value: "v"}}}, "名称非法"},
		{"头名被系统占用", Config{URL: "https://203.0.113.10/hook", Method: "POST",
			Headers: []Header{{Key: "Host", Value: "evil.com"}}}, "由系统控制"},
		{"头值含CRLF", Config{URL: "https://203.0.113.10/hook", Method: "POST",
			Headers: []Header{{Key: "X-Token", Value: "a\r\nX-Injected: 1"}}}, "非法控制字符"},
		{"头重复", Config{URL: "https://203.0.113.10/hook", Method: "POST",
			Headers: []Header{{Key: "X-Token", Value: "a"}, {Key: "x-token", Value: "b"}}}, "重复"},
		{"模板语法错误", Config{URL: "https://203.0.113.10/hook", Method: "POST",
			BodyTemplate: "{{.Title"}, "语法错误"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.normalize()
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("期望校验失败，实际通过")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("错误信息不含 %q，实际: %v", tc.wantSub, err)
			}
		})
	}
}

func TestNormalizeFillsDefaultsAndDropsEmptyHeaders(t *testing.T) {
	cfg := Config{
		URL:     "  https://203.0.113.10/hook  ",
		Headers: []Header{{Key: "  ", Value: "x"}, {Key: " X-Token ", Value: " abc "}},
	}
	cfg.normalize()

	if cfg.URL != "https://203.0.113.10/hook" {
		t.Fatalf("URL 未去空白: %q", cfg.URL)
	}
	if cfg.Method != DefaultMethod || cfg.ContentType != DefaultContentType {
		t.Fatalf("默认值未填充: %s %s", cfg.Method, cfg.ContentType)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0].Key != "X-Token" || cfg.Headers[0].Value != "abc" {
		t.Fatalf("空行未丢弃或未去空白: %+v", cfg.Headers)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("规范化后应校验通过: %v", err)
	}
}

// 正文里带引号和换行是常态（攻击URL、UA），不转义就会把 JSON 报文打碎
func TestRenderBodyEscapesJSON(t *testing.T) {
	n := mustConfig(t, Config{
		URL:          "https://203.0.113.10/hook",
		Method:       "POST",
		ContentType:  "application/json",
		BodyTemplate: `{"title":"{{.Title}}","text":"{{.Content}}"}`,
	})

	body, err := n.RenderBody(Message{
		Title:   `告警"紧急"`,
		Content: "第一行\n第二行\\结束",
	})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	var got map[string]string
	if err = json.Unmarshal(body, &got); err != nil {
		t.Fatalf("渲染结果不是合法 JSON: %s (%v)", body, err)
	}
	if got["title"] != `告警"紧急"` {
		t.Fatalf("标题被改动: %q", got["title"])
	}
	if got["text"] != "第一行\n第二行\\结束" {
		t.Fatalf("正文被改动: %q", got["text"])
	}
}

func TestRenderBodyRejectsInvalidJSON(t *testing.T) {
	n := mustConfig(t, Config{
		URL:          "https://203.0.113.10/hook",
		Method:       "POST",
		ContentType:  "application/json",
		BodyTemplate: `{"title":"{{.Title}}"`, // 少一个右括号
	})
	if _, err := n.RenderBody(Message{Title: "x"}); err == nil ||
		!strings.Contains(err.Error(), "不是合法 JSON") {
		t.Fatalf("期望报非法 JSON，实际: %v", err)
	}
}

func TestRenderBodyFormURLEncoded(t *testing.T) {
	n := mustConfig(t, Config{
		URL:          "https://203.0.113.10/hook",
		Method:       "POST",
		ContentType:  "application/x-www-form-urlencoded",
		BodyTemplate: `title={{.Title}}&body={{.Content}}`,
	})
	body, err := n.RenderBody(Message{Title: "a b&c", Content: "d=e"})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if string(body) != "title=a+b%26c&body=d%3De" {
		t.Fatalf("表单转义不正确: %s", body)
	}
}

func TestDefaultBody(t *testing.T) {
	jsonNotifier := mustConfig(t, Config{URL: "https://203.0.113.10/hook", Method: "POST", ContentType: "application/json"})
	body, err := jsonNotifier.RenderBody(Message{Title: "标题", Content: "正文", Severity: "warn"})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	var got Message
	if err = json.Unmarshal(body, &got); err != nil {
		t.Fatalf("默认报文不是合法 JSON: %s", body)
	}
	if got.Title != "标题" || got.Content != "正文" || got.Severity != "warn" {
		t.Fatalf("默认报文字段丢失: %+v", got)
	}

	textNotifier := mustConfig(t, Config{URL: "https://203.0.113.10/hook", Method: "POST", ContentType: "text/plain"})
	body, err = textNotifier.RenderBody(Message{Title: "标题", Content: "正文"})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if string(body) != "标题\n\n正文" {
		t.Fatalf("纯文本默认报文不正确: %q", body)
	}
}

func TestRenderBodyRejectsOversizeOutput(t *testing.T) {
	n := mustConfig(t, Config{
		URL:          "https://203.0.113.10/hook",
		Method:       "POST",
		ContentType:  "text/plain",
		BodyTemplate: "{{.Content}}",
	})
	if _, err := n.RenderBody(Message{Content: strings.Repeat("A", MaxBodyBytes+1)}); err == nil {
		t.Fatalf("超长报文应被拒绝")
	}
}

func TestParseConfigFromJSON(t *testing.T) {
	raw := `{"url":"https://203.0.113.10/hook","method":"post","headers":[{"key":"Authorization","value":"Bearer x"}],"body_template":"{\"t\":\"{{.Title}}\"}"}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if cfg.Method != "POST" {
		t.Fatalf("方法未大写: %s", cfg.Method)
	}
	if cfg.ContentType != DefaultContentType {
		t.Fatalf("Content-Type 默认值不对: %s", cfg.ContentType)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0].Value != "Bearer x" {
		t.Fatalf("请求头解析不对: %+v", cfg.Headers)
	}
}

// 把订阅模板的变量误写到渠道模板里，是最容易犯的错：保存时就要点名，
// 而不是等真出告警时整条发不出去。
func TestValidateRejectsUnknownVars(t *testing.T) {
	cfg := Config{
		URL:          "https://203.0.113.10/hook",
		Method:       "POST",
		ContentType:  "application/json",
		BodyTemplate: `{"a":"{{.Title}}","b":"{{.Domain}}","c":"{{ .Ip | upper }}"}`,
	}
	cfg.normalize()
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("期望校验失败，实际通过")
	}
	for _, want := range []string{"Domain", "Ip", "不存在"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误信息缺少 %q，实际: %v", want, err)
		}
	}
}

// if / range / 管道里的变量也要能被识别出来
func TestCollectUnknownFieldsWalksBranches(t *testing.T) {
	cfg := Config{
		URL:         "https://203.0.113.10/hook",
		Method:      "POST",
		ContentType: "text/plain",
		BodyTemplate: `{{ if .Severity }}{{ .Title }}{{ else }}{{ .NotExist }}{{ end }}` +
			`{{ with .Content }}{{ . }}{{ end }}`,
	}
	cfg.normalize()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "NotExist") {
		t.Fatalf("期望识别出 NotExist，实际: %v", err)
	}
}

// 已入库的老配置（或直接改库）带未知变量时不能让告警消失：渲染成空串照发
func TestRenderBodyTreatsUnknownVarAsEmpty(t *testing.T) {
	n := mustConfig(t, Config{
		URL:          "https://203.0.113.10/hook",
		Method:       "POST",
		ContentType:  "application/json",
		BodyTemplate: `{"a":"{{.Title}}","b":"{{.Domain}}"}`,
	})
	body, err := n.RenderBody(Message{Title: "标题"})
	if err != nil {
		t.Fatalf("不应渲染失败: %v", err)
	}
	var got map[string]string
	if err = json.Unmarshal(body, &got); err != nil {
		t.Fatalf("渲染结果不是合法 JSON: %s", body)
	}
	if got["a"] != "标题" || got["b"] != "" {
		t.Fatalf("未知变量应渲染为空串: %+v", got)
	}
}

// 保存时就该发现括号没配平，不用等到发送
func TestValidateCatchesInvalidJSONAtSaveTime(t *testing.T) {
	cfg := Config{
		URL:          "https://203.0.113.10/hook",
		Method:       "POST",
		ContentType:  "application/json",
		BodyTemplate: `{"title":"{{.Title}}"`,
	}
	cfg.normalize()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "不是合法 JSON") {
		t.Fatalf("期望保存时就报非法 JSON，实际: %v", err)
	}
}
