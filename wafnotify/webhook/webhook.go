package webhook

import (
	"SamWaf/utils"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"text/template/parse"
)

/*
*
通用 Webhook 通知渠道（issue #693）

内置的钉钉/飞书/企业微信只能覆盖固定几家，用户自建的告警平台（Slack、Telegram、Bark、
ntfy、Gotify、内部工单系统…）报文格式各不相同，所以这里把「地址 + 方法 + 请求头 + 报文模板」
全部交给用户定义。

三条硬约束：

 1. 用户可控的对外地址一律走 IsSafeOutboundURL + SafeHTTPClient，跳转链上每一跳都重新校验，
    否则这就是一个现成的 SSRF 打内网的入口。
 2. 自定义请求头是拼进 HTTP 报文的原始数据：头名必须是 RFC token，头值不得含 CR/LF，
    并且禁止覆盖 Host/Content-Length/Transfer-Encoding 这类由传输层决定的头（请求走私）。
 3. 模板变量（Title/Content）里含攻击者可控内容，塞进 JSON 报文前必须按 Content-Type 转义，
    否则一个带引号的 URL 就能把报文打成非法 JSON，告警直接发不出去。
*/

const (
	// MaxHeaders 自定义请求头数量上限
	MaxHeaders = 20
	// MaxHeaderKeyLen 单个头名长度上限
	MaxHeaderKeyLen = 128
	// MaxHeaderValueLen 单个头值长度上限
	MaxHeaderValueLen = 2048
	// MaxBodyTemplateLen Body 模板长度上限
	MaxBodyTemplateLen = 64 * 1024
	// MaxBodyBytes 渲染后报文体积上限
	MaxBodyBytes = 256 * 1024
	// maxRespSnippet 错误信息里回显的响应片段长度
	maxRespSnippet = 512

	// DefaultMethod 默认请求方法
	DefaultMethod = "POST"
	// DefaultContentType 默认报文类型
	DefaultContentType = "application/json"
)

// allowedMethods 允许的请求方法白名单
var allowedMethods = map[string]bool{
	"POST": true, "PUT": true, "PATCH": true, "GET": true, "DELETE": true,
}

// forbiddenHeaders 禁止用户覆盖的请求头
//
// 这些头由 http.Transport 自己决定，放开会造成请求走私，或把请求实际打到别的主机上，
// 绕过前面刚做完的 SSRF 校验。
var forbiddenHeaders = map[string]bool{
	"host":                true,
	"content-length":      true,
	"transfer-encoding":   true,
	"connection":          true,
	"upgrade":             true,
	"expect":              true,
	"proxy-connection":    true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
}

// Header 一条自定义请求头
type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Config 通用 Webhook 渠道配置（存放于 NotifyChannel.ConfigJSON）
type Config struct {
	URL          string   `json:"url"`
	Method       string   `json:"method"`
	ContentType  string   `json:"content_type"`
	Headers      []Header `json:"headers"`
	BodyTemplate string   `json:"body_template"`
}

// Message 供 Body 模板使用的变量集合
//
// 字段名即模板变量名：{{.Title}} {{.Content}} …… 与订阅级模板引擎保持同一套语法，
// 用户不用记两种写法。
//
// 注意与「订阅级消息模板」的分工：订阅模板负责把域名/攻击IP/规则信息这些细节
// 渲染成一段文案，渲染结果就是这里的 Title / Content；渠道模板只负责报文外壳
// （对端要什么字段名）。两层不冲突，但订阅模板的变量在这里是不存在的。
type Message struct {
	Title           string `json:"title"`
	Content         string `json:"content"`
	Time            string `json:"time"`
	MessageType     string `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	Severity        string `json:"severity"`
	ServerName      string `json:"server_name"`
}

// VarNames Body 模板可用的变量名（顺序与前端变量标签一致）
func VarNames() []string {
	return []string{"Title", "Content", "Time", "MessageType", "MessageTypeName", "Severity", "ServerName"}
}

// toVars 转成模板数据
//
// 用 map 而不是结构体：配合 missingkey=zero，写错的变量渲染成空串而不是执行报错。
// 告警场景下"少一个字段"远好于"整条发不出去"，写错变量的兜底在保存时校验（见 Validate）。
func (m Message) toVars() map[string]string {
	return map[string]string{
		"Title":           m.Title,
		"Content":         m.Content,
		"Time":            m.Time,
		"MessageType":     m.MessageType,
		"MessageTypeName": m.MessageTypeName,
		"Severity":        m.Severity,
		"ServerName":      m.ServerName,
	}
}

// sampleMessage 保存时干跑用的样例数据
func sampleMessage() Message {
	return Message{
		Title:           "SamWaf 测试通知",
		Content:         "这是一条用于校验模板的样例正文",
		Time:            "2026-01-01 00:00:00",
		MessageType:     "rule_trigger",
		MessageTypeName: "规则触发",
		Severity:        "warn",
		ServerName:      "SamWaf",
	}
}

// templateFuncs 模板可用函数白名单（与订阅级模板引擎一致，不暴露任何 IO 能力）
var templateFuncs = template.FuncMap{
	"default": func(def, s string) string {
		if strings.TrimSpace(s) == "" {
			return def
		}
		return s
	},
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"truncate": func(n int, s string) string {
		if n <= 0 || len(s) <= n {
			return s
		}
		return s[:n] + "..."
	},
	"contains": strings.Contains,
}

// WebhookNotifier 通用 Webhook 通知器
type WebhookNotifier struct {
	Config Config
}

// NewWebhookNotifier 从 ConfigJSON 构造通知器（会做完整校验）
func NewWebhookNotifier(configJSON string) (*WebhookNotifier, error) {
	cfg, err := ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	return &WebhookNotifier{Config: *cfg}, nil
}

// ParseConfig 解析并规范化配置
func ParseConfig(configJSON string) (*Config, error) {
	if strings.TrimSpace(configJSON) == "" {
		return nil, errors.New("Webhook 配置不能为空")
	}
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("解析 Webhook 配置失败: %v", err)
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// normalize 补默认值、去空白
func (c *Config) normalize() {
	c.URL = strings.TrimSpace(c.URL)
	c.Method = strings.ToUpper(strings.TrimSpace(c.Method))
	if c.Method == "" {
		c.Method = DefaultMethod
	}
	c.ContentType = strings.TrimSpace(c.ContentType)
	if c.ContentType == "" {
		c.ContentType = DefaultContentType
	}

	headers := make([]Header, 0, len(c.Headers))
	for _, h := range c.Headers {
		key := strings.TrimSpace(h.Key)
		if key == "" {
			continue // 前端"添加一行"留下的空行直接丢掉，不当成错误
		}
		headers = append(headers, Header{Key: key, Value: strings.TrimSpace(h.Value)})
	}
	c.Headers = headers
}

// Validate 配置校验（新增/编辑保存时与发送时都会调用）
func (c *Config) Validate() error {
	if c.URL == "" {
		return errors.New("Webhook 地址不能为空")
	}
	if ok, reason := utils.IsSafeOutboundURL(c.URL); !ok {
		return fmt.Errorf("Webhook 地址不被允许: %s", reason)
	}
	if !allowedMethods[c.Method] {
		return fmt.Errorf("不支持的请求方法: %s", c.Method)
	}
	if len(c.ContentType) > MaxHeaderValueLen || containsCTL(c.ContentType) {
		return errors.New("Content-Type 非法")
	}
	if len(c.Headers) > MaxHeaders {
		return fmt.Errorf("自定义请求头最多 %d 条", MaxHeaders)
	}
	seen := make(map[string]bool, len(c.Headers))
	for _, h := range c.Headers {
		if err := validateHeader(h); err != nil {
			return err
		}
		lower := strings.ToLower(h.Key)
		if seen[lower] {
			return fmt.Errorf("请求头 %s 重复", h.Key)
		}
		seen[lower] = true
	}
	if len(c.BodyTemplate) > MaxBodyTemplateLen {
		return fmt.Errorf("Body 模板长度超过 %d 字节上限", MaxBodyTemplateLen)
	}
	if strings.TrimSpace(c.BodyTemplate) != "" {
		tmpl, err := template.New("webhook_body").Funcs(templateFuncs).
			Option("missingkey=zero").Parse(c.BodyTemplate)
		if err != nil {
			return fmt.Errorf("Body 模板语法错误: %v", err)
		}
		// 把订阅模板的变量（{{.Domain}} {{.Ip}} …）误写到这里是最容易犯的错，
		// 保存时就点名指出来，别等到真出告警才发现报文里少了东西
		if unknown := collectUnknownFields(tmpl); len(unknown) > 0 {
			return fmt.Errorf("Body 模板里的变量 %s 不存在。本处可用变量：%s；"+
				"域名、攻击IP、规则信息等细节属于「通知订阅」的消息模板，会被渲染进 {{.Content}}",
				strings.Join(unknown, "、"), strings.Join(VarNames(), " "))
		}
		// 干跑一次：括号/引号没配平这类问题当场报出来
		probe := &WebhookNotifier{Config: *c}
		if _, err = probe.RenderBody(sampleMessage()); err != nil {
			return err
		}
	}
	return nil
}

// collectUnknownFields 遍历模板语法树，挑出不在 VarNames() 里的变量名
//
// 走语法树而不是正则：{{ if .Foo }}、{{ .Foo | upper }} 这类写法正则很难覆盖全。
func collectUnknownFields(tmpl *template.Template) []string {
	known := make(map[string]bool, 8)
	for _, name := range VarNames() {
		known[name] = true
	}

	seen := make(map[string]bool)
	var unknown []string
	var walk func(n parse.Node)
	walk = func(n parse.Node) {
		switch node := n.(type) {
		case *parse.ListNode:
			if node == nil {
				return
			}
			for _, child := range node.Nodes {
				walk(child)
			}
		case *parse.ActionNode:
			walk(node.Pipe)
		case *parse.PipeNode:
			if node == nil {
				return
			}
			for _, cmd := range node.Cmds {
				walk(cmd)
			}
		case *parse.CommandNode:
			for _, arg := range node.Args {
				walk(arg)
			}
		case *parse.IfNode:
			walk(node.Pipe)
			walk(node.List)
			walk(node.ElseList)
		case *parse.RangeNode:
			walk(node.Pipe)
			walk(node.List)
			walk(node.ElseList)
		case *parse.WithNode:
			walk(node.Pipe)
			walk(node.List)
			walk(node.ElseList)
		case *parse.TemplateNode:
			walk(node.Pipe)
		case *parse.ChainNode:
			walk(node.Node)
		case *parse.FieldNode:
			name := node.Ident[0]
			if !known[name] && !seen[name] {
				seen[name] = true
				unknown = append(unknown, name)
			}
		}
	}
	if tmpl.Tree != nil {
		walk(tmpl.Tree.Root)
	}
	return unknown
}

// validateHeader 单条请求头校验
func validateHeader(h Header) error {
	if len(h.Key) > MaxHeaderKeyLen {
		return fmt.Errorf("请求头名称过长: %s", truncateForErr(h.Key))
	}
	if !isValidHeaderToken(h.Key) {
		return fmt.Errorf("请求头名称非法: %s", truncateForErr(h.Key))
	}
	if forbiddenHeaders[strings.ToLower(h.Key)] {
		return fmt.Errorf("请求头 %s 由系统控制，不允许自定义", h.Key)
	}
	if len(h.Value) > MaxHeaderValueLen {
		return fmt.Errorf("请求头 %s 的值过长", h.Key)
	}
	if containsCTL(h.Value) {
		// 头值里的 CR/LF 是最典型的 HTTP 响应/请求拆分手法，必须在入口就挡掉
		return fmt.Errorf("请求头 %s 的值包含非法控制字符", h.Key)
	}
	return nil
}

// isValidHeaderToken 头名是否为 RFC 7230 token
func isValidHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// containsCTL 是否含控制字符（含 CR/LF/NUL）
func containsCTL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func truncateForErr(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

// SendMarkdown 与其他渠道保持一致的调用形态（只有标题正文时使用）
func (w *WebhookNotifier) SendMarkdown(title, content string) error {
	return w.Send(Message{Title: title, Content: content})
}

// Send 渲染报文并投递
func (w *WebhookNotifier) Send(msg Message) error {
	// 配置可能是很久以前存下的（甚至被直接改过库），发送前重新校验一次目标地址
	if ok, reason := utils.IsSafeOutboundURL(w.Config.URL); !ok {
		return fmt.Errorf("Webhook 地址不被允许: %s", reason)
	}

	body, err := w.RenderBody(msg)
	if err != nil {
		return err
	}

	var reader io.Reader
	if w.Config.Method != http.MethodGet && len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(w.Config.Method, w.Config.URL, reader)
	if err != nil {
		return fmt.Errorf("构造请求失败: %v", err)
	}
	if reader != nil {
		req.Header.Set("Content-Type", w.Config.ContentType)
	}
	req.Header.Set("User-Agent", "SamWaf-Notify")
	// 用户自定义头放最后，允许覆盖上面两个默认头（Content-Type / User-Agent）
	for _, h := range w.Config.Headers {
		req.Header.Set(h.Key, h.Value)
	}

	resp, err := utils.SafeHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 响应体只读一小段用于报错，避免对端返回巨量内容把内存吃满
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespSnippet))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := strings.TrimSpace(string(respBody))
		if snippet == "" {
			return fmt.Errorf("Webhook 返回状态码 %d", resp.StatusCode)
		}
		return fmt.Errorf("Webhook 返回状态码 %d: %s", resp.StatusCode, snippet)
	}
	return nil
}

// RenderBody 按 Content-Type 转义变量后渲染 Body 模板
func (w *WebhookNotifier) RenderBody(msg Message) ([]byte, error) {
	tpl := strings.TrimSpace(w.Config.BodyTemplate)
	if tpl == "" {
		return w.defaultBody(msg)
	}

	tmpl, err := template.New("webhook_body").Funcs(templateFuncs).
		Option("missingkey=zero").Parse(w.Config.BodyTemplate)
	if err != nil {
		return nil, fmt.Errorf("Body 模板语法错误: %v", err)
	}

	var buf bytes.Buffer
	lw := &limitedWriter{buf: &buf, limit: MaxBodyBytes}
	if err = tmpl.Execute(lw, escapeMessage(w.Config.ContentType, msg).toVars()); err != nil {
		return nil, fmt.Errorf("Body 模板渲染失败: %v", err)
	}

	out := buf.Bytes()
	if isJSONContentType(w.Config.ContentType) && !json.Valid(out) {
		// 这里报错而不是硬发出去：对端收到非法 JSON 只会回 400，用户对着日志更难定位
		return nil, errors.New("Body 模板渲染后不是合法 JSON，请检查括号与引号")
	}
	return out, nil
}

// defaultBody 未配置模板时的默认报文
func (w *WebhookNotifier) defaultBody(msg Message) ([]byte, error) {
	if isJSONContentType(w.Config.ContentType) {
		b, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("序列化默认报文失败: %v", err)
		}
		return b, nil
	}
	return []byte(msg.Title + "\n\n" + msg.Content), nil
}

// escapeMessage 按报文类型逐字段转义
//
// 绝大多数场景是「把变量塞进 JSON 字符串里」，正文里的换行和引号不转义就会打碎报文。
func escapeMessage(contentType string, msg Message) Message {
	esc := func(s string) string { return escapeValue(contentType, s) }
	return Message{
		Title:           esc(msg.Title),
		Content:         esc(msg.Content),
		Time:            esc(msg.Time),
		MessageType:     esc(msg.MessageType),
		MessageTypeName: esc(msg.MessageTypeName),
		Severity:        esc(msg.Severity),
		ServerName:      esc(msg.ServerName),
	}
}

func escapeValue(contentType, s string) string {
	if s == "" {
		return s
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json"):
		return jsonStringInner(s)
	case strings.Contains(ct, "x-www-form-urlencoded"):
		return url.QueryEscape(s)
	case strings.Contains(ct, "xml"), strings.Contains(ct, "html"):
		return xmlEscaper.Replace(s)
	default:
		return s
	}
}

var xmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"\"", "&quot;",
	"'", "&apos;",
)

// jsonStringInner 取 JSON 字符串字面量去掉首尾引号后的内容
func jsonStringInner(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return ""
	}
	return string(b[1 : len(b)-1])
}

func isJSONContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "json")
}

// limitedWriter 输出超过上限即报错，防止模板产出巨量报文
type limitedWriter struct {
	buf     *bytes.Buffer
	limit   int
	written int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		return 0, errors.New("渲染报文超出体积上限")
	}
	w.written += len(p)
	return w.buf.Write(p)
}
