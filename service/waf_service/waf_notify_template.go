package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"bytes"
	"errors"
	"fmt"
	"html"
	"strings"
	"text/template"
	"time"
)

/*
*
通知消息模板引擎（issue #822）

三条硬约束：

 1. 模板渲染失败绝不能让告警消失 —— 一律降级回内置默认格式，只在日志里标记 custom_fallback。
 2. 模板变量（Url / RuleInfo / UserAgent / Message）是攻击者可控输入，
    直接塞进 Markdown / 邮件 HTML 会破坏排版甚至带出可执行内容，所以按渠道逐个转义 + 截断。
 3. 只用标准库 text/template，不引入任何模板/表达式依赖，
    funcMap 是白名单，不暴露任何 IO 能力。
*/

const (
	notifyVarMaxLen      = 512         // 单个变量最大长度
	notifyRenderMaxBytes = 64 * 1024   // 渲染输出上限
	notifyRenderTimeout  = time.Second // 渲染超时
	notifyContentMaxLen  = 4096        // 最终正文长度上限
	notifyTitleMaxLen    = 200         // 最终标题长度上限
	notifyTruncatedMark  = "...(内容过长已截断)"
)

// notifyTemplateFuncs 模板可用函数白名单
var notifyTemplateFuncs = template.FuncMap{
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

// RenderNotifyMessage 渲染一条通知的标题与正文
//
// 返回 templateUsed 标明本次用的是内置默认还是自定义模板（渲染失败会是 custom_fallback），
// 管理端据此在订阅格子上提示"模板渲染失败"。
func RenderNotifyMessage(sub model.NotifySubscription, channelType string, ev NotifyEvent) (title, content, templateUsed string) {
	title, content, templateUsed = ev.DefaultTitle, ev.DefaultContent, model.TemplateUsedDefault

	titleTpl := strings.TrimSpace(sub.TitleTemplate)
	contentTpl := strings.TrimSpace(sub.ContentTemplate)
	if titleTpl == "" && contentTpl == "" {
		return title, truncateText(content, notifyContentMaxLen), templateUsed
	}

	vars := prepareTemplateVars(channelType, ev)
	templateUsed = model.TemplateUsedCustom

	if titleTpl != "" {
		if rendered, err := renderTemplateSafely("title", titleTpl, vars); err == nil {
			title = rendered
		} else {
			zlog.Warn("通知标题模板渲染失败，已降级为默认格式", "subscription", sub.Id, "error", err.Error())
			templateUsed = model.TemplateUsedFallback
		}
	}
	if contentTpl != "" {
		if rendered, err := renderTemplateSafely("content", contentTpl, vars); err == nil {
			content = rendered
		} else {
			zlog.Warn("通知正文模板渲染失败，已降级为默认格式", "subscription", sub.Id, "error", err.Error())
			templateUsed = model.TemplateUsedFallback
		}
	}

	return truncateText(title, notifyTitleMaxLen), truncateText(content, notifyContentMaxLen), templateUsed
}

// prepareTemplateVars 变量转义 + 截断，得到可安全塞进模板的数据
func prepareTemplateVars(channelType string, ev NotifyEvent) map[string]string {
	out := make(map[string]string, len(ev.Vars))
	for k, v := range ev.Vars {
		out[k] = escapeForChannel(channelType, truncateText(v, notifyVarMaxLen))
	}
	return out
}

// escapeForChannel 按渠道转义变量
//
// 邮件最终会以 HTML 呈现，必须做实体转义；IM 渠道走 Markdown，转义会破坏排版的元字符。
func escapeForChannel(channelType, s string) string {
	if s == "" {
		return s
	}
	switch channelType {
	case "email":
		return html.EscapeString(s)
	default:
		return escapeMarkdown(s)
	}
}

// escapeMarkdown 转义 Markdown 结构字符，防止攻击 payload 把消息排版打乱
//
// 只处理会改变结构的几个字符；不做全量转义，否则正常的 URL 会变得难以阅读。
var markdownEscaper = strings.NewReplacer(
	"`", "'",
	"*", "\\*",
	"_", "\\_",
	"[", "\\[",
	"]", "\\]",
	"\r", " ",
)

func escapeMarkdown(s string) string {
	return markdownEscaper.Replace(s)
}

// truncateText 按字节截断，并保证不切断 UTF-8 字符
func truncateText(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !isUTF8Start(s[cut]) {
		cut--
	}
	return s[:cut] + notifyTruncatedMark
}

func isUTF8Start(b byte) bool {
	return b&0xC0 != 0x80
}

// renderTemplateSafely 带超时与输出上限的模板渲染
func renderTemplateSafely(name, tpl string, vars map[string]string) (string, error) {
	tmpl, err := template.New(name).Funcs(notifyTemplateFuncs).Option("missingkey=zero").Parse(tpl)
	if err != nil {
		return "", fmt.Errorf("模板语法错误: %w", err)
	}

	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: fmt.Errorf("模板渲染 panic: %v", r)}
			}
		}()
		var buf bytes.Buffer
		lw := &limitedWriter{buf: &buf, limit: notifyRenderMaxBytes}
		if execErr := tmpl.Execute(lw, vars); execErr != nil {
			ch <- result{err: execErr}
			return
		}
		ch <- result{out: buf.String()}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return "", r.err
		}
		if strings.TrimSpace(r.out) == "" {
			return "", errors.New("模板渲染结果为空")
		}
		return r.out, nil
	case <-time.After(notifyRenderTimeout):
		return "", errors.New("模板渲染超时")
	}
}

// limitedWriter 输出超过上限即报错，防止模板产出巨量内容
type limitedWriter struct {
	buf     *bytes.Buffer
	limit   int
	written int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		return 0, errors.New("模板渲染输出超出上限")
	}
	w.written += len(p)
	return w.buf.Write(p)
}

// ========== 变量说明表（前端"点击插入变量"用） ==========

// NotifyTemplateVar 模板变量说明
type NotifyTemplateVar struct {
	Name    string `json:"name"`    // 变量名，如 Domain
	Desc    string `json:"desc"`    // 中文说明
	Example string `json:"example"` // 示例值
}

var notifyCommonVars = []NotifyTemplateVar{
	{Name: "Time", Desc: "事件时间", Example: "2026-08-05 10:00:00"},
	{Name: "ServerName", Desc: "本机名称", Example: "SamWaf"},
	{Name: "MessageTypeName", Desc: "消息类型名称", Example: "攻击信息"},
	{Name: "Severity", Desc: "严重级别", Example: "critical"},
}

var notifyTypeVars = map[string][]NotifyTemplateVar{
	model.MSG_TYPE_RULE_TRIGGER: {
		{Name: "OperaType", Desc: "操作类型", Example: "命中保护规则"},
		{Name: "Server", Desc: "服务器", Example: "samwaf-01"},
		{Name: "Domain", Desc: "域名", Example: "www.example.com"},
		{Name: "RuleInfo", Desc: "规则信息", Example: "SQL注入检测"},
		{Name: "Ip", Desc: "来源IP", Example: "1.2.3.4"},
	},
	model.MSG_TYPE_ATTACK_INFO: {
		{Name: "AttackType", Desc: "攻击类型", Example: "SQL注入"},
		{Name: "Url", Desc: "攻击URL", Example: "https://www.example.com/api?id=1"},
		{Name: "Ip", Desc: "攻击IP", Example: "1.2.3.4"},
	},
	model.MSG_TYPE_IP_BAN: {
		{Name: "Ip", Desc: "被封禁IP", Example: "1.2.3.4"},
		{Name: "Reason", Desc: "封禁原因", Example: "CC攻击"},
		{Name: "Duration", Desc: "封禁时长(分钟)", Example: "30"},
		{Name: "Remaining", Desc: "剩余时间", Example: "29分30秒"},
	},
	model.MSG_TYPE_SSL_EXPIRE: {
		{Name: "Domain", Desc: "域名", Example: "www.example.com"},
		{Name: "ExpireTime", Desc: "过期时间", Example: "2026-09-01 00:00:00"},
		{Name: "DaysLeft", Desc: "剩余天数", Example: "7"},
	},
	model.MSG_TYPE_USER_LOGIN: {
		{Name: "Username", Desc: "用户名", Example: "admin"},
		{Name: "Ip", Desc: "登录IP", Example: "192.168.1.10"},
	},
	model.MSG_TYPE_WEEKLY_REPORT: {
		{Name: "TotalRequests", Desc: "总请求数", Example: "120000"},
		{Name: "BlockedRequests", Desc: "拦截请求数", Example: "356"},
		{Name: "BlockRate", Desc: "拦截率", Example: "0.30%"},
		{Name: "WeekRange", Desc: "统计周期", Example: "2026-07-29 ~ 2026-08-04"},
	},
	model.MSG_TYPE_SYSTEM_ERROR: {
		{Name: "ErrorType", Desc: "错误类型", Example: "数据库连接失败"},
		{Name: "ErrorMsg", Desc: "错误信息", Example: "connection refused"},
	},
	model.MSG_TYPE_OPERATION_NOTICE: {
		{Name: "OperaType", Desc: "操作类型", Example: "新增网站"},
		{Name: "Server", Desc: "服务器", Example: "samwaf-01"},
		{Name: "OperaCnt", Desc: "操作内容", Example: "www.example.com"},
	},
	model.MSG_TYPE_ACCESS_LOGIN: {
		{Name: "EventName", Desc: "事件名称", Example: "访问认证登录成功"},
		{Name: "AccountName", Desc: "访问账号", Example: "zhangsan"},
		{Name: "Host", Desc: "访问域名", Example: "oa.example.com"},
		{Name: "Url", Desc: "访问地址", Example: "https://oa.example.com/"},
		{Name: "Ip", Desc: "来源IP", Example: "1.2.3.4"},
		{Name: "Location", Desc: "IP归属地", Example: "浙江杭州"},
		{Name: "Message", Desc: "事件详情", Example: "登录成功"},
	},
}

// GetNotifyTemplateVars 取某消息类型可用的模板变量（公共变量 + 类型专属变量）
func GetNotifyTemplateVars(messageType string) []NotifyTemplateVar {
	vars := make([]NotifyTemplateVar, 0, 12)
	vars = append(vars, notifyCommonVars...)
	if messageType == model.MSG_TYPE_ACCESS_ABNORMAL {
		messageType = model.MSG_TYPE_ACCESS_LOGIN // 两者变量集合一致
	}
	if typeVars, ok := notifyTypeVars[messageType]; ok {
		vars = append(vars, typeVars...)
	}
	return vars
}

// ========== 样例事件（预览 / 测试发送 / 干跑 用） ==========

// SampleNotifyEvent 按消息类型构造一条样例事件
//
// 预览和测试都必须用真实的渲染链路，否则"预览没问题、真发出去是乱的"就毫无意义。
func SampleNotifyEvent(messageType string) NotifyEvent {
	ev := NotifyEvent{
		MessageType:     messageType,
		MessageTypeName: GetMessageTypeName(messageType),
		Severity:        GetMessageTypeSeverity(messageType),
		Time:            time.Now(),
		Vars:            map[string]string{},
		DedupParts:      map[string]string{model.DedupKeyMessageType: messageType},
	}
	for _, v := range GetNotifyTemplateVars(messageType) {
		ev.Vars[v.Name] = v.Example
	}
	ev.Vars["Time"] = ev.Time.Format("2006-01-02 15:04:05")
	ev.Vars["MessageType"] = messageType

	if d := ev.Vars["Domain"]; d != "" {
		ev.DedupParts[model.DedupKeyDomain] = d
	}
	if ip := ev.Vars["Ip"]; ip != "" {
		ev.DedupParts[model.DedupKeyIp] = ip
	}

	ev.DefaultTitle, ev.DefaultContent = buildSampleDefaultMessage(messageType, ev.Vars)
	return ev
}

// buildSampleDefaultMessage 用样例变量拼出内置默认格式的标题与正文
func buildSampleDefaultMessage(messageType string, vars map[string]string) (string, string) {
	s := WafNotifySenderServiceApp
	switch messageType {
	case model.MSG_TYPE_RULE_TRIGGER:
		return "安全规则触发通知", fmt.Sprintf("**操作类型:** %s\n\n**服务器:** %s\n\n**域名:** %s\n\n**规则信息:** %s\n\n**IP地址:** %s",
			vars["OperaType"], vars["Server"], vars["Domain"], vars["RuleInfo"], vars["Ip"])
	case model.MSG_TYPE_OPERATION_NOTICE:
		return "操作通知", fmt.Sprintf("**操作类型:** %s\n\n**服务器:** %s\n\n**操作内容:** %s",
			vars["OperaType"], vars["Server"], vars["OperaCnt"])
	case model.MSG_TYPE_USER_LOGIN:
		title, content := s.FormatUserLoginMessage(vars["Username"], vars["Ip"], vars["Time"])
		return title, content
	case model.MSG_TYPE_ATTACK_INFO:
		title, content := s.FormatAttackInfoMessage(vars["AttackType"], vars["Url"], vars["Ip"], vars["Time"])
		return title, content
	case model.MSG_TYPE_WEEKLY_REPORT:
		title, content := s.FormatWeeklyReportMessage(120000, 356, vars["WeekRange"])
		return title, content
	case model.MSG_TYPE_SSL_EXPIRE:
		title, content := s.FormatSSLExpireMessage(vars["Domain"], vars["ExpireTime"], 7)
		return title, content
	case model.MSG_TYPE_SYSTEM_ERROR:
		title, content := s.FormatSystemErrorMessage(vars["ErrorType"], vars["ErrorMsg"], vars["Time"])
		return title, content
	case model.MSG_TYPE_IP_BAN:
		title, content := s.FormatIPBanMessage(vars["Ip"], vars["Reason"], vars["Time"], 30, 1770)
		return title, content
	case model.MSG_TYPE_ACCESS_LOGIN, model.MSG_TYPE_ACCESS_ABNORMAL:
		title := "统一访问认证登录通知"
		if messageType == model.MSG_TYPE_ACCESS_ABNORMAL {
			title = "统一访问认证异常告警"
		}
		return title, fmt.Sprintf("**事件:** %s\n\n**账号:** %s\n\n**来源IP:** %s\n\n**归属地:** %s\n\n**访问域名:** %s\n\n**时间:** %s",
			vars["EventName"], vars["AccountName"], vars["Ip"], vars["Location"], vars["Host"], vars["Time"])
	}
	return GetMessageTypeName(messageType), "这是一条来自 SamWaf 的测试通知"
}
