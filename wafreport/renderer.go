package wafreport

import (
	"SamWaf/model"
	"context"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

type HTMLRenderer struct{ template *template.Template }

func NewHTMLRenderer() *HTMLRenderer {
	funcs := template.FuncMap{
		"date":          reportDate,
		"label":         safeReportLabel,
		"auditCategory": reportAuditCategory,
		"auditEvent":    reportAuditEvent,
		"auditResult":   reportAuditResult,
		"available":     func(s State) bool { return s == OK || s == Partial },
		"isOK":          func(s State) bool { return s == OK },
		"average": func(v *float64) string {
			if v == nil {
				return "—"
			}
			return fmt.Sprintf("%.2f", *v)
		},
		"delta": reportDelta,
		"cmp": func(cs, ps State, cur, prev int64) template.HTML {
			if cs == OK && ps == OK {
				return reportDelta(cur, prev)
			}
			return "—"
		},
	}
	return &HTMLRenderer{template: template.Must(template.New("report").Funcs(funcs).Parse(reportHTML))}
}

type reportView struct {
	Report
	Text  map[string]string
	Ranks []rankView
}
type rankView struct {
	Title string
	Section[[]Rank]
}

func (h *HTMLRenderer) Render(ctx context.Context, out io.Writer, report Report) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := report.Request.Validate(); err != nil {
		return err
	}
	text := reportZH
	if report.Request.Locale == "en-US" {
		text = reportEN
	}
	view := reportView{Report: report, Text: text, Ranks: []rankView{
		{text["top_ips"], report.TopIPs}, {text["top_rules"], report.TopRules},
		{text["top_paths"], report.TopPaths}, {text["top_regions"], report.TopRegions},
	}}
	return h.template.Execute(contextReportWriter{ctx, out}, view)
}

type contextReportWriter struct {
	context.Context
	io.Writer
}

func (w contextReportWriter) Write(p []byte) (int, error) {
	if err := w.Err(); err != nil {
		return 0, err
	}
	return w.Writer.Write(p)
}

func reportDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04:05 MST -07:00")
}

func safeReportLabel(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	runes := []rune(s)
	if len(runes) > 200 {
		s = string(runes[:200]) + "…"
	}
	return s
}

func reportAuditCategory(text map[string]string, category string) string {
	if name := text["audit_category_"+category]; name != "" {
		return name
	}
	return text["unknown_category"]
}

func reportAuditEvent(locale, event string) string {
	if locale == "en-US" {
		if name := reportAuditEN[event]; name != "" {
			return name
		}
		return reportEN["unknown_event"]
	}
	if name := model.AccessEventNames[event]; name != "" {
		return name
	}
	return reportZH["unknown_event"]
}

func reportAuditResult(text map[string]string, result int) string {
	switch result {
	case model.AccessAuditOK:
		return text["audit_success"]
	case model.AccessAuditFail:
		return text["audit_failure"]
	default:
		return text["unknown"]
	}
}

var reportAuditEN = map[string]string{
	model.AccessEventLoginOK:             "Login succeeded",
	model.AccessEventLoginFail:           "Incorrect password",
	model.AccessEventOtpFail:             "Incorrect verification code",
	model.AccessEventLocked:              "Login attempt limit reached",
	model.AccessEventLogout:              "Logged out",
	model.AccessEventKick:                "Session ended by administrator",
	model.AccessEventTicketIssue:         "Cross-site ticket issued",
	model.AccessEventTicketConsume:       "Ticket redeemed",
	model.AccessEventTicketReplay:        "Ticket rejected",
	model.AccessEventBadReturnTo:         "Invalid return address",
	model.AccessEventDenied:              "Unauthenticated access blocked",
	model.AccessEventBypassIP:            "IP exemption applied",
	model.AccessEventBypassToken:         "Service token accepted",
	model.AuditEventConfigSSLExportWrite: "SSL certificate exported",
	model.AuditEventConfigBatchTaskRun:   "Batch task execution",
	model.AuditEventConfigDiagPackage:    "Diagnostic package download",
	model.AuditEventConfigLogExport:      "Log export",
	model.AuditEventConfigReport:         "Security operations report",
	model.HttpAuthEventLoginOK:           "Site password login succeeded",
	model.HttpAuthEventLoginFail:         "Incorrect site password",
	model.HttpAuthEventLocked:            "Site login attempt limit reached",
	model.HttpAuthEventKick:              "Site session ended by administrator",
	model.HttpAuthEventExpired:           "Site session expired",
	model.HttpAuthEventDenied:            "Site login required",
	model.AuditEventAppAdd:               "Application added",
	model.AuditEventAppEdit:              "Application updated",
	model.AuditEventAppDel:               "Application deleted",
	model.AuditEventAppStart:             "Application started",
	model.AuditEventAppStop:              "Application stopped",
	model.AuditEventAppRestart:           "Application restarted",
	model.AuditEventAppUpload:            "Application file uploaded",
	model.AuditEventAppUpgrade:           "Application upgraded",
	model.AuditEventAppRollback:          "Application rolled back",
	model.AuditEventAppClearLogs:         "Application logs cleared",
	model.AuditEventAppOpDenied:          "Application operation denied",
}

// 百分比 HTML 仅包含整数计算结果。
func reportDelta(current, previous int64) template.HTML {
	if previous == 0 {
		return "—"
	}
	return template.HTML(fmt.Sprintf("%+.1f%%", (float64(current)-float64(previous))/float64(previous)*100))
}

var reportZH = map[string]string{
	"title":                               "安全运营报告",
	"daily":                               "日报",
	"weekly":                              "周报",
	"monthly":                             "月报",
	"id":                                  "报告编号",
	"generated":                           "生成时间",
	"range":                               "统计区间（含开始、不含结束）",
	"status":                              "数据状态",
	"summary":                             "全实例概览与前周期比较",
	"metric":                              "指标",
	"current":                             "本周期",
	"previous":                            "前一自然周期",
	"change":                              "较前周期",
	"requests":                            "请求数",
	"blocked":                             "阻止请求数",
	"allowed":                             "非阻止请求数",
	"in":                                  "入站流量（字节）",
	"out":                                 "出站流量（字节）",
	"average":                             "加权平均响应时间（毫秒）",
	"ips":                                 "区间去重 IP",
	"blocked_ips":                         "区间阻止 IP 去重数",
	"trend":                               "趋势（日报按小时，周报/月报按天）",
	"time":                                "时间",
	"name":                                "项目",
	"count":                               "数量",
	"top_ips":                             "阻止请求 TOP IP",
	"top_rules":                           "规则命中 TOP（含放行与验证）",
	"top_paths":                           "阻止请求 TOP 路径模板",
	"top_regions":                         "阻止请求 TOP 地域",
	"actions":                             "实际动作分布",
	"audit":                               "安全审计计数",
	"category":                            "分类",
	"event":                               "事件",
	"result":                              "结果",
	"audit_success":                       "成功",
	"audit_failure":                       "失败",
	"audit_category_access":               "访问认证",
	"audit_category_config":               "配置操作",
	"audit_category_httpauth":             "网站密码访问",
	"audit_category_app":                  "应用管理",
	"unknown_category":                    "其他分类",
	"unknown_event":                       "其他事件",
	"snapshot":                            "生成时的当前配置与运行快照",
	"snapshot_note":                       "此处是采集时的当前状态，不代表报告区间内的历史状态。",
	"version":                             "后端 / 前端版本",
	"log_mode":                            "访问日志存储模式",
	"sites":                               "网站配置",
	"enabled":                             "网站启用",
	"guard":                               "防御启用",
	"log_only":                            "仅记录",
	"certificate_name":                    "证书名称 / 主题",
	"domains":                             "证书域名",
	"certificates":                        "证书有效期",
	"valid_from":                          "有效期开始",
	"valid_to":                            "有效期结束",
	"yes":                                 "是",
	"no":                                  "否",
	"ok":                                  "可用",
	"no_data":                             "无数据",
	"failed":                              "采集失败",
	"partial":                             "部分可用",
	"unavailable":                         "不可用",
	"valid":                               "有效",
	"expired":                             "已过期",
	"expiring":                            "30 天内到期",
	"unknown":                             "未知",
	"not_yet_valid":                       "尚未生效",
	"notes":                               "统计口径与数据边界",
	"method":                              "请求、响应时间、IP 与榜单来自统计表；流量来自独立字节计量，不随明细日志过滤。阻止动作仅按实际值“阻止”计数。平均响应时间为总耗时除以总请求数。",
	"boundary":                            "只查询统计表、安全审计计数及当前配置，不读取请求明细。规则榜单是规则命中次数，路径榜单是归一化路径的阻止次数。审计为写入条数，部分事件在写入时节流，不能作为原始尝试次数。",
	"missing":                             "缺失数据不补零；无数据与查询失败分开显示。前周期缺失或基数为零时不计算百分比。小时统计保留时间有限，历史日报的小时趋势可能不可用。报告不推断同比、处理闭环或历史名单规模。",
	"summary_query_failed":                "站点汇总读取失败",
	"ip_query_failed":                     "IP 汇总读取失败",
	"action_query_failed":                 "动作分布读取失败",
	"trend_query_failed":                  "趋势读取失败",
	"ranking_query_failed":                "榜单读取失败",
	"audit_query_failed":                  "审计计数读取失败",
	"site_snapshot_failed":                "网站配置读取失败",
	"certificate_snapshot_failed":         "证书配置读取失败",
	"hourly_retention_or_missing":         "小时统计已过保留期或尚无小时数据",
	"missing_buckets_not_zero_filled":     "部分时间桶没有记录，未填充为零",
	"audit_rows_include_write_throttling": "计数按实际审计行统计，包含写入侧节流影响",
	"no_note":                             "—",
}
var reportEN = map[string]string{
	"title":                               "Security Operations Report",
	"daily":                               "Daily",
	"weekly":                              "Weekly",
	"monthly":                             "Monthly",
	"id":                                  "Report ID",
	"generated":                           "Generated",
	"range":                               "Period [start, end)",
	"status":                              "Data status",
	"summary":                             "Instance summary and previous calendar period",
	"metric":                              "Metric",
	"current":                             "Current",
	"previous":                            "Previous calendar period",
	"change":                              "Change",
	"requests":                            "Requests",
	"blocked":                             "Blocked requests",
	"allowed":                             "Non-blocked requests",
	"in":                                  "Inbound traffic (bytes)",
	"out":                                 "Outbound traffic (bytes)",
	"average":                             "Weighted average response time (ms)",
	"ips":                                 "Distinct IPs in period",
	"blocked_ips":                         "Distinct blocked IPs in period",
	"trend":                               "Trend (hourly for daily, daily for weekly/monthly)",
	"time":                                "Time",
	"name":                                "Item",
	"count":                               "Count",
	"top_ips":                             "Top IPs by blocked requests",
	"top_rules":                           "Top rule matches (including allow and verification)",
	"top_paths":                           "Top normalized paths by blocked requests",
	"top_regions":                         "Top regions by blocked requests",
	"actions":                             "Observed action distribution",
	"audit":                               "Security audit counts",
	"category":                            "Category",
	"event":                               "Event",
	"result":                              "Result",
	"audit_success":                       "Success",
	"audit_failure":                       "Failure",
	"audit_category_access":               "Access authentication",
	"audit_category_config":               "Configuration operations",
	"audit_category_httpauth":             "Site password access",
	"audit_category_app":                  "Application management",
	"unknown_category":                    "Other category",
	"unknown_event":                       "Other event",
	"snapshot":                            "Current configuration and runtime snapshot",
	"snapshot_note":                       "This is the state at collection time, not the historical state during the report period.",
	"version":                             "Backend / frontend version",
	"log_mode":                            "Access log storage mode",
	"sites":                               "Site configuration",
	"enabled":                             "Site enabled",
	"guard":                               "Protection enabled",
	"log_only":                            "Log only",
	"certificate_name":                    "Certificate name / subject",
	"domains":                             "Certificate domains",
	"certificates":                        "Certificate validity",
	"valid_from":                          "Valid from",
	"valid_to":                            "Valid until",
	"yes":                                 "Yes",
	"no":                                  "No",
	"ok":                                  "Available",
	"no_data":                             "No data",
	"failed":                              "Collection failed",
	"partial":                             "Partially available",
	"unavailable":                         "Unavailable",
	"valid":                               "Valid",
	"expired":                             "Expired",
	"expiring":                            "Expires within 30 days",
	"unknown":                             "Unknown",
	"not_yet_valid":                       "Not yet valid",
	"notes":                               "Measurement and data boundaries",
	"method":                              "Requests, response times, IPs and rankings come from aggregate tables. Traffic uses independent byte counters and is unaffected by request log filtering. Only the observed action value 阻止 is counted as blocked. Average response time is total elapsed time divided by total requests.",
	"boundary":                            "Only aggregates, security audit counts and current configuration are queried. Request details are not read. Rule rankings count all rule matches; path rankings count blocked requests by normalized path. Audits count stored rows; write throttling means they do not represent raw attempts.",
	"missing":                             "Missing data is not filled with zero. Empty results and collection failures are shown separately. Percentage changes require available periods and a nonzero baseline. Hourly aggregates have limited retention, so historical daily trends may be unavailable. No year-over-year, remediation or historical list-size claims are inferred.",
	"summary_query_failed":                "Site aggregate query failed",
	"ip_query_failed":                     "IP aggregate query failed",
	"action_query_failed":                 "Action query failed",
	"trend_query_failed":                  "Trend query failed",
	"ranking_query_failed":                "Ranking query failed",
	"audit_query_failed":                  "Audit query failed",
	"site_snapshot_failed":                "Site snapshot failed",
	"certificate_snapshot_failed":         "Certificate snapshot failed",
	"hourly_retention_or_missing":         "Hourly data has expired or is unavailable",
	"missing_buckets_not_zero_filled":     "Some time buckets have no rows and were not filled with zero",
	"audit_rows_include_write_throttling": "Counts reflect stored audit rows and write throttling",
	"no_note":                             "—",
}

const reportHTML = `<!doctype html>
<html lang="{{if eq .Request.Locale "en-US"}}en{{else}}zh-CN{{end}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{index .Text "title"}}</title>
<style>:root{color-scheme:light;--ink:#182333;--muted:#566274;--line:#d5dce5;--paper:#fff;--back:#f3f5f8;--accent:#244d77}*{box-sizing:border-box}body{margin:0;background:var(--back);color:var(--ink);font:14px/1.65 system-ui,-apple-system,"Microsoft YaHei",sans-serif}main{max-width:1120px;margin:24px auto;padding:32px;background:var(--paper)}h1{font-size:28px;line-height:1.3;margin:0 0 16px}h2{font-size:19px;margin:32px 0 12px;border-bottom:2px solid var(--accent);padding-bottom:6px}h3{font-size:16px;margin:20px 0 8px}p{margin:6px 0;color:var(--muted)}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;margin:10px 0 18px;font-variant-numeric:tabular-nums}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{background:var(--back);font-weight:600}td.num{text-align:right;white-space:nowrap}.state{color:var(--accent);font-weight:600}.meta{margin-bottom:18px}small{color:var(--muted)}@media(max-width:700px){main{margin:0;padding:20px 16px}h1{font-size:24px}th,td{padding:7px 6px}}@media print{body{background:white;font-size:10pt}main{max-width:none;margin:0;padding:0}.scroll{overflow:visible}h2,h3{break-after:avoid}tr{break-inside:avoid}thead{display:table-header-group}th{background:#f3f5f8!important}a{color:inherit}@page{size:A4;margin:16mm}}</style></head><body><main>
<h1>{{index .Text "title"}} · {{index .Text (printf "%s" .Request.Kind)}}</h1><div class="meta"><p>{{index .Text "id"}}: {{label .Request.ID}}</p><p>{{index .Text "range"}}: {{date .Request.Range.Start}} → {{date .Request.Range.End}}</p><p>{{index .Text "generated"}}: {{date .Request.GeneratedAt}}</p><p>{{index .Text "status"}}: <span class="state">{{index .Text (printf "%s" .Status)}}</span></p></div>
<h2>{{index .Text "summary"}}</h2><p>{{index .Text "current"}}: {{index .Text (printf "%s" .Current.Summary.State)}} · {{index .Text "previous"}}: {{index .Text (printf "%s" .Previous.Summary.State)}}</p>
<div class="scroll"><table><thead><tr><th>{{index .Text "metric"}}</th><th>{{index .Text "current"}}</th><th>{{index .Text "previous"}}</th><th>{{index .Text "change"}}</th></tr></thead><tbody>
{{$c := .Current.Summary}}{{$p := .Previous.Summary}}
<tr><td>{{index .Text "requests"}}</td><td class="num">{{if available $c.State}}{{$c.Data.Requests}}{{else}}—{{end}}</td><td class="num">{{if available $p.State}}{{$p.Data.Requests}}{{else}}—{{end}}</td><td class="num">{{cmp $c.State $p.State $c.Data.Requests $p.Data.Requests}}</td></tr>
<tr><td>{{index .Text "blocked"}}</td><td class="num">{{if available $c.State}}{{$c.Data.Blocked}}{{else}}—{{end}}</td><td class="num">{{if available $p.State}}{{$p.Data.Blocked}}{{else}}—{{end}}</td><td class="num">{{cmp $c.State $p.State $c.Data.Blocked $p.Data.Blocked}}</td></tr>
<tr><td>{{index .Text "allowed"}}</td><td class="num">{{if available $c.State}}{{$c.Data.Allowed}}{{else}}—{{end}}</td><td class="num">{{if available $p.State}}{{$p.Data.Allowed}}{{else}}—{{end}}</td><td>—</td></tr>
<tr><td>{{index .Text "in"}}</td><td class="num">{{if available $c.State}}{{$c.Data.TrafficIn}}{{else}}—{{end}}</td><td class="num">{{if available $p.State}}{{$p.Data.TrafficIn}}{{else}}—{{end}}</td><td class="num">{{cmp $c.State $p.State $c.Data.TrafficIn $p.Data.TrafficIn}}</td></tr>
<tr><td>{{index .Text "out"}}</td><td class="num">{{if available $c.State}}{{$c.Data.TrafficOut}}{{else}}—{{end}}</td><td class="num">{{if available $p.State}}{{$p.Data.TrafficOut}}{{else}}—{{end}}</td><td class="num">{{cmp $c.State $p.State $c.Data.TrafficOut $p.Data.TrafficOut}}</td></tr>
<tr><td>{{index .Text "average"}}</td><td class="num">{{if available $c.State}}{{average $c.Data.AverageTimeMS}}{{else}}—{{end}}</td><td class="num">{{if available $p.State}}{{average $p.Data.AverageTimeMS}}{{else}}—{{end}}</td><td>—</td></tr>
<tr><td>{{index .Text "ips"}}</td><td class="num">{{if available .Current.IPs.State}}{{.Current.IPs.Data.Distinct}}{{else}}—{{end}}</td><td class="num">{{if available .Previous.IPs.State}}{{.Previous.IPs.Data.Distinct}}{{else}}—{{end}}</td><td>—</td></tr>
<tr><td>{{index .Text "blocked_ips"}}</td><td class="num">{{if available .Current.IPs.State}}{{.Current.IPs.Data.BlockedDistinct}}{{else}}—{{end}}</td><td class="num">{{if available .Previous.IPs.State}}{{.Previous.IPs.Data.BlockedDistinct}}{{else}}—{{end}}</td><td>—</td></tr>
</tbody></table></div><p>{{index .Text "ips"}}: {{index .Text (printf "%s" .Current.IPs.State)}} / {{index .Text (printf "%s" .Previous.IPs.State)}}</p>
<h2>{{index .Text "trend"}}</h2><p class="state">{{index .Text (printf "%s" .Trend.State)}}</p>{{with .Trend.Note}}<p>{{index $.Text .}}</p>{{end}}
{{if available .Trend.State}}<div class="scroll"><table><thead><tr><th>{{index .Text "time"}}</th><th>{{index .Text "requests"}}</th><th>{{index .Text "blocked"}}</th><th>{{index .Text "in"}}</th><th>{{index .Text "out"}}</th><th>{{index .Text "average"}}</th></tr></thead><tbody>{{range .Trend.Data}}<tr><td>{{date .Start}}</td><td class="num">{{.Requests}}</td><td class="num">{{.Blocked}}</td><td class="num">{{.TrafficIn}}</td><td class="num">{{.TrafficOut}}</td><td class="num">{{average .AverageTimeMS}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{range .Ranks}}<h2>{{.Title}}</h2><p class="state">{{index $.Text (printf "%s" .State)}}</p>{{if available .State}}<table><thead><tr><th>{{index $.Text "name"}}</th><th>{{index $.Text "count"}}</th></tr></thead><tbody>{{range .Data}}<tr><td>{{label .Name}}</td><td class="num">{{.Count}}</td></tr>{{end}}</tbody></table>{{end}}{{end}}
<h2>{{index .Text "actions"}}</h2><p class="state">{{index .Text (printf "%s" .Current.Actions.State)}}</p>{{if available .Current.Actions.State}}<table><thead><tr><th>{{index .Text "name"}}</th><th>{{index .Text "count"}}</th></tr></thead><tbody>{{range .Current.Actions.Data}}<tr><td>{{label .Action}}</td><td class="num">{{.Count}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>{{index .Text "audit"}}</h2><p class="state">{{index .Text (printf "%s" .Audit.State)}}</p>{{if available .Audit.State}}<table><thead><tr><th>{{index .Text "category"}}</th><th>{{index .Text "event"}}</th><th>{{index .Text "result"}}</th><th>{{index .Text "count"}}</th></tr></thead><tbody>{{range .Audit.Data}}<tr><td>{{auditCategory $.Text .Category}}</td><td>{{auditEvent $.Request.Locale .Event}}</td><td>{{auditResult $.Text .Result}}</td><td class="num">{{.Count}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>{{index .Text "snapshot"}}</h2><p>{{index .Text "snapshot_note"}}</p><p>{{date .Snapshot.Data.CollectedAt}}</p><p>{{index .Text "version"}}: {{label .Snapshot.Data.Version}} / {{label .Snapshot.Data.WebVersion}}</p><p>{{index .Text "log_mode"}}: {{label .Snapshot.Data.AccessLogMode}}</p>
<h3>{{index .Text "sites"}}</h3><p class="state">{{index .Text (printf "%s" .Snapshot.Data.Sites.State)}}</p>{{if available .Snapshot.Data.Sites.State}}<div class="scroll"><table><thead><tr><th>{{index .Text "name"}}</th><th>{{index .Text "enabled"}}</th><th>{{index .Text "guard"}}</th><th>{{index .Text "log_only"}}</th></tr></thead><tbody>{{range .Snapshot.Data.Sites.Data}}<tr><td>{{label .Name}}</td><td>{{if .Enabled}}{{index $.Text "yes"}}{{else}}{{index $.Text "no"}}{{end}}</td><td>{{if .GuardEnabled}}{{index $.Text "yes"}}{{else}}{{index $.Text "no"}}{{end}}</td><td>{{if .LogOnly}}{{index $.Text "yes"}}{{else}}{{index $.Text "no"}}{{end}}</td></tr>{{end}}</tbody></table></div>{{end}}
<h3>{{index .Text "certificates"}}</h3><p class="state">{{index .Text (printf "%s" .Snapshot.Data.Certificates.State)}}</p>{{if available .Snapshot.Data.Certificates.State}}<table><thead><tr><th>{{index .Text "certificate_name"}}</th><th>{{index .Text "domains"}}</th><th>{{index .Text "valid_from"}}</th><th>{{index .Text "valid_to"}}</th><th>{{index .Text "status"}}</th></tr></thead><tbody>{{range .Snapshot.Data.Certificates.Data}}<tr><td>{{label .Name}}</td><td>{{if .Domains}}{{label .Domains}}{{else}}—{{end}}</td><td>{{date .ValidFrom}}</td><td>{{date .ValidTo}}</td><td>{{index $.Text .State}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>{{index .Text "notes"}}</h2><p>{{index .Text "method"}}</p><p>{{index .Text "boundary"}}</p><p>{{index .Text "missing"}}</p></main></body></html>`

var _ Renderer = (*HTMLRenderer)(nil)
