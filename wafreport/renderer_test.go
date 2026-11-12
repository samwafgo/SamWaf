package wafreport

import (
	"SamWaf/model"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func rendererTestReport() Report {
	r, _ := NewRange(Daily, time.Date(2026, 11, 10, 0, 0, 0, 0, time.Local))
	return Report{Request: Request{ID: "R-1", Kind: Daily, Range: r, GeneratedAt: r.End}, Status: Partial,
		Current: PeriodData{Summary: Section[Summary]{State: OK, Data: Summary{Requests: 20, Blocked: 4, TrafficIn: 4096}},
			IPs: Section[IPCounts]{State: NoData}, Actions: Section[[]ActionCount]{State: NoData}},
		Previous: PeriodData{Summary: Section[Summary]{State: NoData}},
		TopIPs:   Section[[]Rank]{State: OK, Data: []Rank{{Name: "<b>escaped</b>", Count: 5}}},
		TopPaths: Section[[]Rank]{State: OK, Data: []Rank{{Name: "/public?private-marker=hidden#fragment", Count: 3}}},
		TopRules: Section[[]Rank]{State: Failed, Data: []Rank{{Name: "should-not-render", Count: 999}}},
		Trend:    Section[[]TrendPoint]{State: Unavailable}, Audit: Section[[]AuditCount]{State: NoData},
		Snapshot: Section[Snapshot]{State: OK}}
}

func TestReportHTMLLocaleEscapingAndAbsence(t *testing.T) {
	r := rendererTestReport()
	for _, locale := range []string{"zh-CN", "en-US"} {
		r.Request.Locale = locale
		var out bytes.Buffer
		if err := NewHTMLRenderer().Render(context.Background(), &out, r); err != nil {
			t.Fatal(err)
		}
		html := out.String()
		for _, forbidden := range []string{"<b>escaped</b>", "private-marker", "fragment", "should-not-render", "<script", "<link", "<img", "src=", "compliance", "法规", "合规"} {
			if strings.Contains(html, forbidden) {
				t.Fatalf("%s contains %q", locale, forbidden)
			}
		}
		for _, expected := range []string{"&lt;b&gt;escaped&lt;/b&gt;", "4096", "/public", "@media print"} {
			if !strings.Contains(html, expected) {
				t.Fatalf("%s missing %q", locale, expected)
			}
		}
		if locale == "en-US" && !strings.Contains(html, "Security Operations Report") {
			t.Fatal("missing English labels")
		}
		if locale == "zh-CN" && !strings.Contains(html, "无数据") {
			t.Fatal("missing absent-data label")
		}
		if strings.Contains(html, "100.0%") {
			t.Fatal("invented comparison with missing baseline")
		}
	}
}

func TestReportHTMLValidComparison(t *testing.T) {
	r := rendererTestReport()
	r.Previous.Summary = Section[Summary]{State: OK, Data: Summary{Requests: 10}}
	var out bytes.Buffer
	if err := NewHTMLRenderer().Render(context.Background(), &out, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "100.0%") {
		t.Fatal("valid comparison absent")
	}
	if reportDelta(1, 0) != "—" {
		t.Fatal("zero baseline invented")
	}
}

func TestReportHTMLAuditLabels(t *testing.T) {
	r := rendererTestReport()
	r.Audit = Section[[]AuditCount]{State: OK, Data: []AuditCount{
		{Category: "config", Event: model.AuditEventConfigBatchTaskRun, Result: 1, Count: 3},
		{Category: "access", Event: model.AccessEventLoginFail, Result: 0, Count: 2},
		{Category: "<custom-category>", Event: "<custom-event>", Result: 7, Count: 1},
	}}
	for _, locale := range []string{"zh-CN", "en-US"} {
		r.Request.Locale = locale
		var out bytes.Buffer
		if err := NewHTMLRenderer().Render(context.Background(), &out, r); err != nil {
			t.Fatal(err)
		}
		content := out.String()
		expected := []string{"配置操作", "批量任务执行", "密码错误", ">成功<", ">失败<", "其他分类", "其他事件", ">未知<"}
		if locale == "en-US" {
			expected = []string{"Configuration operations", "Batch task execution", "Incorrect password", ">Success<", ">Failure<", "Other category", "Other event", ">Unknown<"}
		}
		for _, label := range expected {
			if !strings.Contains(content, label) {
				t.Fatalf("%s missing audit label %q", locale, label)
			}
		}
		for _, code := range []string{"config_batch_task_run", "login_fail", ">config<", "<custom-event>", "<custom-category>", "<td>1</td>", "<td>0</td>"} {
			if strings.Contains(content, code) {
				t.Fatalf("%s includes internal audit value %q", locale, code)
			}
		}
	}
	for event := range model.AccessEventNames {
		if reportAuditEN[event] == "" {
			t.Errorf("missing English event label: %s", event)
		}
	}
}

func TestReportHTMLCertificateIdentity(t *testing.T) {
	r := rendererTestReport()
	r.Snapshot.Data.Certificates = Section[[]Certificate]{State: OK, Data: []Certificate{
		{Name: "业务证书 <primary>", Domains: "xxxx.com, *.xxxx.com", State: "expiring", ValidFrom: r.Request.Range.Start, ValidTo: r.Request.Range.End},
	}}
	for _, locale := range []string{"zh-CN", "en-US"} {
		r.Request.Locale = locale
		var out bytes.Buffer
		if err := NewHTMLRenderer().Render(context.Background(), &out, r); err != nil {
			t.Fatal(err)
		}
		content := out.String()
		for _, expected := range []string{"业务证书 &lt;primary&gt;", "xxxx.com, *.xxxx.com"} {
			if !strings.Contains(content, expected) {
				t.Fatalf("%s missing certificate identity %q", locale, expected)
			}
		}
		for _, removed := range []string{"后端健康快照", "健康检测配置", "Backend health", "Health check enabled", "<primary>"} {
			if strings.Contains(content, removed) {
				t.Fatalf("%s includes %q", locale, removed)
			}
		}
	}
}

type reportFailWriter struct{}

func (reportFailWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestReportHTMLCancellationAndWriterErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewHTMLRenderer().Render(ctx, &bytes.Buffer{}, rendererTestReport()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if err := NewHTMLRenderer().Render(context.Background(), reportFailWriter{}, rendererTestReport()); err == nil {
		t.Fatal("writer failure hidden")
	}
}
