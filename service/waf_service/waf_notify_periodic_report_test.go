package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestPeriodicReportSummaryEvent(t *testing.T) {
	for _, tc := range []struct{ kind, messageType, name string }{
		{"daily", model.MSG_TYPE_DAILY_REPORT, "日报"},
		{"weekly", model.MSG_TYPE_WEEKLY_REPORT, "周报"},
		{"monthly", model.MSG_TYPE_MONTHLY_REPORT, "月报"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			ev := buildPeriodicReportSummaryEvent(tc.kind, "report-001", "2026-11-01 ~ 2026-11-07", "ok", 100, 3)
			if ev.MessageType != tc.messageType || ev.MessageTypeName != tc.name || ev.Severity != model.SeverityInfo {
				t.Fatalf("unexpected message metadata: %+v", ev)
			}
			want := map[string]string{"ReportID": "report-001", "ReportRange": "2026-11-01 ~ 2026-11-07", "ReportStatus": "ok", "TotalRequests": "100", "BlockedRequests": "3", "BlockRate": "3.00%"}
			registered := map[string]bool{}
			for _, v := range GetNotifyTemplateVars(tc.messageType) {
				registered[v.Name] = true
			}
			for k, v := range want {
				if ev.Vars[k] != v || !registered[k] {
					t.Fatalf("variable %s = %q, registered=%v, want %q", k, ev.Vars[k], registered[k], v)
				}
			}
			if tc.kind == "weekly" && ev.Vars["WeekRange"] != ev.Vars["ReportRange"] {
				t.Fatal("weekly range alias missing")
			}
			if !strings.Contains(ev.DefaultContent, "本地报告中心下载") || strings.Contains(ev.DefaultContent, "http") || strings.Contains(ev.DefaultContent, "<html") {
				t.Fatalf("unexpected default summary: %s", ev.DefaultContent)
			}
			if len(ev.DedupParts) != 1 || ev.DedupParts[model.DedupKeyMessageType] != tc.messageType {
				t.Fatal("summary should only contain the message type dedup dimension")
			}
			sub := model.NotifySubscription{ContentTemplate: "{{.ReportID}} {{.ReportRange}} {{.ReportStatus}} {{.TotalRequests}} {{.BlockedRequests}} {{.BlockRate}}"}
			_, rendered, used := RenderNotifyMessage(sub, "webhook", ev)
			if used != model.TemplateUsedCustom || rendered != "report-001 2026-11-01 ~ 2026-11-07 ok 100 3 3.00%" {
				t.Fatalf("summary template rendered %q (%s)", rendered, used)
			}
			found := 0
			for _, mt := range AllMessageTypes() {
				if mt == tc.messageType {
					found++
				}
			}
			if !IsKnownMessageType(tc.messageType) || found != 1 {
				t.Fatalf("message type missing or repeated: %s", tc.messageType)
			}
		})
	}
}

func TestPeriodicReportSummaryMissingTraffic(t *testing.T) {
	for _, tc := range []struct {
		total, blocked                   int64
		wantTotal, wantBlocked, wantRate string
	}{
		{-1, -1, "未采集", "未采集", "未采集"},
		{100, -1, "100", "未采集", "未采集"},
		{-1, 3, "未采集", "3", "未采集"},
		{0, 0, "0", "0", "0.00%"},
	} {
		ev := buildPeriodicReportSummaryEvent("daily", "report-001", "2026-11-11", "partial", tc.total, tc.blocked)
		if ev.Vars["TotalRequests"] != tc.wantTotal || ev.Vars["BlockedRequests"] != tc.wantBlocked || ev.Vars["BlockRate"] != tc.wantRate {
			t.Fatalf("traffic %d/%d rendered as %+v", tc.total, tc.blocked, ev.Vars)
		}
		for _, text := range []string{"**总请求数:** " + tc.wantTotal, "**拦截请求数:** " + tc.wantBlocked, "**拦截率:** " + tc.wantRate, "部分完成"} {
			if !strings.Contains(ev.DefaultContent, text) {
				t.Fatalf("default content lacks %q: %s", text, ev.DefaultContent)
			}
		}
	}
}

func TestPeriodicReportSummaryDefaultEscaping(t *testing.T) {
	ev := buildPeriodicReportSummaryEvent("daily", "<b>report</b>", "*range*\nnext", "<b>status</b>", 1, 0)
	if strings.Contains(ev.DefaultContent, "<b>") || strings.Contains(ev.DefaultContent, "*range*") || strings.Contains(ev.DefaultContent, "range*\nnext") {
		t.Fatalf("summary fields changed markup: %s", ev.DefaultContent)
	}
}

func TestPeriodicReportLegacyWeeklyUnchanged(t *testing.T) {
	msg := innerbean.WeeklyReportMessageInfo{WeekRange: "2026-11-01 ~ 2026-11-07", TotalRequests: 100, BlockedRequests: 3}
	ev := WafNotifySenderServiceApp.BuildNotifyEvent(msg)
	mt, title, content := WafNotifySenderServiceApp.FormatWeeklyReportMessageFromBean(msg)
	if ev.MessageType != mt || ev.DefaultTitle != title || ev.DefaultContent != content || ev.Vars["WeekRange"] != msg.WeekRange || ev.Vars["ReportRange"] != msg.WeekRange {
		t.Fatal("legacy weekly notification changed")
	}
	sample := SampleNotifyEvent(model.MSG_TYPE_WEEKLY_REPORT)
	wantTitle, wantContent := WafNotifySenderServiceApp.FormatWeeklyReportMessage(120000, 356, sample.Vars["WeekRange"])
	if sample.DefaultTitle != wantTitle || sample.DefaultContent != wantContent {
		t.Fatal("legacy weekly preview changed")
	}
}

func TestPeriodicReportSummaryRequiresSubscription(t *testing.T) {
	oldDialect := func() (d dialect.DBDialect) {
		defer func() { _ = recover() }()
		return dialect.Get()
	}()
	dialect.Register(&dialect.SQLiteDialect{})
	t.Cleanup(func() { dialect.Register(oldDialect) })
	db, err := gorm.Open(sqlitedriver.Open(filepath.Join(t.TempDir(), "notify.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.NotifySubscription{}, &model.NotifyChannel{}, &model.NotifyLog{}); err != nil {
		t.Fatal(err)
	}
	oldDB, oldLogDB := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = db, db
	t.Cleanup(func() { global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = oldDB, oldLogDB })
	for _, kind := range []string{"daily", "weekly", "monthly"} {
		WafNotifySenderServiceApp.SendPeriodicReportSummary(kind, "report-001", "2026-11-11", "ok", 100, 3)
	}
	for _, table := range []interface{}{&model.NotifySubscription{}, &model.NotifyChannel{}, &model.NotifyLog{}} {
		var count int64
		if err := db.Model(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("unexpected default notification rows %T: %d (%v)", table, count, err)
		}
	}
	channel := model.NotifyChannel{Name: "test", Type: "test_no_delivery", Status: 1}
	channel.Id = "report-test-channel"
	if err := db.Create(&channel).Error; err != nil {
		t.Fatal(err)
	}
	sub := model.NotifySubscription{ChannelId: channel.Id, MessageType: model.MSG_TYPE_DAILY_REPORT,
		Status: 0, ThrottleMode: model.ThrottleModeRealtime, FilterJSON: `{"min_severity":"critical"}`}
	sub.Id = "report-test-sub"
	if err := db.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	WafNotifySenderServiceApp.SendPeriodicReportSummary("daily", "report-001", "2026-11-11", "ok", 100, 3)
	var logs []model.NotifyLog
	if err := db.Find(&logs).Error; err != nil || len(logs) != 0 {
		t.Fatalf("disabled subscription generated logs: %+v (%v)", logs, err)
	}
	oldThrottle := WafNotifyThrottleServiceApp
	WafNotifyThrottleServiceApp = &WafNotifyThrottleService{states: make(map[string]*throttleState),
		globalCache: BuiltinGlobalThrottle(), globalLoaded: time.Now()}
	t.Cleanup(func() { WafNotifyThrottleServiceApp = oldThrottle })
	if err := db.Model(&sub).Update("Status", 1).Error; err != nil {
		t.Fatal(err)
	}
	WafNotifySenderServiceApp.SendPeriodicReportSummary("daily", "report-001", "2026-11-11", "ok", 100, 3)
	if err := db.Find(&logs).Error; err != nil || len(logs) != 1 {
		t.Fatalf("enabled subscription did not use notification filtering: %+v (%v)", logs, err)
	}
	if logs[0].SubscriptionId != sub.Id || logs[0].MessageType != model.MSG_TYPE_DAILY_REPORT ||
		logs[0].Status != model.NotifyLogStatusSuppress || logs[0].SuppressReason != model.SuppressReasonFilterMiss {
		t.Fatalf("unexpected filter result: %+v", logs[0])
	}
	// 无效类型在查询订阅前结束。
	global.GWAF_LOCAL_DB = nil
	WafNotifySenderServiceApp.SendPeriodicReportSummary("invalid", "report-001", "2026-11-11", "ok", 100, 3)
}
