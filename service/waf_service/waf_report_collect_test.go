package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafreport"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func reportTestCollector(t *testing.T) (*ReportCollector, wafreport.Request) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "report.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.StatsSiteDay{}, &model.StatsSiteHour{}, &model.StatsIPDay{}, &model.StatsDay{},
		&model.StatsIPCityDay{}, &model.StatsActorPathDay{}, &model.StatsPathRuleDay{}, &model.SecurityAuditLog{}, &model.Hosts{}, &model.SslConfig{}); err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	r, _ := wafreport.NewRange(wafreport.Weekly, time.Date(2026, 11, 4, 12, 0, 0, 0, time.Local))
	return &ReportCollector{StatsDB: db, LogDB: db, CoreDB: db, Version: "test-v1", WebVersion: "test-web", AccessLogMode: "off"},
		wafreport.Request{ID: "report-test", Kind: wafreport.Weekly, Range: r, Locale: "zh-CN", TopN: 10, GeneratedAt: r.End.AddDate(0, 0, 3)}
}

func reportTestBase(id int) baseorm.BaseOrm {
	return baseorm.BaseOrm{Id: fmt.Sprintf("row-%d", id), Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}
}
func reportTestCreate(t *testing.T, db *gorm.DB, v interface{}) {
	t.Helper()
	if err := db.Create(v).Error; err != nil {
		t.Fatal(err)
	}
}

func TestReportCollectAggregateSemantics(t *testing.T) {
	c, req := reportTestCollector(t)
	db := c.StatsDB
	reportTestCreate(t, db, &model.StatsSiteDay{BaseOrm: reportTestBase(1), HostCode: "h1", Day: 20261102, TotalCount: 10, AttackCount: 4, NormalCount: 6, TotalTimeSpent: 100, TrafficIn: 100, TrafficOut: 200})
	reportTestCreate(t, db, &model.StatsSiteDay{BaseOrm: reportTestBase(2), HostCode: "h2", Day: 20261103, TotalCount: 90, AttackCount: 2, NormalCount: 88, TotalTimeSpent: 1800, TrafficIn: 900, TrafficOut: 1800})
	// Independent byte counters can produce rows without request counters.
	reportTestCreate(t, db, &model.StatsSiteDay{BaseOrm: reportTestBase(3), HostCode: "h3", Day: 20261104, TrafficIn: 5000, TrafficOut: 10000})
	reportTestCreate(t, db, &model.StatsSiteDay{BaseOrm: reportTestBase(4), HostCode: "h1", Day: 20261026, TotalCount: 5, AttackCount: 1, NormalCount: 4, TotalTimeSpent: 50})
	reportTestCreate(t, db, &model.StatsSiteDay{BaseOrm: reportTestBase(5), HostCode: "h1", Day: 20261109, TotalCount: 999999})
	for i, row := range []model.StatsIPDay{
		{HostCode: "h1", Day: 20261102, IP: "192.0.2.1", Type: "阻止", Count: 4},
		{HostCode: "h2", Day: 20261103, IP: "192.0.2.1", Type: "阻止", Count: 2},
		{HostCode: "h1", Day: 20261102, IP: "192.0.2.2", Type: "允许", Count: 94},
		{HostCode: "h1", Day: 20261026, IP: "192.0.2.9", Type: "阻止", Count: 1},
	} {
		row.BaseOrm = reportTestBase(10 + i)
		reportTestCreate(t, db, &row)
	}
	for i, row := range []model.StatsDay{{Day: 20261102, Type: "阻止", Count: 6}, {Day: 20261102, Type: "允许", Count: 94}} {
		row.BaseOrm = reportTestBase(20 + i)
		reportTestCreate(t, db, &row)
	}
	reportTestCreate(t, db, &model.StatsActorPathDay{BaseOrm: reportTestBase(30), HostCode: "h1", Day: 20261102, ActorKey: "ip:192.0.2.1", PathNorm: "/public?secret-query=hidden", ReqCnt: 6, DenyCnt: 6})
	reportTestCreate(t, db, &model.StatsActorPathDay{BaseOrm: reportTestBase(31), HostCode: "h1", Day: 20261102, ActorKey: "ip:192.0.2.2", PathNorm: "/allowed", ReqCnt: 94})
	reportTestCreate(t, db, &model.StatsPathRuleDay{BaseOrm: reportTestBase(32), HostCode: "h1", Day: 20261102, PathNorm: "/allowed", Rule: "allow-rule", Cnt: 20})
	reportTestCreate(t, db, &model.StatsIPCityDay{BaseOrm: reportTestBase(33), HostCode: "h1", Day: 20261102, Country: "A", Province: "B", City: "C", Type: "阻止", Count: 6})
	reportTestCreate(t, db, &model.SecurityAuditLog{BaseOrm: reportTestBase(40), Day: 20261102, Category: "access", Event: "login_fail", Result: 0,
		Message: "private-body-marker", URL: "/hidden?secret-marker=private", SessionCode: "private-session-marker"})
	reportTestCreate(t, db, &model.Hosts{BaseOrm: reportTestBase(50), Code: "h1", Host: "xxxx.com", GUARD_STATUS: 1, Keyfile: "private-key-marker", HealthyJSON: `{"is_enable_healthy":1}`})
	reportTestCreate(t, db, &model.SslConfig{BaseOrm: reportTestBase(60), Subject: "CN=xxxx.com", Domains: "xxxx.com, *.xxxx.com", KeyContent: "private-cert-key-marker",
		ValidFrom: customtype.JsonTime(req.GeneratedAt.AddDate(-1, 0, 0)), ValidTo: customtype.JsonTime(req.GeneratedAt.AddDate(0, 0, 5))})
	r, err := c.Collect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	s := r.Current.Summary
	if s.State != wafreport.OK || s.Data.Requests != 100 || s.Data.Blocked != 6 || s.Data.Allowed != 94 || s.Data.TrafficIn != 6000 || s.Data.TrafficOut != 12000 {
		t.Fatalf("summary: %+v", s)
	}
	if s.Data.AverageTimeMS == nil || *s.Data.AverageTimeMS != 19 {
		t.Fatalf("weighted average: %+v", s.Data.AverageTimeMS)
	}
	if r.Previous.Summary.Data.Requests != 5 {
		t.Fatalf("previous: %+v", r.Previous)
	}
	if r.Current.IPs.State != wafreport.OK || r.Current.IPs.Data.Distinct != 2 || r.Current.IPs.Data.BlockedDistinct != 1 {
		t.Fatalf("distinct: %+v", r.Current.IPs)
	}
	if len(r.Current.Actions.Data) != 2 || r.Current.Actions.Data[0].Action != "允许" {
		t.Fatalf("observed actions: %+v", r.Current.Actions)
	}
	if len(r.TopIPs.Data) != 1 || r.TopIPs.Data[0].Count != 6 {
		t.Fatalf("top IP: %+v", r.TopIPs)
	}
	if len(r.TopPaths.Data) != 1 || r.TopPaths.Data[0].Name != "/public" || r.TopPaths.Data[0].Count != 6 {
		t.Fatalf("top path: %+v", r.TopPaths)
	}
	if len(r.TopRules.Data) != 1 || r.TopRules.Data[0].Name != "allow-rule" {
		t.Fatalf("rule matches: %+v", r.TopRules)
	}
	if r.TopRegions.Data[0].Name != "A / B / C" || r.TopRegions.Data[0].Count != 6 {
		t.Fatalf("region: %+v", r.TopRegions)
	}
	if r.Trend.State != wafreport.Partial || len(r.Trend.Data) != 3 {
		t.Fatalf("missing trend buckets: %+v", r.Trend)
	}
	if len(r.Audit.Data) != 1 || r.Audit.Data[0].Count != 1 || r.Audit.Data[0].Result != 0 {
		t.Fatalf("audit: %+v", r.Audit)
	}
	if cert := r.Snapshot.Data.Certificates.Data[0]; cert.State != "expiring" || cert.Name != "CN=xxxx.com" || cert.Domains != "xxxx.com, *.xxxx.com" {
		t.Fatalf("snapshot: %+v", r.Snapshot)
	}
	encoded, _ := json.Marshal(r)
	for _, secret := range []string{"private-body-marker", "secret-marker", "private-session-marker", "private-key-marker", "private-cert-key-marker", "secret-query"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report includes %s", secret)
		}
	}
}

func TestReportCollectEmptyFailureAndUnavailable(t *testing.T) {
	c, req := reportTestCollector(t)
	r, err := c.Collect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if r.Current.Summary.State != wafreport.NoData || r.Current.IPs.State != wafreport.NoData || r.Current.Summary.Data.AverageTimeMS != nil {
		t.Fatalf("empty is not a measured zero: %+v", r.Current)
	}
	if err := c.StatsDB.Migrator().DropTable(&model.StatsIPDay{}); err != nil {
		t.Fatal(err)
	}
	r, err = c.Collect(context.Background(), req)
	if err != nil || r.Current.IPs.State != wafreport.Failed || r.TopIPs.State != wafreport.Failed || r.Status != wafreport.Partial {
		t.Fatalf("query failure: %+v / %v", r, err)
	}
	if strings.Contains(r.Current.IPs.Note, "SQL") {
		t.Fatal("raw query error in report")
	}
	c = &ReportCollector{}
	r, err = c.Collect(context.Background(), req)
	if err != nil || r.Current.Summary.State != wafreport.Unavailable || r.Status != wafreport.Unavailable {
		t.Fatalf("disconnected: %+v / %v", r, err)
	}
}

func TestReportCollectHourlyRetentionAndCancellation(t *testing.T) {
	c, req := reportTestCollector(t)
	req.Kind = wafreport.Daily
	req.Range, _ = wafreport.NewRange(req.Kind, req.Range.Start)
	reportTestCreate(t, c.StatsDB, &model.StatsSiteDay{BaseOrm: reportTestBase(1), Day: 20261102, TotalCount: 2})
	r, err := c.Collect(context.Background(), req)
	if err != nil || r.Trend.State != wafreport.Unavailable || len(r.Trend.Data) != 0 {
		t.Fatalf("expired hourly: %+v %v", r.Trend, err)
	}
	reportTestCreate(t, c.StatsDB, &model.StatsSiteHour{BaseOrm: reportTestBase(2), HourTime: req.Range.Start.Unix(), TotalCount: 2, TotalTimeSpent: 100})
	r, err = c.Collect(context.Background(), req)
	if err != nil || r.Trend.State != wafreport.Partial || len(r.Trend.Data) != 1 || *r.Trend.Data[0].AverageTimeMS != 50 {
		t.Fatalf("hourly: %+v %v", r.Trend, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.Collect(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestReportCollectScope(t *testing.T) {
	c, req := reportTestCollector(t)
	day, _ := reportDays(req.Range)
	for i := 0; i < 3; i++ {
		base := reportTestBase(100 + i)
		if i == 1 {
			base.Tenant_ID += "-other"
		} else if i == 2 {
			base.USER_CODE += "-other"
		}
		name := fmt.Sprintf("scope-%d", i)
		for _, row := range []interface{}{
			&model.StatsSiteDay{BaseOrm: base, Day: day, TotalCount: 1, AttackCount: 1},
			&model.StatsSiteHour{BaseOrm: base, HourTime: req.Range.Start.Unix(), TotalCount: 1, AttackCount: 1},
			&model.StatsIPDay{BaseOrm: base, Day: day, IP: name, Type: "阻止", Count: 1},
			&model.StatsDay{BaseOrm: base, Day: day, Type: "阻止", Count: 1},
			&model.StatsIPCityDay{BaseOrm: base, Day: day, Country: name, Type: "阻止", Count: 1},
			&model.StatsActorPathDay{BaseOrm: base, Day: day, PathNorm: name, DenyCnt: 1},
			&model.StatsPathRuleDay{BaseOrm: base, Day: day, Rule: name, Cnt: 1},
			&model.SecurityAuditLog{BaseOrm: base, Day: day, Category: "config", Event: model.AuditEventConfigReport, Result: 1},
			&model.Hosts{BaseOrm: base, Code: name, Host: name},
			&model.SslConfig{BaseOrm: base, Subject: name, Domains: name},
		} {
			reportTestCreate(t, c.StatsDB, row)
		}
	}
	for _, kind := range []wafreport.Kind{wafreport.Weekly, wafreport.Daily} {
		req.Kind = kind
		req.Range, _ = wafreport.NewRange(kind, req.Range.Start)
		r, err := c.Collect(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if r.Current.Summary.Data.Requests != 1 || r.Current.IPs.Data.Distinct != 1 ||
			len(r.Current.Actions.Data) != 1 || r.Current.Actions.Data[0].Count != 1 ||
			len(r.Trend.Data) != 1 || r.Trend.Data[0].Requests != 1 ||
			len(r.Audit.Data) != 1 || r.Audit.Data[0].Count != 1 {
			t.Fatalf("%s aggregate scope: %+v", kind, r)
		}
		for name, ranks := range map[string]wafreport.Section[[]wafreport.Rank]{
			"IP": r.TopIPs, "rule": r.TopRules, "path": r.TopPaths, "region": r.TopRegions,
		} {
			if len(ranks.Data) != 1 || ranks.Data[0].Count != 1 || !strings.HasPrefix(ranks.Data[0].Name, "scope-0") {
				t.Fatalf("%s %s scope: %+v", kind, name, ranks)
			}
		}
		if sites := r.Snapshot.Data.Sites; len(sites.Data) != 1 || sites.Data[0].Name != "scope-0" {
			t.Fatalf("site scope: %+v", sites)
		}
		if certs := r.Snapshot.Data.Certificates; len(certs.Data) != 1 || certs.Data[0].Name != "scope-0" {
			t.Fatalf("certificate scope: %+v", certs)
		}
	}
}

func TestReportCertificateNameFallback(t *testing.T) {
	c, req := reportTestCollector(t)
	for i, cert := range []model.SslConfig{
		{Subject: "CN=xxxx.com", SerialNo: "serial-1", Domains: "xxxx.com"},
		{SerialNo: "certificate-fallback", Domains: "*.xxxx.com"},
		{},
	} {
		cert.BaseOrm = reportTestBase(i)
		reportTestCreate(t, c.CoreDB, &cert)
	}
	r, err := c.Collect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	certs := r.Snapshot.Data.Certificates.Data
	if len(certs) != 3 || certs[0].Name != "CN=xxxx.com" || certs[0].Domains != "xxxx.com" ||
		certs[1].Name != "certificate-fallback" || certs[2].Name != "row-2" {
		t.Fatalf("certificate identity: %+v", certs)
	}
}

func TestReportCollectNamedSources(t *testing.T) {
	c, req := reportTestCollector(t)
	sources := c.DefaultSources()
	if len(sources) != 5 || sources[0].Name() != "periods" {
		t.Fatalf("sources: %+v", sources)
	}
	c.Sources = []wafreport.Source{sources[3]}
	r, err := c.Collect(context.Background(), req)
	if err != nil || r.Audit.State != wafreport.NoData || r.Current.Summary.State != wafreport.Unavailable || r.Status != wafreport.Partial {
		t.Fatalf("composition: %+v %v", r, err)
	}
}
