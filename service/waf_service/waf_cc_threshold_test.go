package waf_service

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupCCThresholdTestDB 建两个临时 sqlite 库：核心库放站点，日志库放分层 access_log 及真实索引。
func setupCCThresholdTestDB(t *testing.T) (*gorm.DB, *gorm.DB) {
	t.Helper()
	dialect.Register(&dialect.SQLiteDialect{})
	open := func(name string, models ...interface{}) *gorm.DB {
		db, err := gorm.Open(
			sqlite.Open(filepath.Join(t.TempDir(), name)),
			&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
		)
		if err != nil {
			t.Fatalf("打开测试库失败: %v", err)
		}
		if err := db.AutoMigrate(models...); err != nil {
			t.Fatalf("AutoMigrate 失败: %v", err)
		}
		return db
	}
	core := open("cc_th_core.db", &model.Hosts{}, &model.ShareDb{})
	logDB := open("cc_th_log.db", &model.AccessLog{})
	for _, ddl := range []string{
		"CREATE INDEX IF NOT EXISTS idx_al_time ON access_log (tenant_id, user_code, unix_add_time desc)",
		"CREATE INDEX IF NOT EXISTS idx_al_host_time ON access_log (tenant_id, user_code, host_code, unix_add_time desc)",
	} {
		if err := logDB.Exec(ddl).Error; err != nil {
			t.Fatalf("建索引失败: %v", err)
		}
	}
	wafdb.InvalidateShardTierCache()

	oldCore, oldLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = core, logDB
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-ccth"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = oldCore, oldLog
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		wafdb.InvalidateShardTierCache()
		for _, d := range []*gorm.DB{core, logDB} {
			if sqlDB, e := d.DB(); e == nil {
				_ = sqlDB.Close()
			}
		}
	})
	return core, logDB
}

var seedSeq int64

// seedLogs 造 access_log 样本：ip 在 bucket 号 b 的窗口里发 n 次请求。
func seedLogs(t *testing.T, logDB *gorm.DB, hostCode, ip, url string, bucket int64, n int, windowSec int) {
	t.Helper()
	seedLogsForTenant(t, logDB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE, hostCode, ip, url, bucket, n, windowSec)
}

func seedLogsForTenant(t *testing.T, logDB *gorm.DB, tenantID, userCode, hostCode, ip, url string, bucket int64, n int, windowSec int) {
	t.Helper()
	base := time.Now().Add(-24*time.Hour).UnixNano() / 1e6
	winMs := int64(windowSec) * 1000
	base = base - base%winMs // 对齐到窗口起点，避免样本跨桶
	rows := make([]model.AccessLog, 0, n)
	for i := 0; i < n; i++ {
		seedSeq++
		rows = append(rows, model.AccessLog{
			LogNarrow: model.LogNarrow{
				ReqUUID:       fmt.Sprintf("req-%d", seedSeq),
				TenantId:      tenantID,
				UserCode:      userCode,
				HostCode:      hostCode,
				SRC_IP:        ip,
				NetSrcIp:      ip,
				URL:           url,
				UNIX_ADD_TIME: base + bucket*winMs + int64(i%int(winMs)),
			},
		})
	}
	if err := logDB.CreateInBatches(rows, 200).Error; err != nil {
		t.Fatalf("写日志失败: %v", err)
	}
}

// ── 直方图分位数 ──

func TestCCThPercentile(t *testing.T) {
	// 100 个观测：90 个 1 次、9 个 10 次、1 个 500 次
	hist := map[int64]int64{1: 90, 10: 9, 500: 1}
	var samples int64 = 100

	cases := []struct {
		p    float64
		want int64
	}{
		{0.50, 1},
		{0.95, 10},
		{0.99, 10},
		{1, 500},
	}
	for _, c := range cases {
		if got := ccThPercentile(hist, samples, c.p); got != c.want {
			t.Errorf("P%.0f 期望 %d，实际 %d", c.p*100, c.want, got)
		}
	}
	if got := ccThPercentile(map[int64]int64{}, 0, 0.99); got != 0 {
		t.Errorf("空直方图应返回 0，实际 %d", got)
	}
}

func TestCCThCeil(t *testing.T) {
	if ccThCeil(42, 3) != 126 || ccThCeil(42, 5) != 210 || ccThCeil(42, 1.5) != 63 {
		t.Fatalf("三档系数算错：%d %d %d", ccThCeil(42, 5), ccThCeil(42, 3), ccThCeil(42, 1.5))
	}
	// P99 为 0 时不能推荐 0，否则规则一保存就把所有请求都拦了
	if got := ccThCeil(0, 3); got != 1 {
		t.Fatalf("P99=0 时至少应为 1，实际 %d", got)
	}
}

// ── 口径必须与运行时一致 ──

func TestCCThBuildPlan_IPColumnFollowsIPMode(t *testing.T) {
	proxy, err := ccThBuildPlan(request.WafCCThresholdRecommendReq{HostCode: "h"},
		model.Hosts{IPMode: "proxy"}, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxy.dimCols) != 1 || proxy.dimCols[0] != "src_ip" {
		t.Fatalf("代理模式应取 src_ip，实际 %v", proxy.dimCols)
	}
	nic, err := ccThBuildPlan(request.WafCCThresholdRecommendReq{HostCode: "h"},
		model.Hosts{IPMode: "nic"}, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(nic.dimCols) != 1 || nic.dimCols[0] != "net_src_ip" {
		t.Fatalf("网卡模式应取 net_src_ip，实际 %v", nic.dimCols)
	}
}

// 排除静态资源改在 Go 侧按 path.Ext(纯路径) 判定，同时修正动态查询串误排问题
func TestCCThBuildPlan_DynamicScopeHandlesQueryString(t *testing.T) {
	plan, err := ccThBuildPlan(request.WafCCThresholdRecommendReq{
		HostCode: "h", CountScope: model.CCCountScopeDynamic,
	}, model.Hosts{}, 60)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan.where, "NOT LIKE") {
		t.Fatalf("dynamic 口径不应再在 SQL 拼 40 个 NOT LIKE，where=%s", plan.where)
	}
	if !ccThIsStaticURL("/app.js", plan.excludeExts) ||
		!ccThIsStaticURL("/app.js?v=1", plan.excludeExts) ||
		!ccThIsStaticURL("/IMG/LOGO.PNG#top", plan.excludeExts) {
		t.Fatal("静态资源及带查询串/锚点形态应被识别为静态")
	}
	if ccThIsStaticURL("/api/callback?redirect=https://xxxx.com/a.js?v=1", plan.excludeExts) {
		t.Fatal("动态接口查询参数中含 .js? 不应被误判为静态资源")
	}
}

func TestCCThBuildPlan_NonURIConditionsAreDisclosed(t *testing.T) {
	plan, err := ccThBuildPlan(request.WafCCThresholdRecommendReq{
		HostCode:   "h",
		MatchMode:  model.CCMatchModeSimple,
		Conditions: `[{"field":"uri","op":"prefix","value":["/api"]},{"field":"ua","op":"contains","value":["curl"]}]`,
	}, model.Hosts{}, 60)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.where, "url LIKE ?") {
		t.Fatalf("uri 前缀条件应进 SQL，where=%s", plan.where)
	}
	if plan.scopeNote == "" {
		t.Fatal("带了非 URI 条件却没有任何说明，用户会以为样本已经按规则收窄了")
	}
}

func TestCCThURICond(t *testing.T) {
	sql, args := ccThURICond(model.MatchCondition{Field: model.CCFieldURI, Op: model.CCOpEq, Value: model.CCCondVal{"/a"}})
	if !strings.Contains(sql, "url = ?") || !strings.Contains(sql, "url LIKE ?") || len(args) != 2 {
		t.Fatalf("eq 条件应同时覆盖 /a 与 /a?x=1，sql=%s args=%v", sql, args)
	}
	if sql, _ := ccThURICond(model.MatchCondition{Field: model.CCFieldURI, Op: model.CCOpRegex, Value: model.CCCondVal{"^/a"}}); sql != "" {
		t.Fatalf("正则条件应返回空让调用方计入未收窄，实际 %s", sql)
	}
}

// ── 端到端与 6 组专项护栏 ──

func TestCCThRecommend_EndToEnd(t *testing.T) {
	_, logDB := setupCCThresholdTestDB(t)

	host := model.Hosts{Code: "hostA", Host: "t.com", Port: 80, IPMode: "nic"}
	if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
		t.Fatalf("建站点失败: %v", err)
	}

	for i := 0; i < 40; i++ {
		seedLogs(t, logDB, "hostA", "10.0.0."+itoa(i), "/page", int64(i%5), 30, 60)
	}
	seedLogs(t, logDB, "hostA", "1.2.3.4", "/page", 7, 900, 60)
	seedLogs(t, logDB, "hostA", "10.0.0.1", "/app.js?v=1", 3, 1500, 60)

	rep := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode:   "hostA",
		WindowSec:  60,
		CountScope: model.CCCountScopeDynamic,
		StatDim:    model.CCStatDimIP,
		Days:       7,
	})
	if !rep.Supported {
		t.Fatalf("样本充足却没给推荐：%s", rep.Reason)
	}
	if rep.Max != 900 {
		t.Fatalf("峰值应是那个异常客户端的 900（静态资源不计数），实际 %d", rep.Max)
	}
	if rep.P50 != 30 {
		t.Fatalf("一半以上的观测是 30 次，P50 应为 30，实际 %d", rep.P50)
	}
	if rep.Balanced != ccThCeil(rep.P99, 3) || rep.Balanced <= 0 {
		t.Fatalf("均衡档应为 P99×3，实际 P99=%d Balanced=%d", rep.P99, rep.Balanced)
	}
	if len(rep.Top) == 0 || rep.Top[0].DimValue != "1.2.3.4" || rep.Top[0].Peak != 900 {
		t.Fatalf("TOP 第一应是 1.2.3.4/900，实际 %+v", rep.Top)
	}
}

func TestCCThRecommend_NotEnoughSample(t *testing.T) {
	_, logDB := setupCCThresholdTestDB(t)
	host := model.Hosts{Code: "hostB", Host: "t.com", Port: 80}
	_ = global.GWAF_LOCAL_DB.Create(&host).Error
	seedLogs(t, logDB, "hostB", "10.0.0.1", "/page", 1, 50, 60)

	rep := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode: "hostB", WindowSec: 60, StatDim: model.CCStatDimIP, Days: 7,
	})
	if rep.Supported {
		t.Fatal("样本只有 50 条却给了推荐值")
	}
	if rep.Reference == "" {
		t.Fatal("不给推荐时至少要给业界参考值，否则用户还是不知道填多少")
	}
}

func TestCCThRecommend_UnsupportedScope(t *testing.T) {
	setupCCThresholdTestDB(t)
	host := model.Hosts{Code: "hostC", Host: "t.com", Port: 80}
	_ = global.GWAF_LOCAL_DB.Create(&host).Error

	dim := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode: "hostC", StatDim: model.CCStatDimCookie, StatDimField: "sid",
	})
	if dim.Supported || !strings.Contains(dim.Reason, "Cookie") {
		t.Fatalf("Cookie 维度应明确拒绝并说明原因，实际 %+v", dim)
	}
	doc := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode: "hostC", StatDim: model.CCStatDimIP, CountScope: model.CCCountScopeDocument,
	})
	if doc.Supported || !strings.Contains(doc.Reason, "Sec-Fetch-Dest") {
		t.Fatalf("仅页面文档口径应明确拒绝并说明原因，实际 %+v", doc)
	}
}

// 1. 租户隔离 + EXPLAIN QUERY PLAN 索引命中断言（含 idx_al_host_time 缺失时回退 idx_al_time）
func TestCCThRecommend_TenantIsolationAndIndex(t *testing.T) {
	_, logDB := setupCCThresholdTestDB(t)
	host := model.Hosts{Code: "hostIso", Host: "t.com", Port: 80, IPMode: "proxy"}
	_ = global.GWAF_LOCAL_DB.Create(&host).Error

	for i := 0; i < 30; i++ {
		seedLogs(t, logDB, "hostIso", "10.1.0."+itoa(i), "/ok", int64(i%3), 40, 60)
	}
	// 其他租户同 host_code 的极端流量绝不能串入
	seedLogsForTenant(t, logDB, "OtherTenant", "other-user", "hostIso", "9.9.9.9", "/ok", 1, 5000, 60)

	req := request.WafCCThresholdRecommendReq{
		HostCode:   "hostIso",
		WindowSec:  60,
		CountScope: model.CCCountScopeDynamic,
		StatDim:    model.CCStatDimIP,
		Days:       7,
	}
	rep := WafCCThresholdServiceApp.RecommendApi(req)
	if !rep.Supported {
		t.Fatalf("应返回有效推荐，实际 %s", rep.Reason)
	}
	if rep.Max != 40 || rep.TotalReq != 1200 {
		t.Fatalf("其他租户数据串入：期望 Max=40 TotalReq=1200，实际 Max=%d TotalReq=%d", rep.Max, rep.TotalReq)
	}

	// 验证执行计划命中 idx_al_host_time，绝不退化为 SCAN access_log
	plan, err := ccThBuildPlan(req, host, 60)
	if err != nil {
		t.Fatal(err)
	}
	assertExplainUsesIndex := func(wantIdx string) {
		t.Helper()
		fromClause := ccThSelectFromClause(logDB, wafdb.LiveLogName(), model.AccessLogTableName)
		q := "EXPLAIN QUERY PLAN SELECT " + ccThSelectCols(plan) + " FROM " + fromClause +
			" WHERE " + plan.where + " AND unix_add_time >= ? AND unix_add_time <= ? ORDER BY unix_add_time DESC"
		args := append(append([]interface{}{}, plan.args...), int64(0), time.Now().UnixMilli())
		var details []string
		rows, rerr := logDB.Raw(q, args...).Rows()
		if rerr != nil {
			t.Fatalf("EXPLAIN QUERY PLAN 失败: %v (sql=%s)", rerr, q)
		}
		defer rows.Close()
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err == nil {
				details = append(details, detail)
			}
		}
		joined := strings.Join(details, " | ")
		if !strings.Contains(joined, wantIdx) || strings.Contains(joined, "SCAN access_log") {
			t.Fatalf("执行计划未命中 %s（或退化全表扫）：%s", wantIdx, joined)
		}
		if strings.Contains(joined, "USE TEMP B-TREE FOR ORDER BY") {
			t.Fatalf("执行计划触发了临时 B-Tree 排序：%s", joined)
		}
	}

	assertExplainUsesIndex("idx_al_host_time")

	// 模拟历史只读分片（无 idx_al_host_time，仅保留 idx_al_time）
	if err := logDB.Exec("DROP INDEX idx_al_host_time").Error; err != nil {
		t.Fatalf("删除索引失败: %v", err)
	}
	wafdb.InvalidateShardTierCache()
	assertExplainUsesIndex("idx_al_time")
}

// 2. 老分片仅有 web_logs 时的回退兼容
func TestCCThRecommend_LegacyWebLogsFallback(t *testing.T) {
	dialect.Register(&dialect.SQLiteDialect{})
	open := func(name string, models ...interface{}) *gorm.DB {
		db, err := gorm.Open(
			sqlite.Open(filepath.Join(t.TempDir(), name)),
			&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
		)
		if err != nil {
			t.Fatalf("打开测试库失败: %v", err)
		}
		if err := db.AutoMigrate(models...); err != nil {
			t.Fatalf("AutoMigrate 失败: %v", err)
		}
		return db
	}
	core := open("cc_legacy_core.db", &model.Hosts{}, &model.ShareDb{})
	logDB := open("cc_legacy_log.db", &innerbean.WebLog{})
	_ = logDB.Exec("CREATE INDEX IF NOT EXISTS idx_web_time_desc_tenant_user_code ON web_logs (unix_add_time desc, tenant_id, user_code)").Error
	wafdb.InvalidateShardTierCache()

	oldCore, oldLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = core, logDB
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-legacy"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = oldCore, oldLog
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		wafdb.InvalidateShardTierCache()
		for _, d := range []*gorm.DB{core, logDB} {
			if sqlDB, e := d.DB(); e == nil {
				_ = sqlDB.Close()
			}
		}
	})

	host := model.Hosts{Code: "hostLegacy", Host: "t.com", Port: 80, IPMode: "proxy"}
	_ = core.Create(&host).Error

	base := time.Now().Add(-12*time.Hour).UnixNano() / 1e6
	base -= base % 60000
	rows := make([]innerbean.WebLog, 0, 1200)
	for i := 0; i < 30; i++ {
		for j := 0; j < 40; j++ {
			rows = append(rows, innerbean.WebLog{
				TenantId:      global.GWAF_TENANT_ID,
				USER_CODE:     global.GWAF_USER_CODE,
				HOST_CODE:     "hostLegacy",
				SRC_IP:        "10.2.0." + itoa(i),
				NetSrcIp:      "10.2.0." + itoa(i),
				URL:           "/legacy",
				UNIX_ADD_TIME: base + int64(i%3)*60000 + int64(j),
			})
		}
	}
	if err := logDB.CreateInBatches(rows, 200).Error; err != nil {
		t.Fatalf("写 web_logs 失败: %v", err)
	}

	rep := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode:   "hostLegacy",
		WindowSec:  60,
		CountScope: model.CCCountScopeDynamic,
		StatDim:    model.CCStatDimIP,
		Days:       7,
	})
	if !rep.Supported || rep.TotalReq != 1200 || rep.P50 != 40 {
		t.Fatalf("旧表 web_logs 回退失败：%+v", rep)
	}
}

// 3. 超过匹配行数上限时：懒打开不碰旧分片 + 丢弃半截尾桶 + Sampled/SampleHours 准确
func TestCCThRecommend_RowCapTruncatesCleanly(t *testing.T) {
	core, logDB := setupCCThresholdTestDB(t)
	host := model.Hosts{Code: "hostCap", Host: "t.com", Port: 80, IPMode: "proxy"}
	_ = core.Create(&host).Error

	// 登记一个更早的归档分片记录（物理文件不存在，验证实时库命中上限后根本不打开老分片）
	_ = core.Create(&model.ShareDb{
		BaseOrm: baseorm.BaseOrm{
			Id:        "sh-old-1",
			Tenant_ID: global.GWAF_TENANT_ID,
			USER_CODE: global.GWAF_USER_CODE,
		},
		DbLogicType: "log",
		FileName:    "local_log_20261101.db",
		StartTime:   customtype.JsonTime(time.Now().Add(-72 * time.Hour)),
		EndTime:     customtype.JsonTime(time.Now().Add(-48 * time.Hour)),
		Cnt:         1000000,
	}).Error

	// 构造 3 个相邻完整分钟桶，每桶 25 个 IP × 30 次 = 750 次，共 2250 次（都在最近 2 小时内）
	nowMs := time.Now().Add(-2*time.Hour).UnixNano() / 1e6
	nowMs -= nowMs % 60000
	var rows []model.AccessLog
	for b := int64(0); b < 3; b++ {
		for i := 0; i < 25; i++ {
			for j := 0; j < 30; j++ {
				seedSeq++
				rows = append(rows, model.AccessLog{
					LogNarrow: model.LogNarrow{
						ReqUUID:       fmt.Sprintf("cap-%d", seedSeq),
						TenantId:      global.GWAF_TENANT_ID,
						UserCode:      global.GWAF_USER_CODE,
						HostCode:      "hostCap",
						SRC_IP:        "10.3.0." + itoa(i),
						NetSrcIp:      "10.3.0." + itoa(i),
						URL:           "/api/v1/list",
						UNIX_ADD_TIME: nowMs + b*60000 + int64(j),
					},
				})
			}
		}
	}
	if err := logDB.CreateInBatches(rows, 200).Error; err != nil {
		t.Fatalf("写日志失败: %v", err)
	}

	oldCap := ccThMaxScanRows
	ccThMaxScanRows = 1700 // 扫完最新 2 个完整桶(1500行) + 第 3 桶扫 200 行时截断，应丢弃第 3 桶的 200 行
	t.Cleanup(func() { ccThMaxScanRows = oldCap })

	rep := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode:   "hostCap",
		WindowSec:  60,
		CountScope: model.CCCountScopeDynamic,
		StatDim:    model.CCStatDimIP,
		Days:       7,
	})
	if !rep.Supported {
		t.Fatalf("截断后样本仍充足应返回推荐，实际 %+v", rep)
	}
	if !rep.Sampled || rep.TruncatedBy != "rows" {
		t.Fatalf("应标记 Sampled=true 且 TruncatedBy=rows，实际 %+v", rep)
	}
	if rep.TotalReq != 1500 {
		t.Fatalf("半截尾桶的 200 行应被丢弃，期望 TotalReq=1500，实际 %d", rep.TotalReq)
	}
	if rep.SampleHours < 1 || rep.SampleHours >= 24 {
		t.Fatalf("最近 2 小时样本 SampleHours 应在 [1,24)，实际 %d", rep.SampleHours)
	}
	if !strings.Contains(rep.ScopeNote, "24 小时") {
		t.Fatalf("小于 24 小时应给出昼夜周期提示，实际 ScopeNote=%q", rep.ScopeNote)
	}
}

// 4. 时间预算耗尽时优雅降级返回（不阻塞、带业界起步值）
func TestCCThRecommend_TimeBudgetGracefulDegrade(t *testing.T) {
	core, logDB := setupCCThresholdTestDB(t)
	host := model.Hosts{Code: "hostBudget", Host: "t.com", Port: 80, IPMode: "proxy"}
	_ = core.Create(&host).Error
	seedLogs(t, logDB, "hostBudget", "10.4.0.1", "/page", 1, 50, 60)

	oldBudget := ccThQueryBudget
	ccThQueryBudget = time.Nanosecond
	t.Cleanup(func() { ccThQueryBudget = oldBudget })

	rep := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode: "hostBudget", WindowSec: 60, StatDim: model.CCStatDimIP, Days: 7,
	})
	if rep.Supported {
		t.Fatalf("预算耗尽且样本不足时不应返回 Supported=true")
	}
	if !rep.Sampled || rep.TruncatedBy != "time_budget" {
		t.Fatalf("应标记 time_budget 截断，实际 %+v", rep)
	}
	if rep.Reference == "" || !strings.Contains(rep.Reason, "查询保护上限") {
		t.Fatalf("预算降级应说明保护上限并给参考值，实际 Reason=%q Reference=%q", rep.Reason, rep.Reference)
	}
}

// 5. 动态口径查询串边界：/app.js?v=1 排除，/api/callback?redirect=https://xxxx.com/a.js?v=1 必须保留
func TestCCThRecommend_DynamicQueryStringEdgeCase(t *testing.T) {
	core, logDB := setupCCThresholdTestDB(t)
	host := model.Hosts{Code: "hostDyn", Host: "t.com", Port: 80, IPMode: "proxy"}
	_ = core.Create(&host).Error

	for i := 0; i < 25; i++ {
		seedLogs(t, logDB, "hostDyn", "10.5.0."+itoa(i), "/api/callback?redirect=https://xxxx.com/a.js?v=1", int64(i%2), 50, 60)
	}
	seedLogs(t, logDB, "hostDyn", "10.5.0.1", "/static/app.js?v=123", 1, 800, 60)

	rep := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode:   "hostDyn",
		WindowSec:  60,
		CountScope: model.CCCountScopeDynamic,
		StatDim:    model.CCStatDimIP,
		Days:       7,
	})
	if !rep.Supported || rep.TotalReq != 1250 || rep.Max != 50 {
		t.Fatalf("动态回调 URL 被误排或静态资源未排：%+v", rep)
	}
}

// 6. 维度峰值表容量上限保护（防高基数扫描撑爆内存）
func TestCCThRecommend_DimMapMemoryCap(t *testing.T) {
	core, logDB := setupCCThresholdTestDB(t)
	host := model.Hosts{Code: "hostMem", Host: "t.com", Port: 80, IPMode: "proxy"}
	_ = core.Create(&host).Error

	// 80 个不同 IP，前 60 个各 1 次（单次噪声），后 20 个各 60 次（高频正常，合计 1260 次）
	for i := 0; i < 60; i++ {
		seedLogs(t, logDB, "hostMem", fmt.Sprintf("10.6.1.%d", i), "/one", 1, 1, 60)
	}
	for i := 0; i < 20; i++ {
		seedLogs(t, logDB, "hostMem", fmt.Sprintf("10.6.2.%d", i), "/hot", 2, 60, 60)
	}

	oldDimCap := ccThMaxTrackDims
	ccThMaxTrackDims = 40
	t.Cleanup(func() { ccThMaxTrackDims = oldDimCap })

	rep := WafCCThresholdServiceApp.RecommendApi(request.WafCCThresholdRecommendReq{
		HostCode:   "hostMem",
		WindowSec:  60,
		CountScope: model.CCCountScopeDynamic,
		StatDim:    model.CCStatDimIP,
		Days:       7,
	})
	if !rep.Supported {
		t.Fatalf("维度表受限时仍应正常算出推荐，实际 %+v", rep)
	}
	if rep.TotalDim < 80 {
		t.Fatalf("驱逐单次噪声键后 TotalDim 仍应计入真实基数 >=80，实际 %d", rep.TotalDim)
	}
	if len(rep.Top) == 0 || rep.Top[0].Peak != 60 {
		t.Fatalf("高频对象峰值应保留在 TOP 中，实际 %+v", rep.Top)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
