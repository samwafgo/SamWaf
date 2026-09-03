package waf_service

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupCCThresholdTestDB 建两个临时 sqlite 库：核心库放站点，日志库放访问日志。
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
	logDB := open("cc_th_log.db", &innerbean.WebLog{})

	oldCore, oldLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = core, logDB
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-ccth"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = oldCore, oldLog
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		// Windows 下句柄不关，t.TempDir 清理会失败
		for _, d := range []*gorm.DB{core, logDB} {
			if sqlDB, e := d.DB(); e == nil {
				_ = sqlDB.Close()
			}
		}
	})
	return core, logDB
}

// seedLogs 造样本：ip 在 bucket 号 b 的窗口里发 n 次请求。
func seedLogs(t *testing.T, logDB *gorm.DB, hostCode, ip, url string, bucket int64, n int, windowSec int) {
	t.Helper()
	base := time.Now().Add(-24*time.Hour).UnixNano() / 1e6
	winMs := int64(windowSec) * 1000
	base = base - base%winMs // 对齐到窗口起点，避免样本跨桶
	rows := make([]innerbean.WebLog, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, innerbean.WebLog{
			HOST_CODE:     hostCode,
			SRC_IP:        ip,
			NetSrcIp:      ip,
			URL:           url,
			UNIX_ADD_TIME: base + bucket*winMs + int64(i),
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

// 客户端 IP 取哪一列必须跟站点的 IPMode 走，写死一列就会和运行时对不上
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

// 排除静态资源要处理日志 url 带查询串的情况：/a.js?v=1 也是静态资源
func TestCCThBuildPlan_DynamicScopeHandlesQueryString(t *testing.T) {
	plan, err := ccThBuildPlan(request.WafCCThresholdRecommendReq{
		HostCode: "h", CountScope: model.CCCountScopeDynamic,
	}, model.Hosts{}, 60)
	if err != nil {
		t.Fatal(err)
	}
	var hasPlain, hasQuery bool
	for _, a := range plan.args {
		switch a {
		case "%.js":
			hasPlain = true
		case "%.js?%":
			hasQuery = true
		}
	}
	if !hasPlain || !hasQuery {
		t.Fatalf("静态后缀应同时比「结尾」和「后面跟查询串」两种形态，args=%v", plan.args)
	}
}

// 规则还带着非 URI 条件时必须如实说明样本没收窄，不能假装已经按规则收敛
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
	// uri 取的是 URL.Path，日志 url 含查询串，所以 eq 要多比一种形态
	sql, args := ccThURICond(model.MatchCondition{Field: model.CCFieldURI, Op: model.CCOpEq, Value: model.CCCondVal{"/a"}})
	if !strings.Contains(sql, "url = ?") || !strings.Contains(sql, "url LIKE ?") || len(args) != 2 {
		t.Fatalf("eq 条件应同时覆盖 /a 与 /a?x=1，sql=%s args=%v", sql, args)
	}
	// 不支持的操作符不能悄悄变成「无条件」，要让调用方知道没收窄
	if sql, _ := ccThURICond(model.MatchCondition{Field: model.CCFieldURI, Op: model.CCOpRegex, Value: model.CCCondVal{"^/a"}}); sql != "" {
		t.Fatalf("正则条件应返回空让调用方计入未收窄，实际 %s", sql)
	}
}

// ── 端到端：SQL 真的能在 sqlite 上跑出正确分布 ──

func TestCCThRecommend_EndToEnd(t *testing.T) {
	_, logDB := setupCCThresholdTestDB(t)

	host := model.Hosts{Code: "hostA", Host: "t.com", Port: 80, IPMode: "nic"}
	if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
		t.Fatalf("建站点失败: %v", err)
	}

	// 40 个普通访客各 30 次，1 个异常客户端 900 次；再加静态资源噪音
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
	// 静态资源那 1500 次必须被排除，否则 10.0.0.1 会顶到第一（日志 url 带查询串，别漏了 ?% 那种形态）
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

// 样本太少时宁可不给推荐，也不给一个看起来很准的错数
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

// 日志里还原不可靠的口径必须明确拒绝，不能硬算
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

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
