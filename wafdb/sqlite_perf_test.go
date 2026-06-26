package wafdb

import (
	"SamWaf/innerbean"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 这些用例验证 Issue #838 的两类目标：
//   - 响应速度：T1 高频写入吞吐(FULL vs NORMAL)、T2 不同数据量下查询延迟
//   - 文件完整性：T3 多分片 integrity_check + 零丢数据、T4 WAL 受控
//
// 注意：SQLite 驱动需要 CGO，运行需 `CGO_ENABLED=1` + C 编译器(mingw)。
// 用临时目录隔离，不污染真实 data 目录。

// openPerfTestDB 打开一个临时加密日志库并应用性能 pragma + 迁移 web_logs 表。
func openPerfTestDB(t *testing.T, path string, relaxedSync bool) *gorm.DB {
	t.Helper()
	key := url.QueryEscape("perf_test_key_3Y)(27Et")
	dns := fmt.Sprintf("%s?_db_key=%s", path, key)
	db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	applyPerfPragmas(db, relaxedSync)
	if err := db.AutoMigrate(&innerbean.WebLog{}); err != nil {
		t.Fatalf("迁移 web_logs 失败: %v", err)
	}
	// 关闭连接，否则 Windows 下 t.TempDir 清理会因文件被占用而失败
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// genWebLogs 构造 n 条贴近真实的访问日志（含 BODY/POST_FORM 大字段）。
func genWebLogs(n int) []*innerbean.WebLog {
	body := strings.Repeat("a=1&b=2&payload=", 64)         // ~1KB
	postForm := strings.Repeat("user=test&token=abc&", 32) // ~640B
	now := time.Now()
	logs := make([]*innerbean.WebLog, 0, n)
	for i := 0; i < n; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		logs = append(logs, &innerbean.WebLog{
			HOST:          "site.example.com",
			URL:           fmt.Sprintf("/api/path/%d?x=%d", i, i),
			METHOD:        "POST",
			SRC_IP:        fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256),
			BODY:          body,
			POST_FORM:     postForm,
			HEADER:        "Content-Type: application/x-www-form-urlencoded",
			STATUS_CODE:   200,
			USER_CODE:     "test_user",
			TenantId:      "test_user",
			HOST_CODE:     "host_01",
			CREATE_TIME:   ts.Format("2006-01-02 15:04:05"),
			UNIX_ADD_TIME: ts.UnixNano() / 1e6,
			Day:           ts.Year()*10000 + int(ts.Month())*100 + ts.Day(),
		})
	}
	return logs
}

func pctile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), d...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(float64(len(cp)-1) * p)
	return cp[idx]
}

func batchInsert(t *testing.T, db *gorm.DB, logs []*innerbean.WebLog, batchSize int) (time.Duration, []time.Duration) {
	t.Helper()
	var perBatch []time.Duration
	start := time.Now()
	for i := 0; i < len(logs); i += batchSize {
		end := i + batchSize
		if end > len(logs) {
			end = len(logs)
		}
		bs := time.Now()
		if err := db.CreateInBatches(logs[i:end], batchSize).Error; err != nil {
			t.Fatalf("批量写入失败: %v", err)
		}
		perBatch = append(perBatch, time.Since(bs))
	}
	return time.Since(start), perBatch
}

// T1：高频写入吞吐与延迟，对比 synchronous=FULL 与 NORMAL。
func TestSqliteHighFreqWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过写入压测")
	}
	const n = 50000
	const batch = 100
	dir := t.TempDir()

	fullDB := openPerfTestDB(t, dir+"/full.db", false)
	normalDB := openPerfTestDB(t, dir+"/normal.db", true)

	fullElapsed, fullBatches := batchInsert(t, fullDB, genWebLogs(n), batch)
	normalElapsed, normalBatches := batchInsert(t, normalDB, genWebLogs(n), batch)

	fullQPS := float64(n) / fullElapsed.Seconds()
	normalQPS := float64(n) / normalElapsed.Seconds()
	t.Logf("写入 %d 条：FULL=%v (%.0f QPS, 批P95=%v)  NORMAL=%v (%.0f QPS, 批P95=%v)  提速=%.2fx",
		n, fullElapsed, fullQPS, pctile(fullBatches, 0.95),
		normalElapsed, normalQPS, pctile(normalBatches, 0.95),
		fullElapsed.Seconds()/normalElapsed.Seconds())

	var cnt int64
	normalDB.Model(&innerbean.WebLog{}).Count(&cnt)
	if cnt != int64(n) {
		t.Fatalf("NORMAL 库写入条数不符: got=%d want=%d", cnt, n)
	}
}

// T2：不同数据量下分页查询延迟（模拟 GetListApi：时间范围 + 倒序 + Count）。
func TestSqliteQueryLatencyBySize(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过查询压测")
	}
	dir := t.TempDir()
	for _, size := range []int{2000, 20000} {
		db := openPerfTestDB(t, fmt.Sprintf("%s/q_%d.db", dir, size), true)
		if _, _, err := func() (time.Duration, []time.Duration, error) {
			el, pb := batchInsert(t, db, genWebLogs(size), 100)
			return el, pb, nil
		}(); err != nil {
			t.Fatal(err)
		}

		nowMs := time.Now().UnixNano() / 1e6
		var lat []time.Duration
		for page := 1; page <= 5; page++ {
			st := time.Now()
			var rows []innerbean.WebLog
			db.Table("web_logs").
				Where("unix_add_time >= ? and unix_add_time <= ?", int64(0), nowMs+86400000).
				Order("unix_add_time desc").
				Limit(20).Offset(20 * (page - 1)).
				Find(&rows)
			var total int64
			db.Table("web_logs").
				Where("unix_add_time >= ? and unix_add_time <= ?", int64(0), nowMs+86400000).
				Count(&total)
			lat = append(lat, time.Since(st))
		}
		t.Logf("表 %d 行：查询 P50=%v P95=%v", size, pctile(lat, 0.5), pctile(lat, 0.95))
	}
}

// T3：多分片完整性 + 零丢数据。模拟切库后存在多个 .db 文件，逐个 integrity_check，并校验各分片条数之和。
func TestSqliteIntegrityAcrossShards(t *testing.T) {
	dir := t.TempDir()
	counts := []int{300, 500, 200}
	total := 0
	for i, c := range counts {
		path := fmt.Sprintf("%s/local_log_shard%d.db", dir, i)
		db := openPerfTestDB(t, path, true)
		if err := db.CreateInBatches(genWebLogs(c), 100).Error; err != nil {
			t.Fatalf("写入分片失败: %v", err)
		}
		// checkpoint 让数据落主库，贴近切库后归档文件状态
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")

		var res string
		db.Raw("PRAGMA integrity_check;").Scan(&res)
		if res != "ok" {
			t.Fatalf("分片 %s integrity_check 未通过: %q", path, res)
		}
		var n int64
		db.Model(&innerbean.WebLog{}).Count(&n)
		if n != int64(c) {
			t.Fatalf("分片 %d 条数不符: got=%d want=%d", i, n, c)
		}
		total += int(n)

		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	}
	want := 0
	for _, c := range counts {
		want += c
	}
	if total != want {
		t.Fatalf("各分片条数之和不符(疑似丢数据): got=%d want=%d", total, want)
	}
	t.Logf("跨 %d 个分片完整性校验通过，总条数=%d", len(counts), total)
}

// T4：WAL 受控。关闭自动 checkpoint 写入后 WAL 增大，手动 wal_checkpoint(TRUNCATE) 后回落。
func TestSqliteWalBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过 WAL 压测")
	}
	dir := t.TempDir()
	path := dir + "/wal.db"
	db := openPerfTestDB(t, path, true)
	// 关闭自动 checkpoint 以便观察 WAL 累积
	db.Exec("PRAGMA wal_autocheckpoint=0;")

	if err := db.CreateInBatches(genWebLogs(20000), 100).Error; err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	walBefore := fileSize(path + "-wal")
	if walBefore == 0 {
		t.Skip("未观察到 WAL 文件（驱动可能即时 checkpoint），跳过断言")
	}

	if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error; err != nil {
		t.Fatalf("checkpoint 失败: %v", err)
	}
	walAfter := fileSize(path + "-wal")
	t.Logf("WAL: checkpoint 前=%dKB 后=%dKB", walBefore/1024, walAfter/1024)
	if walAfter >= walBefore {
		t.Fatalf("checkpoint(TRUNCATE) 后 WAL 未回落: before=%d after=%d", walBefore, walAfter)
	}
}

func fileSize(p string) int64 {
	if fi, err := os.Stat(p); err == nil {
		return fi.Size()
	}
	return 0
}
