package wafdb

import (
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 守护用例：分层导出的分批拷贝曾用 map 接行，FindInBatches 拿不到主键信息，
// 报 "model value required"、拼出 `ORDER BY access_log.` 的坏 SQL，导出整批失败。
// 这里走真实两库过一遍 exportCopyTier：时间段过滤要对、跨多个批次续批不能漏不能重。
func TestExportCopyTierBatchesByPrimaryKey(t *testing.T) {
	srcDB := openTenantTestDB(t, "sqlite")
	dstDB := openTenantTestDB(t, "sqlite")
	if err := srcDB.AutoMigrate(&model.AccessLog{}); err != nil {
		t.Fatalf("源库建表失败: %v", err)
	}
	if err := dstDB.AutoMigrate(&model.AccessLog{}); err != nil {
		t.Fatalf("导出库建表失败: %v", err)
	}

	// 2500 行（> 2 个批次）：create_time 每分钟一行，时间段只覆盖前 1500 行
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.Local)
	const total = 2500
	batch := make([]model.AccessLog, 0, 500)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := srcDB.Create(&batch).Error; err != nil {
			t.Fatalf("造数失败: %v", err)
		}
		batch = batch[:0]
	}
	for i := 0; i < total; i++ {
		batch = append(batch, model.AccessLog{LogNarrow: model.LogNarrow{
			ReqUUID:     fmt.Sprintf("uuid-%05d", i),
			CREATE_TIME: base.Add(time.Duration(i) * time.Minute).Format("2006-01-02 15:04:05"),
		}})
		if len(batch) == 500 {
			flush()
		}
	}
	flush()

	start := base.Format("2006-01-02 15:04:05")
	end := base.Add(1499 * time.Minute).Format("2006-01-02 15:04:05")
	n, err := exportCopyTier[model.AccessLog](srcDB, dstDB, model.AccessLogTableName, model.AccessLogTableName, start, end)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if n != 1500 {
		t.Fatalf("应导出 1500 行，实际 %d", n)
	}
	var got int64
	dstDB.Model(&model.AccessLog{}).Count(&got)
	if got != 1500 {
		t.Fatalf("导出文件应有 1500 行，实际 %d（分批续批漏行或重复）", got)
	}

	// 同区间再导一次：主键冲突保留先到，不翻倍
	if _, err := exportCopyTier[model.AccessLog](srcDB, dstDB, model.AccessLogTableName, model.AccessLogTableName, start, end); err != nil {
		t.Fatalf("重复导出失败: %v", err)
	}
	dstDB.Model(&model.AccessLog{}).Count(&got)
	if got != 1500 {
		t.Fatalf("重复导出后应仍 1500 行，实际 %d", got)
	}
}

// 守护用例：导出必须跨数据源扇出——只导实时库时，时间段落在归档分区里的数据会整张空表。
// 造「实时 + 边界归档（access_log 与 web_logs 并存）」两个源，行数要合并且两层都要带出来。
func TestExportLogRangeDbFansOutAcrossSources(t *testing.T) {
	liveDB := openTenantTestDB(t, "sqlite")
	archDB := openTenantTestDB(t, "sqlite")
	for _, db := range []*gorm.DB{liveDB, archDB} {
		if err := db.AutoMigrate(&model.AccessLog{}, &innerbean.WebLog{}); err != nil {
			t.Fatalf("建表失败: %v", err)
		}
	}
	base := time.Date(2026, 9, 28, 12, 0, 0, 0, time.Local)
	ts := func(i int) string { return base.Add(time.Duration(i) * time.Minute).Format("2006-01-02 15:04:05") }

	put := func(db *gorm.DB, prefix string, n int) {
		for i := 0; i < n; i++ {
			row := &model.AccessLog{LogNarrow: model.LogNarrow{
				ReqUUID: fmt.Sprintf("%s-a%d", prefix, i), CREATE_TIME: ts(i)}}
			if err := db.Create(row).Error; err != nil {
				t.Fatalf("写 access_log 失败: %v", err)
			}
		}
	}
	put(liveDB, "live", 3)
	put(archDB, "arch", 2)
	for i := 0; i < 2; i++ {
		row := &innerbean.WebLog{REQ_UUID: fmt.Sprintf("arch-w%d", i), CREATE_TIME: ts(i)}
		if err := archDB.Create(row).Error; err != nil {
			t.Fatalf("写 web_logs 失败: %v", err)
		}
	}

	out := filepath.Join(t.TempDir(), "export.db")
	sources := []ExportSource{
		{Shard: "local_log.db", Tables: TierTables{DB: liveDB, Access: model.AccessLogTableName, WebLog: LogTableName}},
		{Shard: "local_log_202609.db", Tables: TierTables{DB: archDB, Access: model.AccessLogTableName, WebLog: LogTableName}},
	}
	tiers := map[string]bool{ExportTierAccess: true, ExportTierWeblog: true}
	counts, err := ExportLogRangeDb(out, ts(0), ts(10), tiers, sources)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if counts[ExportTierAccess] != 5 || counts[ExportTierWeblog] != 2 {
		t.Fatalf("行数应为 access=5 weblog=2，实际 %+v", counts)
	}

	// 用同一密钥打开导出件复核
	dsn := out + "?_db_key=" + url.QueryEscape(global.GWAF_PWD_LOGDB)
	check, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开导出件失败: %v", err)
	}
	defer func() {
		if s, e := check.DB(); e == nil {
			_ = s.Close()
		}
	}()
	var n int64
	if err := check.Table(model.AccessLogTableName).Count(&n).Error; err != nil || n != 5 {
		t.Fatalf("导出件 access_log 应 5 行，实际 %d (%v)", n, err)
	}
	if err := check.Table(LogTableName).Count(&n).Error; err != nil || n != 2 {
		t.Fatalf("导出件 web_logs 应 2 行，实际 %d (%v)", n, err)
	}
	// 未选中的层不该在导出件里留下空表
	if check.Migrator().HasTable(model.SecurityEventTableName) {
		t.Fatal("未选中 event 层，导出件里不该有 security_event 表")
	}
}

// 导出专用的层解析：边界分片新旧两层并存时两层都要（读侧只选新层，导出要把数据都带上）。
func TestResolveExportTablesBoundaryArchiveKeepsBothTiers(t *testing.T) {
	const name = "local_log_20260101000009.db"
	makeArchive(t, name, 3, 2)
	t.Cleanup(func() { closeShardDB(name) })

	tier := ResolveExportTables(name)
	if tier.Err != nil {
		t.Fatalf("打开归档失败: %v", tier.Err)
	}
	if tier.Access == "" || tier.WebLog == "" {
		t.Fatalf("边界分片应同时导出两层，实际 %+v", tier)
	}
	if tier.Empty {
		t.Fatal("有数据的归档不该标成空")
	}
}
