package wafdb

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"SamWaf/common/uuid"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openShardTestDBs(t *testing.T) (core, logDB *gorm.DB) {
	t.Helper()
	core = openTenantTestDB(t, "sqlite")
	if err := core.AutoMigrate(&model.ShareDb{}); err != nil {
		t.Fatalf("建 share_dbs 失败: %v", err)
	}
	logDB = openTenantTestDB(t, "sqlite")
	if err := logDB.AutoMigrate(&innerbean.WebLog{}); err != nil {
		t.Fatalf("建 web_logs 失败: %v", err)
	}
	return core, logDB
}

func countShard(t *testing.T, core *gorm.DB, name string) int64 {
	t.Helper()
	var n int64
	if err := core.Model(&model.ShareDb{}).Where("file_name = ?", name).Count(&n).Error; err != nil {
		t.Fatalf("统计 %s 失败: %v", name, err)
	}
	return n
}

// 已有归档分片、却没有实时记录时也要补上：只在整表为空时才补的话，这种库会一直缺这一行，
// 归档列表里就没有任何一项被标为 is_current。
func TestEnsureLiveShardRecordWithArchivesOnly(t *testing.T) {
	core, logDB := openShardTestDBs(t)
	for _, name := range []string{"local_log_20260615173225.db", "local_log_20260616092350.db"} {
		if err := core.Create(&model.ShareDb{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, DbLogicType: "log", FileName: name}).Error; err != nil {
			t.Fatalf("写归档记录失败: %v", err)
		}
	}

	ensureLiveShardRecord(core, logDB, enums.DB_LOG)

	if got := countShard(t, core, enums.DB_LOG); got != 1 {
		t.Fatalf("实时记录条数 = %d，应为 1", got)
	}
}

func TestEnsureLiveShardRecordIdempotent(t *testing.T) {
	core, logDB := openShardTestDBs(t)

	ensureLiveShardRecord(core, logDB, enums.DB_LOG)
	ensureLiveShardRecord(core, logDB, enums.DB_LOG)

	if got := countShard(t, core, enums.DB_LOG); got != 1 {
		t.Fatalf("重复调用后实时记录条数 = %d，应为 1", got)
	}
}

// 补登用的名字必须和归档列表判 is_current 用的是同一个。
func TestLiveLogNameSQLite(t *testing.T) {
	if got := LiveLogName(); got != enums.DB_LOG {
		t.Fatalf("SQLite 下 LiveLogName() = %q，应为 %q", got, enums.DB_LOG)
	}
}

// —— 归档分片只读打开与按数据选层 ——

// makeArchive 在 ./data 下造一个归档文件：建出全部四张日志表（模拟被旧版打开过、跑过迁移的归档），
// legacyRows 行写进 web_logs，accessRows 行写进 access_log。
func makeArchive(t *testing.T, name string, legacyRows, accessRows int) string {
	t.Helper()
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("data", name)
	dsn := path + "?_db_key=" + url.QueryEscape(global.GWAF_PWD_LOGDB)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("建归档文件失败: %v", err)
	}
	if err := db.AutoMigrate(&innerbean.WebLog{}, &model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	for i := 0; i < legacyRows; i++ {
		row := &innerbean.WebLog{REQ_UUID: fmt.Sprintf("%s_w%d", name, i), TenantId: global.GWAF_TENANT_ID,
			USER_CODE: global.GWAF_USER_CODE, UNIX_ADD_TIME: int64(i + 1)}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("写 web_logs 失败: %v", err)
		}
	}
	for i := 0; i < accessRows; i++ {
		row := &model.AccessLog{LogNarrow: model.LogNarrow{ReqUUID: fmt.Sprintf("%s_a%d", name, i),
			TenantId: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE, UNIX_ADD_TIME: int64(i + 1)}}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("写 access_log 失败: %v", err)
		}
	}
	if s, e := db.DB(); e == nil {
		_ = s.Close()
	}
	return path
}

// 改造边界切出来的分片（以及被旧版打开过的归档）同时有 web_logs 数据与空的新表：
// 必须读 web_logs，不能因为新表「存在」就去读空表。
func TestResolveTierTablesPollutedArchiveReadsWebLogs(t *testing.T) {
	const name = "local_log_20260101000001.db"
	path := makeArchive(t, name, 3, 0)
	t.Cleanup(func() { closeShardDB(name) })
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	tier := ResolveTierTables(name)
	if tier.Err != nil {
		t.Fatalf("打开归档失败: %v", tier.Err)
	}
	// 对照：新表确实存在，按存在性选层就会读到空表
	if !tier.DB.Migrator().HasTable(model.AccessLogTableName) {
		t.Fatal("对照组失效：归档里应当有空的 access_log")
	}
	if tier.WebLog != LogTableName || tier.Access != "" || tier.Event != "" {
		t.Fatalf("应读 web_logs、新表置空，实际 %+v", tier)
	}
	var n int64
	if err := tier.DB.Table(tier.WebLog).Count(&n).Error; err != nil || n != 3 {
		t.Fatalf("应读到 3 行，实际 %d (%v)", n, err)
	}
	if tier.Empty {
		t.Fatal("有数据的归档不该标成空")
	}

	// 只读：连接层拒写，文件大小与修改时间不变
	if err := tier.DB.Exec("DELETE FROM web_logs").Error; err == nil {
		t.Fatal("归档连接不该能写")
	}
	closeShardDB(name)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("归档文件被改动：%d/%v → %d/%v", before.Size(), before.ModTime(), after.Size(), after.ModTime())
	}
	if _, err := os.Stat(path + "-wal"); err == nil {
		if fi, _ := os.Stat(path + "-wal"); fi.Size() > 0 {
			t.Fatal("只读打开不该留下有内容的 WAL")
		}
	}
}

func TestResolveTierTablesTieredArchiveReadsNewTables(t *testing.T) {
	const name = "local_log_20260101000002.db"
	makeArchive(t, name, 0, 2)
	t.Cleanup(func() { closeShardDB(name) })

	tier := ResolveTierTables(name)
	if tier.Err != nil {
		t.Fatalf("打开归档失败: %v", tier.Err)
	}
	if tier.Access != model.AccessLogTableName || tier.Event != model.SecurityEventTableName || tier.WebLog != "" {
		t.Fatalf("分层之后的归档应读新表，实际 %+v", tier)
	}
}

func TestResolveTierTablesEmptyArchive(t *testing.T) {
	const name = "local_log_20260101000003.db"
	makeArchive(t, name, 0, 0)
	t.Cleanup(func() { closeShardDB(name) })

	tier := ResolveTierTables(name)
	if tier.Err != nil || !tier.Empty {
		t.Fatalf("空归档应可打开且标为空，实际 %+v", tier)
	}
}

// 文件不在时报缺失，且不能在原位置建出一个空库，也不能回落实时库
func TestResolveTierTablesMissingArchive(t *testing.T) {
	const name = "local_log_20260101000004.db"
	tier := ResolveTierTables(name)
	if !errors.Is(tier.Err, ErrShardMissing) {
		t.Fatalf("应报 ErrShardMissing，实际 %v", tier.Err)
	}
	if tier.DB != nil {
		t.Fatal("缺失的分片不该返回任何连接")
	}
	if _, err := os.Stat(filepath.Join("data", name)); !os.IsNotExist(err) {
		t.Fatal("打开缺失分片时在原位置建出了文件")
	}
	if !ShardFileMissing(name) {
		t.Fatal("ShardFileMissing 应为 true")
	}
}

func TestResolveTierTablesRejectsBadNames(t *testing.T) {
	for _, name := range []string{"../local.db", "local_log_1.db/../../x.db", "local.db", "local_log_abc.db"} {
		if tier := ResolveTierTables(name); tier.Err == nil {
			t.Fatalf("%q 不该被当成归档打开", name)
		}
	}
}

// 淘汰出缓存的连接在宽限期内仍可用；显式关闭时连同宽限期里的一起关掉
func TestShardRetireKeepsConnectionUsable(t *testing.T) {
	names := make([]string, 0, shardCacheMax+1)
	for i := 0; i <= shardCacheMax; i++ {
		name := fmt.Sprintf("local_log_2026020100%04d.db", i)
		makeArchive(t, name, 1, 0)
		names = append(names, name)
	}
	t.Cleanup(func() {
		for _, n := range names {
			closeShardDB(n)
		}
	})
	first := ResolveTierTables(names[0])
	if first.Err != nil {
		t.Fatal(first.Err)
	}
	for _, n := range names[1:] {
		if tier := ResolveTierTables(n); tier.Err != nil {
			t.Fatal(tier.Err)
		}
	}
	if getShardDB(names[0]) != nil {
		t.Fatal("超过上限后最早的连接应被移出缓存")
	}
	var n int64
	if err := first.DB.Table(LogTableName).Count(&n).Error; err != nil {
		t.Fatalf("宽限期内被淘汰的连接应仍可用: %v", err)
	}
	closeShardDB(names[0])
	if err := first.DB.Table(LogTableName).Count(&n).Error; err == nil {
		t.Fatal("显式关闭后宽限期里的连接也应已关")
	}
}

func TestShardHasIndex(t *testing.T) {
	const name = "local_log_20260101000005.db"
	makeArchive(t, name, 1, 0)
	t.Cleanup(func() { closeShardDB(name) })
	tier := ResolveTierTables(name)
	if tier.Err != nil {
		t.Fatal(tier.Err)
	}
	if ShardHasIndex(tier.DB, name, LogTableName, "idx_no_such_index") {
		t.Fatal("不存在的索引应返回 false")
	}
	if !ShardHasIndex(tier.DB, name, LogTableName, "idx_weblog_time") {
		t.Fatal("结构体上声明的索引应存在")
	}
}
