package wafdb

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func resetExportGlobals(t *testing.T) func() {
	t.Helper()
	oldDialect := dialect.Get()
	oldLog := global.GWAF_LOCAL_LOG_DB
	return func() {
		dialect.Register(oldDialect)
		global.GWAF_LOCAL_LOG_DB = oldLog
	}
}

func TestLogExportRowsLiveSourceBatching(t *testing.T) {
	defer resetExportGlobals(t)()
	db := openTenantTestDB(t, "sqlite")
	global.GWAF_LOCAL_LOG_DB = db
	base := time.Date(2026, 10, 29, 0, 0, 0, 0, time.Local)
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "tenantA", "userA"
	t.Cleanup(func() { global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser })
	if err := db.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	rows := make([]model.AccessLog, 0, exportBatchSize+7)
	for i := 0; i < exportBatchSize+7; i++ {
		rows = append(rows, model.AccessLog{LogNarrow: model.LogNarrow{
			ReqUUID:     fmt.Sprintf("uuid-%05d", i),
			TenantId:    "tenantA",
			UserCode:    "userA",
			CREATE_TIME: base.Add(time.Duration(i) * time.Second).Format("2006-01-02 15:04:05"),
		}})
	}
	for i := range rows {
		if i%7 == 0 {
			rows[i].Host = "示例主机"
		}
	}
	for i := 0; i < exportBatchSize+7; i += 50 {
		hi := i + 50
		if hi > len(rows) {
			hi = len(rows)
		}
		chunk := rows[i:hi]
		if err := db.Create(&chunk).Error; err != nil {
			t.Fatalf("造数失败: %v", err)
		}
	}

	seen, batches := 0, 0
	end := base.Add((exportBatchSize + 7) * time.Second).Format("2006-01-02 15:04:05")
	onBatch := func(b ExportRowBatch) error {
		if b.Table != model.AccessLogTableName {
			return errors.New("wrong table")
		}
		for _, row := range b.Rows {
			seen++
			if row["req_uuid"] == "" {
				return errors.New("missing req_uuid")
			}
			if row["create_time"] == "" {
				return errors.New("missing create_time")
			}
		}
		batches++
		return nil
	}
	release, err := AcquireLogRead(context.Background())
	if err != nil {
		t.Fatalf("取读锁失败: %v", err)
	}
	defer release()
	st, err := ReadExportSource(context.Background(), "", "tenantA", "", end, []string{model.AccessLogTableName}, onBatch)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if st.Tables[model.AccessLogTableName].Rows != int64(seen) || seen != exportBatchSize+7 {
		t.Fatalf("行数错误: status=%d seen=%d", st.Tables[model.AccessLogTableName].Rows, seen)
	}
	if st.SnapshotTime.IsZero() {
		t.Fatal("快照时间未记录")
	}
	if st.Tables[model.AccessLogTableName].State != "ready" || len(st.Tables[model.AccessLogTableName].MissingColumns) != 0 {
		t.Fatalf("缺列处理错误: %+v", st.Tables[model.AccessLogTableName])
	}
}

type exportServerDialect struct {
	dialect.DBDialect
}

func (d exportServerDialect) Name() string      { return "mysql" }
func (d exportServerDialect) IsFileBased() bool { return false }
func (d exportServerDialect) ListTables(*gorm.DB) ([]string, error) {
	return []string{}, nil
}

func TestLogExportRowsArchiveSourceMissingTable(t *testing.T) {
	defer resetExportGlobals(t)()
	db := openTenantTestDB(t, "sqlite")
	global.GWAF_LOCAL_LOG_DB = db
	dialect.Register(exportServerDialect{dialect.Get()})
	release, err := AcquireLogRead(context.Background())
	if err != nil {
		t.Fatalf("取读锁失败: %v", err)
	}
	defer release()
	_, err = ReadExportSource(context.Background(), model.AccessLogTableName+"_202609", "tenantA", "", "2026-10-29 00:00:00", []string{model.AccessLogTableName, model.SecurityEventTableName}, func(ExportRowBatch) error { return nil })
	if !errors.Is(err, ErrExportSourceMapping) {
		t.Fatalf("旧周期映射应报明确错误，实际: %v", err)
	}
}

func TestLogExportRowsArchiveFilePathSafety(t *testing.T) {
	defer resetExportGlobals(t)()
	_, _, _, _, err := openExportSource(context.Background(), "../local_log.db")
	if err == nil {
		t.Fatal("路径穿越应被拒绝")
	}
	_, _, _, _, err = openExportSource(context.Background(), "local_log_abc.db")
	if err == nil {
		t.Fatal("非法归档名应被拒绝")
	}
}

func TestLogExportRowsStrictTableSelection(t *testing.T) {
	defer resetExportGlobals(t)()
	dialect.Register(&dialect.SQLiteDialect{})
	global.GWAF_LOCAL_LOG_DB = openTenantTestDB(t, "sqlite")
	for _, tables := range [][]string{
		{"web_logs"}, {"event_payload"}, {"ACCESS_LOG"}, {"access_log;SELECT 1"},
		{"access_log_202609"}, {" access_log"}, {"access_log", "access_log"},
		{"access_log", "event_payload"}, {}, {"access_log", "security_event", "web_logs"},
	} {
		t.Run(strings.Join(tables, ","), func(t *testing.T) {
			called := false
			_, err := ReadExportSource(context.Background(), "", "tenantA", "", "2026-10-30 00:00:00", tables, func(ExportRowBatch) error {
				called = true
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "invalid export") || called {
				t.Fatalf("invalid selection accepted: tables=%q err=%v callback=%v", tables, err, called)
			}
		})
	}
}

type exportHistoricalRow struct {
	ReqUUID    string `gorm:"primaryKey"`
	TenantID   string
	UserCode   string
	CreateTime string
	URL        *string
}

func TestLogExportRowsIsolationMissingColumnsAndBoundary(t *testing.T) {
	defer resetExportGlobals(t)()
	dialect.Register(&dialect.SQLiteDialect{})
	db := openTenantTestDB(t, "sqlite")
	global.GWAF_LOCAL_LOG_DB = db
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "tenantA", "userA"
	t.Cleanup(func() { global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser })
	if e := db.Table("access_log").AutoMigrate(&exportHistoricalRow{}); e != nil {
		t.Fatal(e)
	}
	empty := ""
	rows := []exportHistoricalRow{
		{"a", "tenantA", "userA", "2026-10-29 01:00:00", nil},
		{"b", "tenantA", "userA", "2026-10-29 01:30:00", &empty},
		{"other-tenant", "tenantB", "userA", "2026-10-29 01:30:00", nil},
		{"other-user", "tenantA", "userB", "2026-10-29 01:30:00", nil},
		{"before", "tenantA", "userA", "2026-10-29 00:59:59", nil},
		{"end", "tenantA", "userA", "2026-10-29 02:00:00", nil},
	}
	if e := db.Table("access_log").Create(&rows).Error; e != nil {
		t.Fatal(e)
	}
	// Explicit source conditions must hold even without an installed callback.
	var got []map[string]interface{}
	read := func() (ExportSourceStatus, error) {
		got = nil
		return ReadExportSource(context.Background(), "", "tenantA", "2026-10-29 01:00:00", "2026-10-29 02:00:00", []string{"access_log", "security_event"}, func(b ExportRowBatch) error {
			if b.Table != "access_log" {
				t.Fatalf("unexpected callback table %q", b.Table)
			}
			got = append(got, b.Rows...)
			return nil
		})
	}
	assert := func(st ExportSourceStatus, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		if len(got) != 2 || got[0]["req_uuid"] != "a" || got[1]["req_uuid"] != "b" {
			t.Fatalf("unexpected isolated rows: %v", got)
		}
		if got[0]["url"] != nil || got[1]["url"] != "" {
			t.Fatalf("NULL/empty changed: %v", got)
		}
		if v, ok := got[0]["actor_key"]; !ok || v != nil {
			t.Fatalf("missing column must be NULL: %v", got[0])
		}
		if st.Tables["security_event"].State != "missing" || st.Tables["access_log"].State != "ready" {
			t.Fatalf("wrong table states: %+v", st.Tables)
		}
		if !reflect.DeepEqual(st.Tables["access_log"].Rows, int64(2)) {
			t.Fatalf("wrong count: %+v", st)
		}
	}
	st, e := read()
	assert(st, e)
	if e := db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query); e != nil {
		t.Fatal(e)
	}
	st, e = read()
	assert(st, e)
}

func TestLogExportRowsSnapshotAndCancellation(t *testing.T) {
	defer resetExportGlobals(t)()
	dialect.Register(&dialect.SQLiteDialect{})
	db := openTenantTestDB(t, "sqlite")
	global.GWAF_LOCAL_LOG_DB = db
	if e := db.Exec("PRAGMA journal_mode=WAL").Error; e != nil {
		t.Fatal(e)
	}
	oldUser := global.GWAF_USER_CODE
	global.GWAF_USER_CODE = "userA"
	t.Cleanup(func() { global.GWAF_USER_CODE = oldUser })
	if e := db.Table("access_log").AutoMigrate(&exportHistoricalRow{}); e != nil {
		t.Fatal(e)
	}
	if e := db.Table("security_event").AutoMigrate(&exportHistoricalRow{}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 1001; i++ {
		r := exportHistoricalRow{ReqUUID: fmt.Sprintf("row-%05d", i), TenantID: "tenantA", UserCode: "userA", CreateTime: "2026-10-29 01:00:00"}
		if e := db.Table("access_log").Create(&r).Error; e != nil {
			t.Fatal(e)
		}
	}
	event := exportHistoricalRow{ReqUUID: "event-original", TenantID: "tenantA", UserCode: "userA", CreateTime: "2026-10-29 01:00:00"}
	if e := db.Table("security_event").Create(&event).Error; e != nil {
		t.Fatal(e)
	}
	seen := map[string]int{}
	batches := 0
	_, e := ReadExportSource(context.Background(), "", "tenantA", "", "2026-10-30 00:00:00", []string{"access_log", "security_event"}, func(b ExportRowBatch) error {
		batches++
		seen[b.Table] += len(b.Rows)
		if batches == 1 {
			for _, table := range []string{"access_log", "security_event"} {
				r := exportHistoricalRow{ReqUUID: "zz-late", TenantID: "tenantA", UserCode: "userA", CreateTime: "2026-10-29 01:00:00"}
				if e := db.Table(table).Create(&r).Error; e != nil {
					return e
				}
			}
			if e := db.Table("access_log").Where("req_uuid = ?", "row-01000").Update("url", "changed after snapshot").Error; e != nil {
				return e
			}
		}
		for _, r := range b.Rows {
			if r["req_uuid"] == "zz-late" || r["url"] == "changed after snapshot" {
				return errors.New("snapshot included later write")
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if seen["access_log"] != 1001 || seen["security_event"] != 1 || batches != 3 {
		t.Fatalf("snapshot rows=%v batches=%d", seen, batches)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, e = ReadExportSource(ctx, "", "tenantA", "", "2026-10-30 00:00:00", []string{"access_log"}, func(ExportRowBatch) error { cancel(); return nil })
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("cancel not propagated: %v", e)
	}
	var n int64
	if e := db.Table("access_log").Count(&n).Error; e != nil {
		t.Fatalf("connection not released: %v", e)
	}
}

func TestLogExportRowsRealSQLiteArchive(t *testing.T) {
	defer resetExportGlobals(t)()
	dialect.Register(&dialect.SQLiteDialect{})
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "data"), 0700); e != nil {
		t.Fatal(e)
	}
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chdir(root); e != nil {
		t.Fatal(e)
	}
	defer os.Chdir(cwd)
	t.Setenv("SamWafIDE", "1")
	oldKey, oldTenant, oldUser := global.GWAF_PWD_LOGDB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_PWD_LOGDB = "export-isolated-test-key"
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "tenantA", "userA"
	defer func() {
		global.GWAF_PWD_LOGDB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldKey, oldTenant, oldUser
	}()
	name := "local_log_202609.db"
	path := filepath.Join(root, "data", name)
	db, e := gorm.Open(sqlite.Open(path+"?_db_key="+url.QueryEscape(global.GWAF_PWD_LOGDB)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := db.DB()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if e = db.Table("security_event").AutoMigrate(&exportHistoricalRow{}); e != nil {
		t.Fatal(e)
	}
	r := exportHistoricalRow{ReqUUID: "archive-event", TenantID: "tenantA", UserCode: "userA", CreateTime: "2026-09-20 12:00:00"}
	if e = db.Table("security_event").Create(&r).Error; e != nil {
		t.Fatal(e)
	}
	if e = conn.Close(); e != nil {
		t.Fatal(e)
	}
	var got []string
	st, e := ReadExportSource(context.Background(), name, "tenantA", "", "2026-10-30 00:00:00", []string{"access_log", "security_event"}, func(b ExportRowBatch) error {
		for _, r := range b.Rows {
			got = append(got, r["req_uuid"].(string))
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(got, []string{"archive-event"}) || st.Tables["access_log"].State != "missing" || st.Tables["security_event"].State != "ready" {
		t.Fatalf("wrong real archive result: rows=%v status=%+v", got, st)
	}
	_, e = ReadExportSource(context.Background(), "local_log_202608.db", "tenantA", "", "2026-10-30 00:00:00", []string{"access_log"}, func(ExportRowBatch) error { return nil })
	if !errors.Is(e, ErrShardMissing) {
		t.Fatalf("missing archive not classified: %v", e)
	}
	if _, e = os.Stat(filepath.Join(root, "data", "local_log_202608.db")); !os.IsNotExist(e) {
		t.Fatalf("missing archive created: %v", e)
	}
	opened, _, _, closeDB, e := openExportSource(context.Background(), name)
	if e != nil {
		t.Fatal(e)
	}
	defer closeDB()
	if e = opened.Table("security_event").Create(&exportHistoricalRow{ReqUUID: "should-not-write"}).Error; e == nil {
		t.Fatal("archive connection allowed writes")
	}
}

func TestLogExportSourceWALBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.db")
	if e := os.WriteFile(path+"-wal", make([]byte, 17), 0600); e != nil {
		t.Fatal(e)
	}
	if e := checkExportWAL(path, 16); !errors.Is(e, ErrExportSourcePressure) {
		t.Fatalf("WAL pressure not rejected: %v", e)
	}
	if e := checkExportWAL(path, 17); e != nil {
		t.Fatal(e)
	}
}

func TestLogLifecycleReadersShareWriterWaits(t *testing.T) {
	ctx := context.Background()
	r1, err := AcquireLogRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := AcquireLogRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctxw, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := AcquireLogWrite(ctxw); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("写租约应等待读者释放，实际: %v", err)
	}
	r1()
	r2()
	w, err := AcquireLogWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readCtx, cancelRead := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancelRead()
	if release, err := AcquireLogRead(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			release()
		}
		t.Fatalf("read lease bypassed active writer: %v", err)
	}
	w()
	w()
	r3, err := AcquireLogRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r3()
}
