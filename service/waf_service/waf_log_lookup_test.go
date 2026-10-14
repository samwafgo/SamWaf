package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupLogLookupTest(t *testing.T) (*gorm.DB, *gorm.DB, string) {
	t.Helper()
	priorDialect := func() (d dialect.DBDialect) {
		defer func() { _ = recover() }()
		return dialect.Get()
	}()
	dialect.Register(&dialect.SQLiteDialect{})
	oldCore, oldLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	oldTenant, oldUser, oldKey := global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GWAF_PWD_LOGDB
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GWAF_PWD_LOGDB = "lookup-tenant", "lookup-user", ""
	InvalidateShardCounts()
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = oldCore, oldLog
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GWAF_PWD_LOGDB = oldTenant, oldUser, oldKey
		InvalidateShardCounts()
		dialect.Register(priorDialect)
	})
	open := func(path string) *gorm.DB {
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sqlDB, _ := db.DB(); _ = sqlDB.Close() })
		return db
	}
	root := t.TempDir()
	core, live := open(filepath.Join(root, "core.db")), open(filepath.Join(root, "live.db"))
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = core, live
	if err := core.AutoMigrate(&model.ShareDb{}); err != nil {
		t.Fatal(err)
	}
	if err := live.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}, &innerbean.WebLog{}); err != nil {
		t.Fatal(err)
	}
	for _, db := range []*gorm.DB{core, live} {
		if err := db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", func(d *gorm.DB) {
			d.Where("tenant_id = ? and user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
		}); err != nil {
			t.Fatal(err)
		}
	}
	return core, live, root
}

func TestLogLookupUUIDIgnoresSelectedShardAndDate(t *testing.T) {
	core, _, root := setupLogLookupTest(t)
	const archiveName = "local_log_202001.db"
	if err := os.Mkdir(filepath.Join(root, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	archive, err := gorm.Open(sqlite.Open(filepath.Join(root, "data", archiveName)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	archiveSQL, _ := archive.DB()
	t.Cleanup(func() { _ = archiveSQL.Close() })
	if err = archive.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2020, 1, 10, 12, 0, 0, 0, time.Local)
	narrow := model.LogNarrow{
		ReqUUID: "fan_nonstandard_202001_0", TenantId: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE,
		HostCode: "host-old", Method: "GET", SRC_IP: "203.0.113.8", RULE: "CC封禁", ACTION: "阻止",
		UNIX_ADD_TIME: at.UnixMilli(), CREATE_TIME: at.Format("2006-01-02 15:04:05"), USER_AGENT: "lookup-agent",
	}
	for _, row := range []interface{}{&model.AccessLog{LogNarrow: narrow}, &model.SecurityEvent{LogNarrow: narrow}} {
		if err = archive.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	foreign := narrow
	foreign.ReqUUID, foreign.TenantId = "req_foreign_tenant", "other-tenant"
	if err = archive.Create(&model.AccessLog{LogNarrow: foreign}).Error; err != nil {
		t.Fatal(err)
	}
	if err = core.Create(&model.ShareDb{
		BaseOrm: baseorm.BaseOrm{Id: "lookup-archive", Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE},
		DbLogicType: "log", FileName: archiveName, Cnt: 2,
		StartTime: customtype.JsonTime(at.Add(-time.Hour)), EndTime: customtype.JsonTime(at.Add(time.Hour)),
	}).Error; err != nil {
		t.Fatal(err)
	}
	// 通过现有连接缓存装入临时归档，避免读取工作区 data/。
	if err = wafdb.InitManaulLogDb(root, archiveName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wafdb.CloseManualLogDb(archiveName) })

	base := request.WafAttackLogSearch{
		ReqUuid: "  " + narrow.ReqUUID + "  ", UnixAddTimeBegin: "4102444800000", UnixAddTimeEnd: "4102531200000",
		HostCode: narrow.HostCode, SrcIp: narrow.SRC_IP, Rule: narrow.RULE, FilterBy: "user_agent", FilterValue: "lookup-agent",
		SortBy: "unix_add_time", SortDescending: "desc",
	}
	base.PageIndex, base.PageSize = 1, 10
	for _, selected := range []string{"", AutoShard, wafdb.LiveLogName(), "local_log_199901.db"} {
		for _, view := range []string{"access", "event"} {
			t.Run(selected+"/"+view, func(t *testing.T) {
				req := base
				req.CurrrentDbName, req.ViewType = selected, view
				rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
				if err != nil || total != 1 || len(rows) != 1 || rows[0].REQ_UUID != narrow.ReqUUID || meta.FoundIn != archiveName || !meta.UuidLookup {
					t.Fatalf("archive UUID lookup: total=%d rows=%+v meta=%+v err=%v", total, rows, meta, err)
				}
			})
		}
	}
	for _, filter := range []string{"host", "ip", "rule", "header-filter", "tenant", "user", "missing"} {
		t.Run(filter, func(t *testing.T) {
			req := base
			req.CurrrentDbName = "local_log_199901.db"
			switch filter {
			case "host":
				req.HostCode = "other-host"
			case "ip":
				req.SrcIp = "203.0.113.9"
			case "rule":
				req.Rule = "other-rule"
			case "header-filter":
				req.FilterValue = "different-agent"
			case "tenant":
				req.ReqUuid = foreign.ReqUUID
			case "user":
				global.GWAF_USER_CODE = "other-user"
				defer func() { global.GWAF_USER_CODE = narrow.UserCode }()
			case "missing":
				req.ReqUuid = "req_missing"
			}
			rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
			if err != nil || total != 0 || len(rows) != 0 || !meta.UuidLookup {
				t.Fatalf("expected filtered empty lookup: total=%d rows=%+v meta=%+v err=%v", total, rows, meta, err)
			}
		})
	}
	// 无识别码仍按显式分区、日期查询。
	base.ReqUuid, base.CurrrentDbName = "   ", wafdb.LiveLogName()
	rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(base)
	if err != nil || len(rows) != 0 || total != 0 || meta.UuidLookup || len(meta.Shards) != 1 {
		t.Fatalf("ordinary selected query changed: total=%d meta=%+v err=%v", total, meta, err)
	}
}

func TestLogDetailMissingAndReadError(t *testing.T) {
	_, live, _ := setupLogLookupTest(t)
	for _, id := range []string{"req_missing", "   "} {
		got, err := WafLogServiceApp.GetDetailApi(request.WafAttackLogDetailReq{REQ_UUID: id, CurrrentDbName: wafdb.LiveLogName()})
		if !errors.Is(err, ErrLogNotFound) || got.REQ_UUID != "" {
			t.Fatalf("expected identifiable missing error: got=%+v err=%v", got, err)
		}
	}
	if _, err := WafLogServiceApp.GetDetailApi(request.WafAttackLogDetailReq{REQ_UUID: "req_missing", CurrrentDbName: "local_log_199901.db"}); err == nil || errors.Is(err, ErrLogNotFound) {
		t.Fatalf("missing shard must return storage error, got %v", err)
	}
	row := model.SecurityEvent{LogNarrow: model.LogNarrow{ReqUUID: "req_detail", TenantId: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE}}
	if err := live.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	got, err := WafLogServiceApp.GetDetailApi(request.WafAttackLogDetailReq{REQ_UUID: " req_detail ", CurrrentDbName: wafdb.LiveLogName()})
	if err != nil || got.REQ_UUID != row.ReqUUID {
		t.Fatalf("trimmed detail lookup: got=%+v err=%v", got, err)
	}
	if err := live.Callback().Query().Before("gorm:query").Register("test:read_error", func(db *gorm.DB) { db.AddError(errors.New("test read failure")) }); err != nil {
		t.Fatal(err)
	}
	if _, err := WafLogServiceApp.GetDetailApi(request.WafAttackLogDetailReq{REQ_UUID: row.ReqUUID, CurrrentDbName: wafdb.LiveLogName()}); err == nil || errors.Is(err, ErrLogNotFound) {
		t.Fatalf("read failure must remain an error, got %v", err)
	}
}
