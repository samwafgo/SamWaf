//go:build crossdb

// 报文落库这一步的三库回归。splitForStore 的纯逻辑由 log_split_test.go 覆盖，
// 这里盯的是真正压到数据库上的那条语句：报文表以 req_uuid 为主键，
// 同一请求分两批入队就会撞主键，三个引擎的"冲突即跳过"写法各不相同，
// 撞坏了整批报文都写不进去（日志行还在，用户看到的是报文凭空消失）。
//
//	go test -tags crossdb ./wafqueue/ -run TestStorePayloadsCrossEngine -v
package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	mysqldriver "gorm.io/driver/mysql"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var silentCfg = &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}

type payloadEngine struct {
	name  string
	setup func(t *testing.T) (*gorm.DB, func())
}

func payloadEngines() []payloadEngine {
	return []payloadEngine{
		{"sqlite", func(t *testing.T) (*gorm.DB, func()) {
			dialect.Register(&dialect.SQLiteDialect{})
			path := filepath.Join(t.TempDir(), "payload_test.db")
			db, err := gorm.Open(sqlitedriver.Open(path), silentCfg)
			if err != nil {
				t.Logf("sqlite 打开失败（跳过）: %v", err)
				return nil, nil
			}
			return db, func() {
				if s, e := db.DB(); e == nil {
					s.Close()
				}
			}
		}},
		{"mysql", func(t *testing.T) (*gorm.DB, func()) {
			dsn := os.Getenv("SAMWAF_TEST_MYSQL_DSN")
			if dsn == "" {
				dsn = "root:canteen1@tcp(127.0.0.1:3306)/"
			}
			name := fmt.Sprintf("samwaf_payload_%d", time.Now().UnixNano()%100000)
			root, err := gorm.Open(mysqldriver.Open(dsn+"?charset=utf8mb4&parseTime=True&loc=Local"), silentCfg)
			if err != nil {
				t.Logf("mysql 连接失败（跳过）: %v", err)
				return nil, nil
			}
			if err := root.Exec("CREATE DATABASE " + name + " DEFAULT CHARACTER SET utf8mb4").Error; err != nil {
				t.Logf("mysql 建库失败（跳过）: %v", err)
				return nil, nil
			}
			dialect.Register(&dialect.MySQLDialect{})
			db, err := gorm.Open(mysqldriver.Open(dsn+name+"?charset=utf8mb4&parseTime=True&loc=Local"), silentCfg)
			if err != nil {
				t.Fatalf("mysql 打开 %s: %v", name, err)
			}
			return db, func() {
				if s, e := db.DB(); e == nil {
					s.Close()
				}
				root.Exec("DROP DATABASE IF EXISTS " + name)
				if s, e := root.DB(); e == nil {
					s.Close()
				}
			}
		}},
		{"postgres", func(t *testing.T) (*gorm.DB, func()) {
			base := os.Getenv("SAMWAF_TEST_PG_DSN")
			if base == "" {
				base = "postgres://postgres:postgres@127.0.0.1:5432/"
			}
			name := fmt.Sprintf("samwaf_payload_%d", time.Now().UnixNano()%100000)
			root, err := gorm.Open(pgdriver.Open(base+"postgres?sslmode=disable"), silentCfg)
			if err != nil {
				t.Logf("postgres 连接失败（跳过）: %v", err)
				return nil, nil
			}
			if err := root.Exec("CREATE DATABASE " + name + " ENCODING 'UTF8'").Error; err != nil {
				t.Logf("postgres 建库失败（跳过）: %v", err)
				return nil, nil
			}
			dialect.Register(&dialect.PostgresDialect{})
			db, err := gorm.Open(pgdriver.Open(base+name+"?sslmode=disable&TimeZone=Asia/Shanghai"), silentCfg)
			if err != nil {
				t.Fatalf("postgres 打开 %s: %v", name, err)
			}
			return db, func() {
				if s, e := db.DB(); e == nil {
					s.Close()
				}
				root.Exec("DROP DATABASE IF EXISTS " + name)
				if s, e := root.DB(); e == nil {
					s.Close()
				}
			}
		}},
	}
}

func TestStorePayloadsCrossEngine(t *testing.T) {
	zlog.InitZLog(false, "console")
	saved := global.GWAF_LOCAL_LOG_DB
	defer func() { global.GWAF_LOCAL_LOG_DB = saved }()

	for _, e := range payloadEngines() {
		e := e
		t.Run(e.name, func(t *testing.T) {
			db, teardown := e.setup(t)
			if db == nil {
				t.Skipf("%s 未就绪，跳过", e.name)
				return
			}
			defer teardown()
			if err := db.AutoMigrate(&model.EventPayload{}); err != nil {
				t.Fatalf("建 event_payload 失败: %v", err)
			}
			global.GWAF_LOCAL_LOG_DB = db

			rows := []*model.EventPayload{
				{ReqUUID: "u1", Kind: PayloadKindEvent, BODY: "a=1", CreateTime: "2026-09-17 10:00:00"},
				{ReqUUID: "u2", Kind: PayloadKindEvent, BODY: "b=2", CreateTime: "2026-09-17 10:00:00"},
			}
			storePayloads(rows)

			var n int64
			db.Model(&model.EventPayload{}).Count(&n)
			if n != 2 {
				t.Fatalf("首次写入应有 2 行，实际 %d", n)
			}

			// 同一请求分两批入队：主键撞上必须整批跳过而不是整批失败
			again := []*model.EventPayload{
				{ReqUUID: "u1", Kind: PayloadKindEvent, BODY: "a=1-late", CreateTime: "2026-09-17 10:00:01"},
				{ReqUUID: "u3", Kind: PayloadKindEvent, BODY: "c=3", CreateTime: "2026-09-17 10:00:01"},
			}
			storePayloads(again)

			db.Model(&model.EventPayload{}).Count(&n)
			if n != 3 {
				t.Fatalf("撞主键应跳过冲突行、写入新行，期望 3 行实际 %d（整批失败了？）", n)
			}
			var got model.EventPayload
			db.Where("req_uuid = ?", "u1").First(&got)
			if got.BODY != "a=1" {
				t.Fatalf("冲突行应保留先到的那条，实际 %q", got.BODY)
			}
		})
	}
}
