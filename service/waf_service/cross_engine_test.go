//go:build crossdb

// 跨三种数据库（SQLite / MySQL / PostgreSQL）兼容回归测试 —— 骨架与公共设施。
//
// 目标：对 service 层的数据库操作，在三种引擎各跑一遍，断言 ①不崩溃 ②数据正确。
// 建表走**真实迁移**（RunCoreDBMigrations/RunLogDBMigrations/RunStatsDBMigrations），
// 与生产完全一致（含索引、种子数据、方言分支），而非手写 AutoMigrate 清单。
//
// 分组用例分布在同包的其它 crossdb 文件里：
//   - cross_engine_core_test.go   core 库 CRUD（本阶段主体）
//   - cross_engine_log_test.go    log 库（后续阶段）
//   - cross_engine_stats_test.go  stats 库（后续阶段）
//
// 运行（三种库都开着时）：
//
//	go test -tags crossdb ./service/waf_service/ -run TestCrossEngine -v
//
// 连接可用环境变量覆盖：
//
//	SAMWAF_TEST_MYSQL_DSN="root:canteen1@tcp(127.0.0.1:3306)/"
//	SAMWAF_TEST_PG_DSN="postgres://postgres:postgres@127.0.0.1:5432/"
//
// 未就绪的引擎会被自动 Skip，不影响其它引擎。
package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"net/url"
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

const (
	xtestCoreDB  = "samwaf_xtest_core"
	xtestLogDB   = "samwaf_xtest_log"
	xtestStatsDB = "samwaf_xtest_stats"
	xtestUser    = "xtest_user"
	xtestTenant  = "xtest_tenant"
)

// xdb 打包一个引擎的三个库句柄
type xdb struct {
	core  *gorm.DB
	logdb *gorm.DB
	stats *gorm.DB
}

type xengine struct {
	name  string
	setup func(t *testing.T) (*xdb, func())
}

func xengines() []xengine {
	return []xengine{
		{"sqlite", setupSQLite},
		{"mysql", setupMySQL},
		{"postgres", setupPostgres},
	}
}

// registerTenantScope 复刻 wafdb.before_query：所有 GORM 查询自动加租户/用户过滤，
// 保持与生产一致（Raw/Exec 不受影响）。
func registerTenantScope(db *gorm.DB) {
	_ = db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", func(d *gorm.DB) {
		d.Where("tenant_id = ? and user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	})
}

// runRealMigrations 在给定连接上跑真实建表迁移并注册租户回调。
func migrateCore(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := wafdb.RunCoreDBMigrations(db); err != nil {
		t.Fatalf("core 迁移失败: %v", err)
	}
	if err := wafdb.RunTaskInitMigrations(db); err != nil {
		t.Fatalf("task 初始化迁移失败: %v", err)
	}
	registerTenantScope(db)
}

func migrateLog(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := wafdb.RunLogDBMigrations(db); err != nil {
		t.Fatalf("log 迁移失败: %v", err)
	}
	registerTenantScope(db)
}

func migrateStats(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := wafdb.RunStatsDBMigrations(db); err != nil {
		t.Fatalf("stats 迁移失败: %v", err)
	}
	registerTenantScope(db)
}

var silentCfg = &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}

func setupSQLite(t *testing.T) (*xdb, func()) {
	dir := t.TempDir()
	dialect.Register(&dialect.SQLiteDialect{})
	open := func(name, key string) *gorm.DB {
		dsn := filepath.Join(dir, name) + "?_db_key=" + url.QueryEscape(key)
		db, err := gorm.Open(sqlitedriver.Open(dsn), silentCfg)
		if err != nil {
			t.Fatalf("sqlite 打开 %s 失败: %v", name, err)
		}
		return db
	}
	core := open("core.db", "kcore")
	migrateCore(t, core)
	logdb := open("log.db", "klog")
	migrateLog(t, logdb)
	stats := open("stats.db", "kstats")
	migrateStats(t, stats)

	return &xdb{core, logdb, stats}, func() {
		for _, db := range []*gorm.DB{core, logdb, stats} {
			if s, e := db.DB(); e == nil {
				s.Close()
			}
		}
	}
}

func setupMySQL(t *testing.T) (*xdb, func()) {
	base := os.Getenv("SAMWAF_TEST_MYSQL_DSN")
	if base == "" {
		base = "root:canteen1@tcp(127.0.0.1:3306)/"
	}
	root, err := gorm.Open(mysqldriver.Open(base+"?parseTime=true"), silentCfg)
	if err != nil {
		t.Logf("mysql 连接失败（跳过）: %v", err)
		return nil, nil
	}
	names := []string{xtestCoreDB, xtestLogDB, xtestStatsDB}
	for _, n := range names {
		root.Exec("DROP DATABASE IF EXISTS " + n)
		if err := root.Exec("CREATE DATABASE " + n + " CHARACTER SET utf8mb4").Error; err != nil {
			t.Logf("mysql 建库 %s 失败（跳过）: %v", n, err)
			return nil, nil
		}
	}
	dialect.Register(&dialect.MySQLDialect{})
	open := func(n string) *gorm.DB {
		db, err := gorm.Open(mysqldriver.Open(base+n+"?charset=utf8mb4&parseTime=True&loc=Local"), silentCfg)
		if err != nil {
			t.Fatalf("mysql 打开 %s: %v", n, err)
		}
		return db
	}
	core := open(xtestCoreDB)
	migrateCore(t, core)
	logdb := open(xtestLogDB)
	migrateLog(t, logdb)
	stats := open(xtestStatsDB)
	migrateStats(t, stats)

	return &xdb{core, logdb, stats}, func() {
		for _, db := range []*gorm.DB{core, logdb, stats} {
			if s, e := db.DB(); e == nil {
				s.Close()
			}
		}
		for _, n := range names {
			root.Exec("DROP DATABASE IF EXISTS " + n)
		}
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}

func setupPostgres(t *testing.T) (*xdb, func()) {
	base := os.Getenv("SAMWAF_TEST_PG_DSN")
	if base == "" {
		base = "postgres://postgres:postgres@127.0.0.1:5432/"
	}
	root, err := gorm.Open(pgdriver.Open(base+"postgres?sslmode=disable"), silentCfg)
	if err != nil {
		t.Logf("postgres 连接失败（跳过）: %v", err)
		return nil, nil
	}
	names := []string{xtestCoreDB, xtestLogDB, xtestStatsDB}
	for _, n := range names {
		root.Exec("DROP DATABASE IF EXISTS " + n)
		if err := root.Exec("CREATE DATABASE " + n + " ENCODING 'UTF8'").Error; err != nil {
			t.Logf("postgres 建库 %s 失败（跳过）: %v", n, err)
			return nil, nil
		}
	}
	dialect.Register(&dialect.PostgresDialect{})
	open := func(n string) *gorm.DB {
		db, err := gorm.Open(pgdriver.Open(base+n+"?sslmode=disable&TimeZone=Asia/Shanghai"), silentCfg)
		if err != nil {
			t.Fatalf("postgres 打开 %s: %v", n, err)
		}
		return db
	}
	core := open(xtestCoreDB)
	migrateCore(t, core)
	logdb := open(xtestLogDB)
	migrateLog(t, logdb)
	stats := open(xtestStatsDB)
	migrateStats(t, stats)

	return &xdb{core, logdb, stats}, func() {
		for _, db := range []*gorm.DB{core, logdb, stats} {
			if s, e := db.DB(); e == nil {
				s.Close()
			}
		}
		for _, n := range names {
			root.Exec("DROP DATABASE IF EXISTS " + n)
		}
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}

func newBase(id string) baseorm.BaseOrm {
	return baseorm.BaseOrm{
		Id:          id,
		USER_CODE:   xtestUser,
		Tenant_ID:   xtestTenant,
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
}

func TestCrossEngine(t *testing.T) {
	zlog.InitZLog(false, "console") // 真实迁移内部大量 zlog.Info，未初始化会 nil panic
	global.GWAF_USER_CODE = xtestUser
	global.GWAF_TENANT_ID = xtestTenant
	global.GWAF_CUSTOM_SERVER_NAME = "xtest"

	for _, e := range xengines() {
		e := e
		t.Run(e.name, func(t *testing.T) {
			// 每个引擎前清空三个句柄，避免复用上一个引擎的连接
			global.GWAF_LOCAL_DB = nil
			global.GWAF_LOCAL_LOG_DB = nil
			global.GWAF_LOCAL_STATS_DB = nil

			x, teardown := e.setup(t)
			if x == nil {
				t.Skipf("%s 未就绪，跳过", e.name)
				return
			}
			defer teardown()
			global.GWAF_LOCAL_DB = x.core
			global.GWAF_LOCAL_LOG_DB = x.logdb
			global.GWAF_LOCAL_STATS_DB = x.stats

			// —— core 库 CRUD 用例（见 cross_engine_core_test.go）——
			runCoreCases(t, x.core)

			// —— log 库用例（见 cross_engine_log_test.go）——
			t.Run("log", func(t *testing.T) { runLogCases(t, x.logdb) })

			// —— stats 库用例（见 cross_engine_stats_test.go）——
			t.Run("stats", func(t *testing.T) { runStatsCases(t, x.stats) })

			// —— 有副作用 service 的 DB-only 路径（见 cross_engine_side_test.go）——
			t.Run("side", func(t *testing.T) { runSideCases(t, x) })

			// —— 方言 SQL 在各引擎真实执行 ——
			t.Run("DialectSQL", func(t *testing.T) {
				d := dialect.Get()
				db := x.core
				db.Exec("DROP TABLE IF EXISTS xtest_probe")
				fatalIf(t, db.Exec("CREATE TABLE xtest_probe (id varchar(64), tag varchar(64), cnt int)").Error)
				fatalIf(t, db.Exec("INSERT INTO xtest_probe (id,tag,cnt) VALUES ('a','t1',1),('b','t2',20)").Error)

				var s string
				fatalIf(t, db.Raw("SELECT "+d.GroupConcatDistinct("tag")+" FROM xtest_probe").Scan(&s).Error)

				fatalIf(t, db.Exec(d.BatchDeleteSQL("xtest_probe", "cnt < ?", 100), 10).Error)

				db.Exec("DROP TABLE IF EXISTS xtest_probe")
			})
		})
	}
}

// ————— 公共断言助手 —————

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("前置数据准备失败: %v", err)
	}
}

func fatalIf(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("操作失败: %v", err)
	}
}

// mustCount 断言某模型按条件的记录数
func countBy(t *testing.T, db *gorm.DB, dst interface{}, where string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := db.Model(dst).Where(where, args...).Count(&n).Error; err != nil {
		t.Fatalf("计数失败(%T): %v", dst, err)
	}
	return n
}

// assertGone 断言某 id 的记录已被删除
func assertGone(t *testing.T, db *gorm.DB, dst interface{}, id string) {
	t.Helper()
	if n := countBy(t, db, dst, "id = ?", id); n != 0 {
		t.Fatalf("记录应已删除但仍存在(%T id=%s)", dst, id)
	}
}
