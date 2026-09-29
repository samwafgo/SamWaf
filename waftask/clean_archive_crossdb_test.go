//go:build crossdb

// 过期回收（E3）的三库回归。
//
// 这条路径会**真的删数据**，而且 MySQL/PG 上原来根本没人清归档表，所以必须在真库上跑：
// 按层各走各的保留期（窄行短、事件与报文长）、只过期一层时分片记录要留着、
// 没有分片记录的孤儿分区按周期终点判、实时表一张都不能碰。
//
// 跑法：go test -tags crossdb ./waftask/ -run TestCleanExpiredArchiveShardCrossEngine
// MySQL / PostgreSQL 连不上时跳过，不阻塞；SQLite 走删文件那条路，本用例只管服务型数据库。
package waftask

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/partition"
	"os"
	"testing"
	"time"

	mysqldriver "gorm.io/driver/mysql"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const xtestArchiveDB = "samwaf_xtest_archive"

func TestCleanExpiredArchiveShardCrossEngine(t *testing.T) {
	engines := map[string]func(*testing.T) (*gorm.DB, func()){
		"mysql":    setupArchiveMySQL,
		"postgres": setupArchivePostgres,
	}
	for name, setup := range engines {
		t.Run(name, func(t *testing.T) {
			db, done := setup(t)
			if db == nil {
				t.Skip("引擎不可用，跳过")
			}
			defer done()
			runArchiveCleanupAssertions(t, db)
		})
	}
}

func runArchiveCleanupAssertions(t *testing.T, db *gorm.DB) {
	t.Helper()
	d := dialect.Get()

	prevCore, prevLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	prevDel, prevAccess := global.GDATA_DELETE_INTERVAL, global.GDATA_ACCESS_LOG_RETENTION_DAYS
	// 分片元数据与日志表放同一个库只是测试便利；生产里前者在核心库。
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = db, db
	global.GDATA_DELETE_INTERVAL = 180
	global.GDATA_ACCESS_LOG_RETENTION_DAYS = 30
	defer func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = prevCore, prevLog
		global.GDATA_DELETE_INTERVAL, global.GDATA_ACCESS_LOG_RETENTION_DAYS = prevDel, prevAccess
	}()

	now := time.Now()
	tiers := []string{model.AccessLogTableName, model.SecurityEventTableName, model.EventPayloadTableName}

	mkParts := func(key string) {
		for _, base := range tiers {
			if err := d.CreatePartition(db, base, partition.TableName(base, key)); err != nil {
				t.Fatalf("建分区 %s 失败: %v", partition.TableName(base, key), err)
			}
		}
	}
	mkShard := func(key string, end time.Time) {
		must(t, db.Create(&model.ShareDb{
			BaseOrm:     baseOrmFor("xshard_" + key),
			DbLogicType: "log",
			StartTime:   customtype.JsonTime(end.AddDate(0, 0, -30)),
			EndTime:     customtype.JsonTime(end),
			FileName:    partition.TableName(model.AccessLogTableName, key),
			PeriodKey:   key,
			Cnt:         1,
		}).Error)
	}

	// 场景 A：整段远超两个保留期 —— 三层全丢、分片记录一并删掉
	keyOld := partition.KeyOf(now.AddDate(0, 0, -400))
	mkParts(keyOld)
	mkShard(keyOld, now.AddDate(0, 0, -390))

	// 场景 B：过了窄行保留期(30)但没过日志保留期(180) —— 只丢窄行，其余留着，记录也要留着
	keyMid := partition.KeyOf(now.AddDate(0, 0, -60))
	if keyMid == keyOld {
		t.Fatalf("测试周期键撞车了: %s", keyMid)
	}
	mkParts(keyMid)
	mkShard(keyMid, now.AddDate(0, 0, -60))

	// 场景 C：孤儿分区（有表、没分片记录），周期终点远在保留期之外 —— 该被丢掉
	keyOrphan := partition.KeyOf(now.AddDate(0, 0, -800))
	mkParts(keyOrphan)

	CleanExpiredArchiveShard()

	// A：三层都该没了
	for _, base := range tiers {
		if name := partition.TableName(base, keyOld); d.TableExists(db, name) {
			t.Errorf("整段过期的分区 %s 应被丢掉", name)
		}
	}
	var cntOld int64
	must(t, db.Model(&model.ShareDb{}).Where("period_key = ?", keyOld).Count(&cntOld).Error)
	if cntOld != 0 {
		t.Errorf("整个分区都没了，分片记录应一并删除，实际还有 %d 条", cntOld)
	}

	// B：窄行丢掉、事件与报文留下、记录留下
	if name := partition.TableName(model.AccessLogTableName, keyMid); d.TableExists(db, name) {
		t.Errorf("窄行 %s 已过访问日志保留期，应被丢掉", name)
	}
	for _, base := range []string{model.SecurityEventTableName, model.EventPayloadTableName} {
		if name := partition.TableName(base, keyMid); !d.TableExists(db, name) {
			t.Errorf("%s 还在日志保留期内，不该被丢", name)
		}
	}
	var cntMid int64
	must(t, db.Model(&model.ShareDb{}).Where("period_key = ?", keyMid).Count(&cntMid).Error)
	if cntMid != 1 {
		t.Errorf("还有层没过期时分片记录必须留着，实际 %d 条", cntMid)
	}

	// C：孤儿分区被丢
	for _, base := range tiers {
		if name := partition.TableName(base, keyOrphan); d.TableExists(db, name) {
			t.Errorf("没有分片记录且早已过期的孤儿分区 %s 应被丢掉", name)
		}
	}

	// 实时表一张都不能少
	for _, base := range append(tiers, wafdb.LogTableName) {
		if !d.TableExists(db, base) {
			t.Fatalf("实时表 %s 被误删了", base)
		}
	}
}

// baseOrmFor 造一个够用的 BaseOrm（回收逻辑只认 Id 与归属列）
func baseOrmFor(id string) baseorm.BaseOrm {
	return baseorm.BaseOrm{
		Id:          id,
		USER_CODE:   "xtest_user",
		Tenant_ID:   "xtest_tenant",
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
}

func setupArchiveMySQL(t *testing.T) (*gorm.DB, func()) {
	base := os.Getenv("SAMWAF_TEST_MYSQL_DSN")
	if base == "" {
		base = "root:canteen1@tcp(127.0.0.1:3306)/"
	}
	root, err := gorm.Open(mysqldriver.Open(base+"?parseTime=true"), analysisSilentCfg)
	if err != nil {
		t.Logf("mysql 连接失败（跳过）: %v", err)
		return nil, nil
	}
	root.Exec("DROP DATABASE IF EXISTS " + xtestArchiveDB)
	if err := root.Exec("CREATE DATABASE " + xtestArchiveDB + " CHARACTER SET utf8mb4").Error; err != nil {
		t.Logf("mysql 建库失败（跳过）: %v", err)
		return nil, nil
	}
	dialect.Register(&dialect.MySQLDialect{})
	db, err := gorm.Open(mysqldriver.Open(base+xtestArchiveDB+"?charset=utf8mb4&parseTime=True&loc=Local"), analysisSilentCfg)
	if err != nil {
		t.Fatalf("mysql 打开失败: %v", err)
	}
	migrateArchiveSchema(t, db)
	return db, func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
		root.Exec("DROP DATABASE IF EXISTS " + xtestArchiveDB)
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}

func setupArchivePostgres(t *testing.T) (*gorm.DB, func()) {
	base := os.Getenv("SAMWAF_TEST_PG_DSN")
	if base == "" {
		base = "postgres://postgres:postgres@127.0.0.1:5432/"
	}
	root, err := gorm.Open(pgdriver.Open(base+"postgres?sslmode=disable"), analysisSilentCfg)
	if err != nil {
		t.Logf("postgres 连接失败（跳过）: %v", err)
		return nil, nil
	}
	root.Exec("DROP DATABASE IF EXISTS " + xtestArchiveDB)
	if err := root.Exec("CREATE DATABASE " + xtestArchiveDB + " ENCODING 'UTF8'").Error; err != nil {
		t.Logf("postgres 建库失败（跳过）: %v", err)
		return nil, nil
	}
	dialect.Register(&dialect.PostgresDialect{})
	db, err := gorm.Open(pgdriver.Open(base+xtestArchiveDB+"?sslmode=disable&TimeZone=Asia/Shanghai"), analysisSilentCfg)
	if err != nil {
		t.Fatalf("postgres 打开失败: %v", err)
	}
	migrateArchiveSchema(t, db)
	return db, func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
		root.Exec("DROP DATABASE IF EXISTS " + xtestArchiveDB)
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}

// migrateArchiveSchema 建出用例要的表：日志三层走真实迁移（嵌入结构的索引名在多张表上会撞，
// 直接 AutoMigrate 会失败，这是 M2 踩过的坑），分片元数据表单独 AutoMigrate。
func migrateArchiveSchema(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := wafdb.RunLogDBMigrations(db); err != nil {
		t.Fatalf("日志库迁移失败: %v", err)
	}
	if err := db.AutoMigrate(&model.ShareDb{}); err != nil {
		t.Fatalf("分片表迁移失败: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
}
