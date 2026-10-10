//go:build crossdb

// 分析层汇总的三库回归。
//
// 这里的 upsert 走方言分支（UpsertExcludedRef 在 PG/SQLite 是 excluded.x、MySQL 是 VALUES(x)），
// 冲突目标又落在一个六列的唯一索引上——任一引擎对不上，症状都是「每批新建一行、计数翻倍」
// 这种不报错的静默错账，所以必须三边各跑一遍真实迁移 + 真实写入。
//
// 跑法：go test -tags crossdb ./waftask/ -run TestCollectAnalysisStatsCrossEngine
// MySQL / PostgreSQL 连不上时跳过，不阻塞。
package waftask

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	mysqldriver "gorm.io/driver/mysql"
	pgdriver "gorm.io/driver/postgres"
	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const xtestAnalysisDB = "samwaf_xtest_analysis"

var analysisSilentCfg = &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}

func TestCollectAnalysisStatsCrossEngine(t *testing.T) {
	engines := map[string]func(*testing.T) (*gorm.DB, func()){
		"sqlite":   setupAnalysisSQLite,
		"mysql":    setupAnalysisMySQL,
		"postgres": setupAnalysisPostgres,
	}
	for name, setup := range engines {
		t.Run(name, func(t *testing.T) {
			db, done := setup(t)
			if db == nil {
				t.Skip("引擎不可用，跳过")
			}
			defer done()
			runAnalysisAssertions(t, db)
		})
	}
}

func runAnalysisAssertions(t *testing.T, db *gorm.DB) {
	t.Helper()
	prev := global.GWAF_LOCAL_STATS_DB
	global.GWAF_LOCAL_STATS_DB = db
	defer func() { global.GWAF_LOCAL_STATS_DB = prev }()
	analysisPathGate = &pathGate{seen: map[int]map[string]map[string]struct{}{}}

	const day = 20260919
	row := func(actor, path, rule, action string, code int) model.LogAnalysisRow {
		return model.LogAnalysisRow{
			HostCode: "h1", Day: day, ActorKey: actor, PathNorm: path,
			UaHash: "ua1", Rule: rule, Action: action, StatusCode: code,
		}
	}
	batch := []model.LogAnalysisRow{
		row("ip:1.1.1.1", "/login", "", "放行", 200),
		row("ip:1.1.1.1", "/admin", "", "放行", 404),
		row("ip:2.2.2.2", "/login", "SQL注入", "阻止", 403),
	}
	CollectAnalysisStats(batch)
	CollectAnalysisStats(batch)

	var rows []model.StatsActorPathDay
	if err := db.Order("actor_key, path_norm").Find(&rows).Error; err != nil {
		t.Fatalf("读汇总失败: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("三个 (actor,path) 对应三行，实际 %d 行：upsert 没命中唯一索引", len(rows))
	}
	for _, r := range rows {
		if r.ReqCnt != 2 {
			t.Fatalf("%s %s 两批应累加成 2，实际 %d", r.ActorKey, r.PathNorm, r.ReqCnt)
		}
	}

	var distinctIP int64
	if err := db.Model(&model.StatsActorPathDay{}).
		Where("host_code = ? and day = ? and path_norm = ?", "h1", day, "/login").
		Distinct("actor_key").Count(&distinctIP).Error; err != nil {
		t.Fatalf("去重 IP 统计失败: %v", err)
	}
	if distinctIP != 2 {
		t.Fatalf("/login 去重 IP 数应为 2，实际 %d", distinctIP)
	}

	var ruleRows []model.StatsPathRuleDay
	if err := db.Find(&ruleRows).Error; err != nil {
		t.Fatalf("读规则分布失败: %v", err)
	}
	if len(ruleRows) != 1 || ruleRows[0].Cnt != 2 {
		t.Fatalf("规则分布应是一行 ×2，实际 %+v", ruleRows)
	}
}

func setupAnalysisSQLite(t *testing.T) (*gorm.DB, func()) {
	dialect.Register(&dialect.SQLiteDialect{})
	dsn := filepath.Join(t.TempDir(), "stats.db") + "?_db_key=" + url.QueryEscape("kstats")
	db, err := gorm.Open(sqlitedriver.Open(dsn), analysisSilentCfg)
	if err != nil {
		t.Logf("sqlite 打开失败（跳过）: %v", err)
		return nil, nil
	}
	if err := wafdb.RunStatsDBMigrations(db); err != nil {
		t.Fatalf("sqlite stats 迁移失败: %v", err)
	}
	return db, func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
	}
}

func setupAnalysisMySQL(t *testing.T) (*gorm.DB, func()) {
	base := os.Getenv("SAMWAF_TEST_MYSQL_DSN")
	if base == "" {
		base = "root:canteen1@tcp(127.0.0.1:3306)/"
	}
	root, err := gorm.Open(mysqldriver.Open(base+"?parseTime=true"), analysisSilentCfg)
	if err != nil {
		t.Logf("mysql 连接失败（跳过）: %v", err)
		return nil, nil
	}
	root.Exec("DROP DATABASE IF EXISTS " + xtestAnalysisDB)
	if err := root.Exec("CREATE DATABASE " + xtestAnalysisDB + " CHARACTER SET utf8mb4").Error; err != nil {
		t.Logf("mysql 建库失败（跳过）: %v", err)
		return nil, nil
	}
	dialect.Register(&dialect.MySQLDialect{})
	db, err := gorm.Open(mysqldriver.Open(base+xtestAnalysisDB+"?charset=utf8mb4&parseTime=True&loc=Local"), analysisSilentCfg)
	if err != nil {
		t.Fatalf("mysql 打开失败: %v", err)
	}
	if err := wafdb.RunStatsDBMigrations(db); err != nil {
		t.Fatalf("mysql stats 迁移失败: %v", err)
	}
	return db, func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
		root.Exec("DROP DATABASE IF EXISTS " + xtestAnalysisDB)
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}

func setupAnalysisPostgres(t *testing.T) (*gorm.DB, func()) {
	base := os.Getenv("SAMWAF_TEST_PG_DSN")
	if base == "" {
		base = "postgres://postgres:postgres@127.0.0.1:5432/"
	}
	root, err := gorm.Open(pgdriver.Open(base+"postgres?sslmode=disable"), analysisSilentCfg)
	if err != nil {
		t.Logf("postgres 连接失败（跳过）: %v", err)
		return nil, nil
	}
	root.Exec("DROP DATABASE IF EXISTS " + xtestAnalysisDB)
	if err := root.Exec("CREATE DATABASE " + xtestAnalysisDB + " ENCODING 'UTF8'").Error; err != nil {
		t.Logf("postgres 建库失败（跳过）: %v", err)
		return nil, nil
	}
	dialect.Register(&dialect.PostgresDialect{})
	db, err := gorm.Open(pgdriver.Open(base+xtestAnalysisDB+"?sslmode=disable&TimeZone=Asia/Shanghai"), analysisSilentCfg)
	if err != nil {
		t.Fatalf("postgres 打开失败: %v", err)
	}
	if err := wafdb.RunStatsDBMigrations(db); err != nil {
		t.Fatalf("postgres stats 迁移失败: %v", err)
	}
	return db, func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
		root.Exec("DROP DATABASE IF EXISTS " + xtestAnalysisDB)
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}
