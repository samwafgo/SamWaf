//go:build crossdb

// ip_tags 唯一索引自愈的三库回归：迁移已记为完成之后索引丢了，再次启动要能补回；
// 表里已有同键重复行时走换表，后台回填把重复行折叠（cnt 求和、时间取早/晚）。
// 换表在三个引擎上写法不同（SQLite/PG 事务内改名，MySQL 先建 __new 再原子 RENAME），所以每个引擎都要跑真实路径。
//
// 跑法：go test -tags crossdb ./waftask/ -run TestIPTagHealCrossEngine
// MySQL / PostgreSQL 连不上时跳过，不阻塞。
package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestIPTagHealCrossEngine(t *testing.T) {
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
			runIPTagHealAssertions(t, db)
		})
	}
}

func dropIPTagIndex(t *testing.T, db *gorm.DB, name string) {
	t.Helper()
	sql := "DROP INDEX " + dialect.Q(name)
	if dialect.Get().Name() == "mysql" {
		sql += " ON `ip_tags`"
	}
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("删除索引 %s 失败: %v", name, err)
	}
}

func runIPTagHealAssertions(t *testing.T, db *gorm.DB) {
	t.Helper()
	prevStats, prevCore := global.GWAF_LOCAL_STATS_DB, global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_STATS_DB, global.GWAF_LOCAL_DB = db, db
	defer func() { global.GWAF_LOCAL_STATS_DB, global.GWAF_LOCAL_DB = prevStats, prevCore }()

	has := func(name string) bool { return db.Migrator().HasIndex("ip_tags", name) }
	if !has("uni_iptags_full") {
		t.Fatal("迁移后唯一索引应已存在")
	}

	// 复现现场：迁移早已记为完成，之后索引没了
	dropIPTagIndex(t, db, "uni_iptags_full")
	dropIPTagIndex(t, db, "idx_iptag_ip")

	early := customtype.JsonTime(time.Now().Add(-72 * time.Hour))
	late := customtype.JsonTime(time.Now())
	mk := func(ip, tag string, cnt int64, create, update customtype.JsonTime) model.IPTag {
		return model.IPTag{
			BaseOrm: baseorm.BaseOrm{
				Id: uuid.GenUUID(), USER_CODE: "xtest_user", Tenant_ID: "xtest_tenant",
				CREATE_TIME: create, UPDATE_TIME: update,
			},
			IP: ip, IPTag: tag, Cnt: cnt,
		}
	}
	rows := []model.IPTag{
		mk("1.2.3.4", "SQL注入", 3, late, late),
		mk("1.2.3.4", "SQL注入", 4, early, early), // 同键重复
		mk("1.2.3.4", "SQL注入", 5, late, late),
		mk("5.6.7.8", "XSS", 7, late, late),
		mk("5.6.7.8", "正常", 99, late, late),
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("造数据失败: %v", err)
	}

	// 再次启动：迁移不会重跑，但启动检查要把索引补回来
	if err := wafdb.RunStatsDBMigrations(db); err != nil {
		t.Fatalf("再次迁移失败: %v", err)
	}
	for _, idx := range []string{"uni_iptags_full", "idx_iptag_ip"} {
		if !has(idx) {
			t.Fatalf("启动检查后索引 %s 应存在", idx)
		}
	}
	if !dialect.Get().TableExists(db, "ip_tags__heal") {
		t.Fatal("存在同键重复行，应走换表并保留 ip_tags__heal 待回填")
	}

	wafdb.RunIPTagBackfill()
	if dialect.Get().TableExists(db, "ip_tags__heal") {
		t.Fatal("回填完成后 ip_tags__heal 应删除")
	}

	var folded model.IPTag
	if err := db.Where("ip = ? AND ip_tag = ?", "1.2.3.4", "SQL注入").First(&folded).Error; err != nil {
		t.Fatalf("折叠后的行不存在: %v", err)
	}
	var n int64
	db.Model(&model.IPTag{}).Where("ip = ? AND ip_tag = ?", "1.2.3.4", "SQL注入").Count(&n)
	if n != 1 || folded.Cnt != 12 {
		t.Fatalf("同键应折叠成一行 cnt=12，实得 %d 行 cnt=%d", n, folded.Cnt)
	}
	if time.Time(folded.CREATE_TIME).After(time.Time(early).Add(time.Second)) {
		t.Fatalf("首次时间应取最早，实得 %v", time.Time(folded.CREATE_TIME))
	}
	db.Model(&model.IPTag{}).Where("ip = ? AND ip_tag = ?", "5.6.7.8", "正常").Count(&n)
	if n != 0 {
		t.Fatal("「正常」标签不应被并回")
	}
	db.Model(&model.IPTag{}).Where("ip = ? AND ip_tag = ?", "5.6.7.8", "XSS").Count(&n)
	if n != 1 {
		t.Fatalf("普通标签应原样并回，实得 %d 行", n)
	}

	// 幂等：再启动一次什么都不该变
	if err := wafdb.RunStatsDBMigrations(db); err != nil {
		t.Fatal(err)
	}
	if dialect.Get().TableExists(db, "ip_tags__heal") {
		t.Fatal("索引齐全时不应再换表")
	}
}
