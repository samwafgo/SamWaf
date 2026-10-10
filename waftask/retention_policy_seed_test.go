package waftask

import (
	"SamWaf/model"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"net/url"
	"path/filepath"
	"sort"
	"testing"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 保留策略页只能改不能加（策略由系统预置），所以「把表加进 allowedCleanupTables」
// 只是拿到了清理许可，真正要它被清理还得在 migrations_core 里预置一行策略。
// 两处漏掉任意一处，表就会安静地一直长——页面上根本看不到它。
// 这条用例把两边钉在一起：白名单里的每张表都必须有预置策略。
func TestEveryCleanupTableHasSeededPolicy(t *testing.T) {
	dialect.Register(&dialect.SQLiteDialect{})
	dsn := filepath.Join(t.TempDir(), "core.db") + "?_db_key=" + url.QueryEscape("kcore")
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("打不开 sqlite（缺 CGO？），跳过: %v", err)
	}
	t.Cleanup(func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
	})
	if err := wafdb.RunCoreDBMigrations(db); err != nil {
		t.Fatalf("core 迁移失败: %v", err)
	}

	var policies []model.DataRetentionPolicy
	if err := db.Find(&policies).Error; err != nil {
		t.Fatalf("读保留策略失败: %v", err)
	}
	seeded := map[string]model.DataRetentionPolicy{}
	for _, p := range policies {
		seeded[p.TableName] = p
	}

	var missing []string
	for table := range allowedCleanupTables {
		if _, ok := seeded[table]; !ok {
			missing = append(missing, table)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("这些表在 allowedCleanupTables 里但没有预置策略，页面上加不了、也永远不会被清理：%v；"+
			"修法：在 wafdb/migrations_core.go 加一条迁移预置它们的 DataRetentionPolicy", missing)
	}

	// 反向也查一遍：预置了策略却不在白名单，清理任务会因标识符校验失败跳过，同样是空转
	var orphan []string
	for table := range seeded {
		if _, ok := allowedCleanupTables[table]; !ok {
			orphan = append(orphan, table)
		}
	}
	if len(orphan) > 0 {
		sort.Strings(orphan)
		t.Fatalf("这些表预置了策略却不在 allowedCleanupTables，清理时会被标识符校验挡掉：%v", orphan)
	}
}
