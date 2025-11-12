package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"fmt"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// RunStatsDBMigrations 执行统计数据库迁移（完全兼容老用户）
func RunStatsDBMigrations(db *gorm.DB) error {
	zlog.Info("开始执行stats数据库迁移检查...")

	// 检测表和索引的存在情况
	tablesExist := checkStatsTablesExist(db)
	indexesExist := checkStatsIndexesExist(db)

	zlog.Info("数据库状态检测",
		"表是否存在", tablesExist,
		"索引是否完整", indexesExist)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		// 迁移1: 创建表（如果不存在）
		{
			ID: "202511110001_initial_tables",
			Migrate: func(tx *gorm.DB) error {
				if tablesExist {
					zlog.Info("迁移 202511110001: 表已存在，执行结构同步")
					// 表已存在，只做结构同步（安全操作，不会删除字段/数据）
					if err := tx.AutoMigrate(
						&model.StatsTotal{},
						&model.StatsDay{},
						&model.StatsIPDay{},
						&model.StatsIPCityDay{},
						&model.IPTag{},
					); err != nil {
						return fmt.Errorf("同步表结构失败: %w", err)
					}
					zlog.Info("表结构同步成功（数据完整保留）")
				} else {
					zlog.Info("迁移 202511110001: 创建新表")
					// 表不存在，创建所有表
					if err := tx.AutoMigrate(
						&model.StatsTotal{},
						&model.StatsDay{},
						&model.StatsIPDay{},
						&model.StatsIPCityDay{},
						&model.IPTag{},
					); err != nil {
						return fmt.Errorf("创建stats表失败: %w", err)
					}
					zlog.Info("stats表创建成功")
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				if tablesExist {
					// 如果是老数据库，不执行删除操作（保护数据）
					zlog.Info("回滚 202511110001: 检测到已存在数据，跳过表删除（保护用户数据）")
					return nil
				}
				// 新数据库可以安全删除
				zlog.Info("回滚 202511110001: 删除表")
				return tx.Migrator().DropTable(
					&model.StatsTotal{},
					&model.StatsDay{},
					&model.StatsIPDay{},
					&model.StatsIPCityDay{},
					&model.IPTag{},
				)
			},
		},
		// 迁移2: 创建索引（幂等操作）
		{
			ID: "202511110002_create_indexes",
			Migrate: func(tx *gorm.DB) error {
				if indexesExist {
					zlog.Info("迁移 202511110002: 索引已完整，跳过创建")
					return nil
				}
				zlog.Info("迁移 202511110002: 开始创建索引")
				return createStatsIndexes(tx)
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511110002: 删除索引")
				return dropStatsIndexes(tx)
			},
		},
	})

	// 执行迁移
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("stats数据库迁移失败: %w", err)
	}

	zlog.Info("stats数据库迁移成功完成")
	return nil
}

// checkStatsTablesExist 检查所有stats表是否存在
func checkStatsTablesExist(db *gorm.DB) bool {
	tables := []interface{}{
		&model.StatsTotal{},
		&model.StatsDay{},
		&model.StatsIPDay{},
		&model.StatsIPCityDay{},
		&model.IPTag{},
	}

	for _, table := range tables {
		if !db.Migrator().HasTable(table) {
			return false
		}
	}
	return true
}

// checkStatsIndexesExist 检查所有stats索引是否存在
func checkStatsIndexesExist(db *gorm.DB) bool {
	// 需要检查的索引列表（表名, 索引名）
	indexes := []struct {
		TableName string
		IndexName string
	}{
		{"stats_days", "idx_stats_days_lookup"},
		{"stats_ip_days", "idx_stats_ip_days_lookup"},
		{"stats_ip_city_days", "idx_stats_ip_city_days_lookup"},
		{"ip_tags", "uni_iptags_full"},
		{"ip_tags", "idx_iptag_ip"},
	}

	for _, idx := range indexes {
		if !checkIndexExists(db, idx.TableName, idx.IndexName) {
			zlog.Info("索引不存在", "table", idx.TableName, "index", idx.IndexName)
			return false
		}
	}
	return true
}

// checkIndexExists 检查指定表的索引是否存在（SQLite）
func checkIndexExists(db *gorm.DB, tableName, indexName string) bool {
	var count int64
	// SQLite 查询索引的方法
	err := db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=? AND tbl_name=?",
		indexName, tableName).Scan(&count).Error

	if err != nil {
		zlog.Error("检查索引失败", "error", err, "table", tableName, "index", indexName)
		return false
	}
	return count > 0
}

// createStatsIndexes 创建所有stats索引（幂等操作）
func createStatsIndexes(tx *gorm.DB) error {
	zlog.Info("开始创建stats索引（可能需要几分钟）...")
	startTime := time.Now()

	indexes := []struct {
		Name string
		SQL  string
	}{
		{
			Name: "idx_stats_days_lookup",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_stats_days_lookup ON stats_days (tenant_id, user_code, host_code, type, day)",
		},
		{
			Name: "idx_stats_ip_days_lookup",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_stats_ip_days_lookup ON stats_ip_days (tenant_id, user_code, host_code, ip, type, day)",
		},
		{
			Name: "idx_stats_ip_city_days_lookup",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_stats_ip_city_days_lookup ON stats_ip_city_days (tenant_id, user_code, host_code, country, province, city, type, day)",
		},
		{
			Name: "uni_iptags_full",
			SQL:  "CREATE UNIQUE INDEX IF NOT EXISTS uni_iptags_full ON ip_tags (user_code, tenant_id, ip, ip_tag)",
		},
		{
			Name: "idx_iptag_ip",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_iptag_ip ON ip_tags (user_code, tenant_id, ip)",
		},
	}

	for _, idx := range indexes {
		if err := tx.Exec(idx.SQL).Error; err != nil {
			return fmt.Errorf("创建索引失败 %s: %w", idx.Name, err)
		}
		zlog.Info("索引创建成功", "index", idx.Name)
	}

	duration := time.Since(startTime)
	zlog.Info("所有stats索引创建完成", "耗时", duration.String())
	return nil
}

// dropStatsIndexes 删除所有stats索引
func dropStatsIndexes(tx *gorm.DB) error {
	zlog.Info("开始删除stats索引")

	indexes := []string{
		"idx_stats_days_lookup",
		"idx_stats_ip_days_lookup",
		"idx_stats_ip_city_days_lookup",
		"uni_iptags_full",
		"idx_iptag_ip",
	}

	for _, indexName := range indexes {
		if err := tx.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", indexName)).Error; err != nil {
			zlog.Warn("删除索引失败（可能不存在）", "index", indexName, "error", err)
		} else {
			zlog.Info("索引删除成功", "index", indexName)
		}
	}

	zlog.Info("所有stats索引删除完成")
	return nil
}

// RollbackStatsDBMigration 回滚到指定版本
func RollbackStatsDBMigration(db *gorm.DB, migrationID string) error {
	zlog.Info("准备回滚stats迁移", "target_version", migrationID)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{})
	if err := m.RollbackTo(migrationID); err != nil {
		return fmt.Errorf("回滚失败: %w", err)
	}

	zlog.Info("回滚成功完成", "version", migrationID)
	return nil
}
