package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/model"
	"fmt"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// RunLogDBMigrations 执行日志数据库迁移（完全兼容老用户）
func RunLogDBMigrations(db *gorm.DB) error {
	zlog.Info("开始执行log数据库迁移检查...")

	// 检测表和索引的存在情况
	tablesExist := checkLogTablesExist(db)
	indexesExist := checkLogIndexesExist(db)

	zlog.Info("数据库状态检测",
		"表是否存在", tablesExist,
		"索引是否完整", indexesExist)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		// 迁移1: 创建表（如果不存在）
		{
			ID: "202511140001_initial_log_tables",
			Migrate: func(tx *gorm.DB) error {
				if tablesExist {
					zlog.Info("迁移 202511140001: 表已存在，执行结构同步")
					// 表已存在，只做结构同步（安全操作，不会删除字段/数据）
					if err := tx.AutoMigrate(
						&innerbean.WebLog{},
						&model.AccountLog{},
						&model.WafSysLog{},
						&model.OneKeyMod{},
					); err != nil {
						return fmt.Errorf("同步表结构失败: %w", err)
					}
					zlog.Info("表结构同步成功（数据完整保留）")
				} else {
					zlog.Info("迁移 202511140001: 创建新表")
					// 表不存在，创建所有表
					if err := tx.AutoMigrate(
						&innerbean.WebLog{},
						&model.AccountLog{},
						&model.WafSysLog{},
						&model.OneKeyMod{},
					); err != nil {
						return fmt.Errorf("创建log表失败: %w", err)
					}
					zlog.Info("log表创建成功")
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				if tablesExist {
					// 如果是老数据库，不执行删除操作（保护数据）
					zlog.Info("回滚 202511140001: 检测到已存在数据，跳过表删除（保护用户数据）")
					return nil
				}
				// 新数据库可以安全删除
				zlog.Info("回滚 202511140001: 删除表")
				return tx.Migrator().DropTable(
					&innerbean.WebLog{},
					&model.AccountLog{},
					&model.WafSysLog{},
					&model.OneKeyMod{},
				)
			},
		},
		// 迁移2: 创建索引（幂等操作）
		{
			ID: "202511140002_create_log_indexes",
			Migrate: func(tx *gorm.DB) error {
				if indexesExist {
					zlog.Info("迁移 202511140002: 索引已完整，跳过创建")
					return nil
				}
				zlog.Info("迁移 202511140002: 开始创建索引")
				return createLogIndexes(tx)
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511140002: 删除索引")
				return dropLogIndexes(tx)
			},
		},
	})

	// 执行迁移
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("log数据库迁移失败: %w", err)
	}

	zlog.Info("log数据库迁移成功完成")
	return nil
}

// checkLogTablesExist 检查所有log表是否存在
func checkLogTablesExist(db *gorm.DB) bool {
	tables := []interface{}{
		&innerbean.WebLog{},
		&model.AccountLog{},
		&model.WafSysLog{},
		&model.OneKeyMod{},
	}

	for _, table := range tables {
		if !db.Migrator().HasTable(table) {
			return false
		}
	}
	return true
}

// checkLogIndexesExist 检查所有log索引是否存在
func checkLogIndexesExist(db *gorm.DB) bool {
	// 需要检查的索引列表（表名, 索引名）
	indexes := []struct {
		TableName string
		IndexName string
	}{
		{"web_logs", "idx_web_logs_task_flag_time"},
		{"web_logs", "idx_web_time_tenant_user_code"},
		{"web_logs", "idx_req_uuid_web_logs"},
		{"web_logs", "idx_tenant_usercode_web_logs"},
		{"web_logs", "idx_web_time_desc_tenant_user_code"},
		{"web_logs", "idx_web_time_desc_tenant_user_code_ip"},
		{"web_logs", "idx_web_guest_id_entification"},
	}

	for _, idx := range indexes {
		if !checkIndexExists(db, idx.TableName, idx.IndexName) {
			zlog.Info("索引不存在", "table", idx.TableName, "index", idx.IndexName)
			return false
		}
	}
	return true
}

// createLogIndexes 创建所有log索引（幂等操作）
func createLogIndexes(tx *gorm.DB) error {
	zlog.Info("开始创建log索引（可能需要几分钟）...")
	startTime := time.Now()

	indexes := []struct {
		Name string
		SQL  string
	}{
		{
			Name: "idx_web_logs_task_flag_time",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_web_logs_task_flag_time ON web_logs (task_flag, unix_add_time)",
		},
		{
			Name: "idx_web_time_tenant_user_code",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_web_time_tenant_user_code ON web_logs (unix_add_time, tenant_id, user_code)",
		},
		{
			Name: "idx_req_uuid_web_logs",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_req_uuid_web_logs ON web_logs (REQ_UUID, tenant_id, user_code)",
		},
		{
			Name: "idx_tenant_usercode_web_logs",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_tenant_usercode_web_logs ON web_logs (tenant_id, user_code)",
		},
		{
			Name: "idx_web_time_desc_tenant_user_code",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_web_time_desc_tenant_user_code ON web_logs (unix_add_time desc, tenant_id, user_code)",
		},
		{
			Name: "idx_web_time_desc_tenant_user_code_ip",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_web_time_desc_tenant_user_code_ip ON web_logs (unix_add_time desc, tenant_id, user_code, src_ip)",
		},
		{
			Name: "idx_web_guest_id_entification",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_web_guest_id_entification ON web_logs (guest_id_entification, day, is_bot, host_code)",
		},
	}

	for _, idx := range indexes {
		if err := tx.Exec(idx.SQL).Error; err != nil {
			return fmt.Errorf("创建索引失败 %s: %w", idx.Name, err)
		}
		zlog.Info("索引创建成功", "index", idx.Name)
	}

	duration := time.Since(startTime)
	zlog.Info("所有log索引创建完成", "耗时", duration.String())
	return nil
}

// dropLogIndexes 删除所有log索引
func dropLogIndexes(tx *gorm.DB) error {
	zlog.Info("开始删除log索引")

	indexes := []string{
		"idx_web_logs_task_flag_time",
		"idx_web_time_tenant_user_code",
		"idx_req_uuid_web_logs",
		"idx_tenant_usercode_web_logs",
		"idx_web_time_desc_tenant_user_code",
		"idx_web_time_desc_tenant_user_code_ip",
		"idx_web_guest_id_entification",
	}

	for _, indexName := range indexes {
		if err := tx.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", indexName)).Error; err != nil {
			zlog.Warn("删除索引失败（可能不存在）", "index", indexName, "error", err)
		} else {
			zlog.Info("索引删除成功", "index", indexName)
		}
	}

	zlog.Info("所有log索引删除完成")
	return nil
}

// RollbackLogDBMigration 回滚到指定版本
func RollbackLogDBMigration(db *gorm.DB, migrationID string) error {
	zlog.Info("准备回滚log迁移", "target_version", migrationID)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{})
	if err := m.RollbackTo(migrationID); err != nil {
		return fmt.Errorf("回滚失败: %w", err)
	}

	zlog.Info("回滚成功完成", "version", migrationID)
	return nil
}
