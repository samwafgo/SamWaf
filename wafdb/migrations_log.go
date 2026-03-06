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
		// 迁移3: 创建通知日志表
		{
			ID: "202511240001_add_notify_log_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202511240001: 创建通知日志表")
				// 创建通知日志表
				if err := tx.AutoMigrate(
					&model.NotifyLog{},
				); err != nil {
					return fmt.Errorf("创建通知日志表失败: %w", err)
				}
				zlog.Info("通知日志表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511240001: 删除通知日志表")
				return tx.Migrator().DropTable(
					&model.NotifyLog{},
				)
			},
		},
		// 迁移4: 为 notify_log 表添加 recipients 字段（记录邮件收件人）
		{
			ID: "202601300002_add_notify_log_recipients",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601300002: 为 notify_log 表添加 recipients 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.NotifyLog{}, "recipients") {
					zlog.Info("recipients 字段已存在，跳过添加")
					return nil
				}

				// 添加字段
				if err := tx.Migrator().AddColumn(&model.NotifyLog{}, "recipients"); err != nil {
					return fmt.Errorf("添加 recipients 字段失败: %w", err)
				}

				zlog.Info("recipients 字段添加成功（用于记录邮件通知的实际收件人）")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601300002: 删除 notify_log 表的 recipients 字段")
				if tx.Migrator().HasColumn(&model.NotifyLog{}, "recipients") {
					return tx.Migrator().DropColumn(&model.NotifyLog{}, "recipients")
				}
				return nil
			},
		},
		// 迁移5: 创建开放平台调用日志表
		{
			ID: "202603060001_add_oplatform_log_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202603060001: 创建开放平台调用日志表")

				if tx.Migrator().HasTable(&model.OPlatformLog{}) {
					zlog.Info("o_platform_logs 表已存在，执行结构同步")
					if err := tx.AutoMigrate(&model.OPlatformLog{}); err != nil {
						return fmt.Errorf("同步 o_platform_logs 表结构失败: %w", err)
					}
					return nil
				}

				if err := tx.AutoMigrate(&model.OPlatformLog{}); err != nil {
					return fmt.Errorf("创建 o_platform_logs 表失败: %w", err)
				}

				zlog.Info("o_platform_logs 表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202603060001: 删除开放平台调用日志表")
				return tx.Migrator().DropTable(&model.OPlatformLog{})
			},
		},
	})

	// 执行迁移
	if err := m.Migrate(); err != nil {
		errMsg := fmt.Sprintf("log数据库迁移失败: %v", err)
		zlog.Error("迁移执行错误", "error", err.Error())
		return fmt.Errorf("%s", errMsg)
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
		zlog.Info("开始创建索引", "index", idx.Name, "sql", idx.SQL)
		indexStartTime := time.Now()

		if err := tx.Exec(idx.SQL).Error; err != nil {
			// 记录详细的错误信息
			errMsg := fmt.Sprintf("创建索引失败 %s: %v (错误类型: %T)", idx.Name, err, err)
			zlog.Error("索引创建失败详情", "index", idx.Name, "error", err.Error(), "sql", idx.SQL)
			return fmt.Errorf("%s", errMsg)
		}

		indexDuration := time.Since(indexStartTime)
		zlog.Info("索引创建成功", "index", idx.Name, "耗时", indexDuration.String())
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
