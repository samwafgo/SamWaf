package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"fmt"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// RunCoreDBMigrations 执行主数据库迁移（完全兼容老用户）
func RunCoreDBMigrations(db *gorm.DB) error {
	zlog.Info("开始执行core数据库迁移检查...")

	// 检测表和索引的存在情况
	tablesExist := checkCoreTablesExist(db)
	indexesExist := checkCoreIndexesExist(db)

	zlog.Info("数据库状态检测",
		"表是否存在", tablesExist,
		"索引是否完整", indexesExist)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		// 迁移1: 创建表（如果不存在）
		{
			ID: "202511140001_initial_core_tables",
			Migrate: func(tx *gorm.DB) error {
				if tablesExist {
					zlog.Info("迁移 202511140001: 表已存在，执行结构同步")
					// 表已存在，只做结构同步（安全操作，不会删除字段/数据）
					if err := tx.AutoMigrate(
						&model.Hosts{},
						&model.Rules{},
						&model.LDPUrl{},
						&model.IPAllowList{},
						&model.URLAllowList{},
						&model.IPBlockList{},
						&model.URLBlockList{},
						&model.AntiCC{},
						&model.TokenInfo{},
						&model.Account{},
						&model.SystemConfig{},
						&model.DelayMsg{},
						&model.ShareDb{},
						&model.Center{},
						&model.Sensitive{},
						&model.LoadBalance{},
						&model.SslConfig{},
						&model.IPTag{},
						&model.BatchTask{},
						&model.SslOrder{},
						&model.SslExpire{},
						&model.HttpAuthBase{},
						&model.Task{},
						&model.BlockingPage{},
						&model.Otp{},
						&model.PrivateInfo{},
						&model.PrivateGroup{},
						&model.CacheRule{},
						&model.Tunnel{},
						&model.CaServerInfo{},
					); err != nil {
						return fmt.Errorf("同步表结构失败: %w", err)
					}
					zlog.Info("表结构同步成功（数据完整保留）")
				} else {
					zlog.Info("迁移 202511140001: 创建新表")
					// 表不存在，创建所有表
					if err := tx.AutoMigrate(
						&model.Hosts{},
						&model.Rules{},
						&model.LDPUrl{},
						&model.IPAllowList{},
						&model.URLAllowList{},
						&model.IPBlockList{},
						&model.URLBlockList{},
						&model.AntiCC{},
						&model.TokenInfo{},
						&model.Account{},
						&model.SystemConfig{},
						&model.DelayMsg{},
						&model.ShareDb{},
						&model.Center{},
						&model.Sensitive{},
						&model.LoadBalance{},
						&model.SslConfig{},
						&model.IPTag{},
						&model.BatchTask{},
						&model.SslOrder{},
						&model.SslExpire{},
						&model.HttpAuthBase{},
						&model.Task{},
						&model.BlockingPage{},
						&model.Otp{},
						&model.PrivateInfo{},
						&model.PrivateGroup{},
						&model.CacheRule{},
						&model.Tunnel{},
						&model.CaServerInfo{},
					); err != nil {
						return fmt.Errorf("创建core表失败: %w", err)
					}
					zlog.Info("core表创建成功")
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
					&model.Hosts{},
					&model.Rules{},
					&model.LDPUrl{},
					&model.IPAllowList{},
					&model.URLAllowList{},
					&model.IPBlockList{},
					&model.URLBlockList{},
					&model.AntiCC{},
					&model.TokenInfo{},
					&model.Account{},
					&model.SystemConfig{},
					&model.DelayMsg{},
					&model.ShareDb{},
					&model.Center{},
					&model.Sensitive{},
					&model.LoadBalance{},
					&model.SslConfig{},
					&model.IPTag{},
					&model.BatchTask{},
					&model.SslOrder{},
					&model.SslExpire{},
					&model.HttpAuthBase{},
					&model.Task{},
					&model.BlockingPage{},
					&model.Otp{},
					&model.PrivateInfo{},
					&model.PrivateGroup{},
					&model.CacheRule{},
					&model.Tunnel{},
					&model.CaServerInfo{},
				)
			},
		},
		// 迁移2: 创建索引（幂等操作）
		{
			ID: "202511140002_create_core_indexes",
			Migrate: func(tx *gorm.DB) error {
				if indexesExist {
					zlog.Info("迁移 202511140002: 索引已完整，跳过创建")
					return nil
				}
				zlog.Info("迁移 202511140002: 开始创建索引")
				return createCoreIndexes(tx)
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511140002: 删除索引")
				return dropCoreIndexes(tx)
			},
		},
		// 迁移3: 创建通知管理相关表
		{
			ID: "202511240001_add_notify_tables",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202511240001: 创建通知管理表")
				// 创建通知渠道和订阅表
				if err := tx.AutoMigrate(
					&model.NotifyChannel{},
					&model.NotifySubscription{},
				); err != nil {
					return fmt.Errorf("创建通知管理表失败: %w", err)
				}
				zlog.Info("通知管理表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511240001: 删除通知管理表")
				return tx.Migrator().DropTable(
					&model.NotifyChannel{},
					&model.NotifySubscription{},
				)
			},
		},
		// 迁移4: 创建防火墙IP封禁表
		{
			ID: "202511280001_add_firewall_ip_block_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202511280001: 创建防火墙IP封禁表")
				// 创建防火墙IP封禁表
				if err := tx.AutoMigrate(
					&model.FirewallIPBlock{},
				); err != nil {
					return fmt.Errorf("创建防火墙IP封禁表失败: %w", err)
				}

				// 创建索引
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_firewall_ip_block_ip ON firewall_ip_block(ip)").Error; err != nil {
					zlog.Warn("创建索引 idx_firewall_ip_block_ip 失败", "error", err.Error())
				}
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_firewall_ip_block_status ON firewall_ip_block(status)").Error; err != nil {
					zlog.Warn("创建索引 idx_firewall_ip_block_status 失败", "error", err.Error())
				}
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_firewall_ip_block_expire_time ON firewall_ip_block(expire_time)").Error; err != nil {
					zlog.Warn("创建索引 idx_firewall_ip_block_expire_time 失败", "error", err.Error())
				}

				zlog.Info("防火墙IP封禁表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511280001: 删除防火墙IP封禁表")
				return tx.Migrator().DropTable(&model.FirewallIPBlock{})
			},
		},
		// 迁移5: 为 tunnel 表添加 allowed_time_ranges 字段
		{
			ID: "202512100001_add_tunnel_allowed_time_ranges",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202512100001: 为 tunnel 表添加 allowed_time_ranges 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Tunnel{}, "allowed_time_ranges") {
					zlog.Info("allowed_time_ranges 字段已存在，跳过添加")
					return nil
				}

				// 添加字段，默认值为空字符串（表示不限制）
				if err := tx.Migrator().AddColumn(&model.Tunnel{}, "allowed_time_ranges"); err != nil {
					return fmt.Errorf("添加 allowed_time_ranges 字段失败: %w", err)
				}

				zlog.Info("allowed_time_ranges 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202512100001: 删除 tunnel 表的 allowed_time_ranges 字段")
				if tx.Migrator().HasColumn(&model.Tunnel{}, "allowed_time_ranges") {
					return tx.Migrator().DropColumn(&model.Tunnel{}, "allowed_time_ranges")
				}
				return nil
			},
		},
	})

	// 执行迁移
	if err := m.Migrate(); err != nil {
		errMsg := fmt.Sprintf("core数据库迁移失败: %v", err)
		zlog.Error("迁移执行错误", "error", err.Error())
		return fmt.Errorf("%s", errMsg)
	}

	zlog.Info("core数据库迁移成功完成")
	return nil
}

// checkCoreTablesExist 检查核心表是否存在（检查几个关键表）
func checkCoreTablesExist(db *gorm.DB) bool {
	// 检查几个关键表，如果都存在则认为是老数据库
	keyTables := []interface{}{
		&model.Hosts{},
		&model.Rules{},
		&model.Account{},
		&model.SystemConfig{},
	}

	for _, table := range keyTables {
		if !db.Migrator().HasTable(table) {
			return false
		}
	}
	return true
}

// checkCoreIndexesExist 检查所有core索引是否存在
func checkCoreIndexesExist(db *gorm.DB) bool {
	// 需要检查的索引列表（表名, 索引名）
	indexes := []struct {
		TableName string
		IndexName string
	}{
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

// createCoreIndexes 创建所有core索引（幂等操作）
func createCoreIndexes(tx *gorm.DB) error {
	zlog.Info("开始创建core索引...")
	startTime := time.Now()

	// 先检查并清理 ip_tags 表中的重复数据（针对唯一索引）
	if err := cleanupDuplicateIPTags(tx); err != nil {
		zlog.Warn("清理重复数据时出现问题（非致命）", "error", err.Error())
	}

	indexes := []struct {
		Name string
		SQL  string
	}{
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
	zlog.Info("所有core索引创建完成", "耗时", duration.String())
	return nil
}

// cleanupDuplicateIPTags 清理 ip_tags 表中的重复数据
func cleanupDuplicateIPTags(tx *gorm.DB) error {
	zlog.Info("检查 ip_tags 表中的重复数据...")

	// 检查是否存在重复数据
	var duplicateCount int64
	err := tx.Raw(`
		SELECT COUNT(*) FROM (
			SELECT user_code, tenant_id, ip, ip_tag, COUNT(*) as cnt
			FROM ip_tags
			GROUP BY user_code, tenant_id, ip, ip_tag
			HAVING cnt > 1
		)
	`).Scan(&duplicateCount).Error

	if err != nil {
		return fmt.Errorf("检查重复数据失败: %w", err)
	}

	if duplicateCount == 0 {
		zlog.Info("ip_tags 表无重复数据，可以安全创建唯一索引")
		return nil
	}

	zlog.Warn("发现重复数据，开始清理", "重复组数", duplicateCount)

	// 删除重复数据，保留 id 最小的记录
	result := tx.Exec(`
		DELETE FROM ip_tags
		WHERE id NOT IN (
			SELECT MIN(id)
			FROM ip_tags
			GROUP BY user_code, tenant_id, ip, ip_tag
		)
	`)

	if result.Error != nil {
		return fmt.Errorf("清理重复数据失败: %w", result.Error)
	}

	zlog.Info("重复数据清理完成", "删除记录数", result.RowsAffected)
	return nil
}

// dropCoreIndexes 删除所有core索引
func dropCoreIndexes(tx *gorm.DB) error {
	zlog.Info("开始删除core索引")

	indexes := []string{
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

	zlog.Info("所有core索引删除完成")
	return nil
}

// RollbackCoreDBMigration 回滚到指定版本
func RollbackCoreDBMigration(db *gorm.DB, migrationID string) error {
	zlog.Info("准备回滚core迁移", "target_version", migrationID)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{})
	if err := m.RollbackTo(migrationID); err != nil {
		return fmt.Errorf("回滚失败: %w", err)
	}

	zlog.Info("回滚成功完成", "version", migrationID)
	return nil
}
