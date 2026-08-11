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
		// 迁移5: 为 web_logs 表添加 res_content_length 字段（响应内容大小）
		{
			ID: "202603100001_add_web_logs_res_content_length",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202603100001: 为 web_logs 表添加 res_content_length 字段")

				if tx.Migrator().HasColumn(&innerbean.WebLog{}, "res_content_length") {
					zlog.Info("res_content_length 字段已存在，跳过添加")
					return nil
				}

				if err := tx.Migrator().AddColumn(&innerbean.WebLog{}, "RES_CONTENT_LENGTH"); err != nil {
					return fmt.Errorf("添加 res_content_length 字段失败: %w", err)
				}

				zlog.Info("res_content_length 字段添加成功（用于记录响应内容大小，支持流量统计）")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202603100001: 删除 web_logs 表的 res_content_length 字段")
				if tx.Migrator().HasColumn(&innerbean.WebLog{}, "res_content_length") {
					return tx.Migrator().DropColumn(&innerbean.WebLog{}, "RES_CONTENT_LENGTH")
				}
				return nil
			},
		},
		// 迁移6: 为 web_logs 表添加 ai_score 字段（AI智能检测得分，支持集中查看观察/拦截）
		{
			ID: "202606120001_add_web_logs_ai_score",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202606120001: 为 web_logs 表添加 ai_score 字段")

				if tx.Migrator().HasColumn(&innerbean.WebLog{}, "ai_score") {
					zlog.Info("ai_score 字段已存在，跳过添加")
					return nil
				}

				if err := tx.Migrator().AddColumn(&innerbean.WebLog{}, "AI_SCORE"); err != nil {
					return fmt.Errorf("添加 ai_score 字段失败: %w", err)
				}

				zlog.Info("ai_score 字段添加成功（用于记录AI检测得分，支持观察/拦截集中查看）")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202606120001: 删除 web_logs 表的 ai_score 字段")
				if tx.Migrator().HasColumn(&innerbean.WebLog{}, "ai_score") {
					return tx.Migrator().DropColumn(&innerbean.WebLog{}, "AI_SCORE")
				}
				return nil
			},
		},
		// 迁移7: 为 web_logs 表的 ai_score 建索引（AI看板按 ai_score>0 过滤，命中是极小子集，
		// 走索引可避免全表扫描；复合 day 兼顾按天范围过滤与趋势排序）
		{
			ID: "202606120002_add_web_logs_ai_score_index",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202606120002: 为 web_logs.ai_score 创建索引")
				return safeCreateIndex(tx, "web_logs", "idx_web_logs_ai_score_day",
					"CREATE INDEX IF NOT EXISTS idx_web_logs_ai_score_day ON web_logs (ai_score, day)")
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202606120002: 删除 web_logs.ai_score 索引")
				return safeDropIndex(tx, "web_logs", "idx_web_logs_ai_score_day")
			},
		},
		// 迁移: 创建统一访问认证审计日志表
		// 放 log 库而不是 core 库：它与 account_logs 同属审计流水，生命周期一致（按天清理）。
		// 而 wafdb/log_shard.go 的日志分库只搬 web_logs 一张表，本表不会因分库变得不可见。
		{
			ID: "202608040002_add_access_audit_log",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202608040002: 创建统一访问认证审计日志表")
				if err := tx.AutoMigrate(&model.AccessAuditLog{}); err != nil {
					return fmt.Errorf("创建 access_audit_log 表失败: %w", err)
				}
				// 管理端最常见的查询是「按时间倒序看某类事件」
				if err := safeCreateIndex(tx, "access_audit_log", "idx_access_audit_day_event",
					"CREATE INDEX IF NOT EXISTS idx_access_audit_day_event ON access_audit_log (day, event)"); err != nil {
					zlog.Warn("创建索引 idx_access_audit_day_event 失败", "error", err.Error())
				}
				// 排查「某个账号/某个IP干了什么」
				if err := safeCreateIndex(tx, "access_audit_log", "idx_access_audit_account",
					"CREATE INDEX IF NOT EXISTS idx_access_audit_account ON access_audit_log (account_name)"); err != nil {
					zlog.Warn("创建索引 idx_access_audit_account 失败", "error", err.Error())
				}
				if err := safeCreateIndex(tx, "access_audit_log", "idx_access_audit_ip",
					"CREATE INDEX IF NOT EXISTS idx_access_audit_ip ON access_audit_log (client_ip)"); err != nil {
					zlog.Warn("创建索引 idx_access_audit_ip 失败", "error", err.Error())
				}
				zlog.Info("access_audit_log 表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202608040002: 删除统一访问认证审计日志表")
				return tx.Migrator().DropTable(&model.AccessAuditLog{})
			},
		},
		// 迁移: notify_log 增加可调试字段（issue #822）
		// 老表只记"发出去的"，用户问"为什么没收到通知"时完全查不到；
		// 补上订阅ID/抑制原因/抑制条数/模板来源后，管理端就能直接回答这个问题。
		{
			ID: "202608050002_add_notify_log_debug_columns",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202608050002: 为 notify_log 表添加可调试字段")
				cols := []struct{ column, field string }{
					{"subscription_id", "SubscriptionId"},
					{"suppress_reason", "SuppressReason"},
					{"suppress_count", "SuppressCount"},
					{"template_used", "TemplateUsed"},
				}
				for _, c := range cols {
					if tx.Migrator().HasColumn(&model.NotifyLog{}, c.column) {
						zlog.Info("字段已存在，跳过", "column", c.column)
						continue
					}
					if err := tx.Migrator().AddColumn(&model.NotifyLog{}, c.field); err != nil {
						return fmt.Errorf("添加 notify_log.%s 字段失败: %w", c.column, err)
					}
				}
				zlog.Info("notify_log 可调试字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202608050002: 删除 notify_log 可调试字段")
				for _, field := range []string{"SubscriptionId", "SuppressReason", "SuppressCount", "TemplateUsed"} {
					if tx.Migrator().HasColumn(&model.NotifyLog{}, field) {
						if err := tx.Migrator().DropColumn(&model.NotifyLog{}, field); err != nil {
							zlog.Warn("删除字段失败", "field", field, "error", err.Error())
						}
					}
				}
				return nil
			},
		},
		// 迁移: 创建管理端登录历史表（登录提醒 + 登录历史查询）
		{
			ID: "202608060001_add_login_history_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202608060001: 创建登录历史表")
				if err := tx.AutoMigrate(
					&model.LoginHistory{},
				); err != nil {
					return fmt.Errorf("创建登录历史表失败: %w", err)
				}
				zlog.Info("登录历史表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202608060001: 删除登录历史表")
				return tx.Migrator().DropTable(
					&model.LoginHistory{},
				)
			},
		},
		// 迁移: 创建主机远程登录(SSH/RDP)失败事件表
		// 放 log 库是因为它随攻击量线性增长，属于可按保留策略清理的观测数据。
		{
			ID: "202608070001_add_host_login_event_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202608070001: 创建主机登录失败事件表")
				if err := tx.AutoMigrate(&model.HostLoginEvent{}); err != nil {
					return fmt.Errorf("创建主机登录失败事件表失败: %w", err)
				}
				// (ip, event_time)：单IP攻击历史下钻
				if err := safeCreateIndex(tx, "host_login_event", "idx_hle_ip_time",
					"CREATE INDEX IF NOT EXISTS idx_hle_ip_time ON host_login_event(ip, event_time)"); err != nil {
					zlog.Warn("创建索引 idx_hle_ip_time 失败", "error", err.Error())
				}
				// (source, event_time)：按来源分页 + 时间范围
				if err := safeCreateIndex(tx, "host_login_event", "idx_hle_src_time",
					"CREATE INDEX IF NOT EXISTS idx_hle_src_time ON host_login_event(source, event_time)"); err != nil {
					zlog.Warn("创建索引 idx_hle_src_time 失败", "error", err.Error())
				}
				// (event_time)：全局时间范围与保留期清理
				if err := safeCreateIndex(tx, "host_login_event", "idx_hle_event_time",
					"CREATE INDEX IF NOT EXISTS idx_hle_event_time ON host_login_event(event_time)"); err != nil {
					zlog.Warn("创建索引 idx_hle_event_time 失败", "error", err.Error())
				}
				zlog.Info("主机登录失败事件表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202608070001: 删除主机登录失败事件表")
				return tx.Migrator().DropTable(&model.HostLoginEvent{})
			},
		},
		// 迁移: 创建威胁情报排除名单审计表
		// 排除是主动降低防护的操作，删除排除条目后原记录就没了，
		// 所以"曾经排除过什么、谁排的"必须另留一份只增不改的流水。
		{
			ID: "202608110002_add_threat_ip_exclude_audit_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202608110002: 创建威胁情报排除名单审计表")
				if err := tx.AutoMigrate(&model.ThreatIPExcludeAudit{}); err != nil {
					return fmt.Errorf("创建威胁情报排除审计表失败: %w", err)
				}
				// (create_time)：按时间倒序分页 + 保留期清理
				if err := safeCreateIndex(tx, "threat_ip_exclude_audit", "idx_tiea_create_time",
					"CREATE INDEX IF NOT EXISTS idx_tiea_create_time ON threat_ip_exclude_audit(create_time)"); err != nil {
					zlog.Warn("创建索引 idx_tiea_create_time 失败", "error", err.Error())
				}
				zlog.Info("威胁情报排除名单审计表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202608110002: 删除威胁情报排除名单审计表")
				return tx.Migrator().DropTable(&model.ThreatIPExcludeAudit{})
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

		if err := safeCreateIndex(tx, "web_logs", idx.Name, idx.SQL); err != nil {
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
		if err := safeDropIndex(tx, "web_logs", indexName); err != nil {
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
