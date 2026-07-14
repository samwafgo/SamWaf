package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"fmt"
	"regexp"
	"time"

	"gorm.io/gorm"
)

const cleanupBatchSize = 5000
const cleanupBatchSleep = 50 * time.Millisecond

// safeIdentPattern 合法 SQL 标识符（表名/列名）：字母或下划线开头，仅含字母、数字、下划线。
// 。执行前用此白名单严格校验。
var safeIdentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// allowedCleanupTables 数据保留清理任务允许操作的表白名单。
// 目前仅这三张统计/标签表会被自动清理；任何不在此列的表一律拒绝（即便表名是合法标识符），
// 防止保留策略被篡改后误删/恶意删除业务表或核心表。新增可清理表时在此登记。
var allowedCleanupTables = map[string]struct{}{
	"stats_ip_days":      {},
	"stats_ip_city_days": {},
	"ip_tags":            {},
}

// validatePolicyIdentifiers 校验保留策略中所有会被拼接进 SQL 的标识符字段。
// 任一不合法即返回错误（调用方跳过该策略、不执行任何删除），防止二阶 SQL 注入。
func validatePolicyIdentifiers(policy *model.DataRetentionPolicy) error {
	// 表名必须在清理白名单内（最紧控制：只允许动这几张表，其余一律不碰）
	if _, ok := allowedCleanupTables[policy.TableName]; !ok {
		return fmt.Errorf("表不在清理白名单内: %q", policy.TableName)
	}
	if policy.RetainDays > 0 {
		if !safeIdentPattern.MatchString(policy.DayField) {
			return fmt.Errorf("非法天数字段: %q", policy.DayField)
		}
		if policy.DayFieldType != "int_day" && policy.DayFieldType != "datetime" {
			return fmt.Errorf("非法天数字段类型: %q", policy.DayFieldType)
		}
	}
	if policy.RetainRows > 0 {
		if !safeIdentPattern.MatchString(policy.RowOrderField) {
			return fmt.Errorf("非法排序字段: %q", policy.RowOrderField)
		}
		// 方向仅允许精确的 ASC/DESC（与下游 compareOp 的大小写敏感判定一致）；
		// 用精确等值而非 EqualFold，杜绝借排序方向注入，也排除 Unicode 大小写折叠等价字符(如 AſC)。
		if policy.RowOrderDir != "ASC" && policy.RowOrderDir != "DESC" {
			return fmt.Errorf("非法排序方向: %q", policy.RowOrderDir)
		}
	}
	return nil
}

// TaskStatsDataCleanup 按数据保留策略清理统计数据
func TaskStatsDataCleanup() {
	zlog.Info("TaskStatsDataCleanup: 开始执行统计数据清理")

	var policies []model.DataRetentionPolicy
	if err := global.GWAF_LOCAL_DB.Where("clean_enabled = 1").Find(&policies).Error; err != nil {
		zlog.Error("TaskStatsDataCleanup: 读取保留策略失败", "error", err.Error())
		return
	}

	if len(policies) == 0 {
		zlog.Info("TaskStatsDataCleanup: 无启用的清理策略，跳过")
		return
	}

	for i := range policies {
		policy := &policies[i]

		// 防二阶 SQL 注入：执行任何删除前，先校验所有将被拼接进 SQL 的标识符字段；
		// 不合法则跳过该策略（不删任何数据），并记日志告警。
		if err := validatePolicyIdentifiers(policy); err != nil {
			zlog.Error("TaskStatsDataCleanup: 保留策略标识符非法，已跳过该策略",
				"table", policy.TableName, "error", err.Error())
			continue
		}

		db := getDBForPolicy(policy.DbType, policy.TableName)
		if db == nil {
			zlog.Warn("TaskStatsDataCleanup: 无法获取目标数据库连接",
				"table", policy.TableName, "db_type", policy.DbType)
			continue
		}

		totalDeleted := int64(0)

		// 先执行天数清理，再执行行数清理
		if policy.RetainDays > 0 {
			n, err := cleanByDays(db, policy)
			if err != nil {
				zlog.Error("TaskStatsDataCleanup: 天数清理失败", "table", policy.TableName, "error", err.Error())
			} else {
				totalDeleted += n
				zlog.Info("TaskStatsDataCleanup: 天数清理完成", "table", policy.TableName, "deleted", n)
			}
		}

		if policy.RetainRows > 0 {
			n, err := cleanByRows(db, policy)
			if err != nil {
				zlog.Error("TaskStatsDataCleanup: 行数清理失败", "table", policy.TableName, "error", err.Error())
			} else {
				totalDeleted += n
				zlog.Info("TaskStatsDataCleanup: 行数清理完成", "table", policy.TableName, "deleted", n)
			}
		}

		// 更新策略记录
		now := customtype.JsonTime(time.Now())
		if err := global.GWAF_LOCAL_DB.Model(policy).Updates(map[string]interface{}{
			"last_clean_time": now,
			"last_clean_rows": totalDeleted,
			"update_time":     now,
		}).Error; err != nil {
			zlog.Warn("TaskStatsDataCleanup: 更新策略记录失败", "table", policy.TableName, "error", err.Error())
		}

		zlog.Info("TaskStatsDataCleanup: 策略执行完毕", "table", policy.TableName, "total_deleted", totalDeleted)
	}

	zlog.Info("TaskStatsDataCleanup: 所有清理任务完成")
}

// getDBForPolicy 根据策略的 DbType 和 TableName 返回正确的数据库连接。
//
// DbType 支持的值：
//   - "stats" → GWAF_LOCAL_STATS_DB（统计库，默认）
//   - "log"   → GWAF_LOCAL_LOG_DB（日志库）
//   - "core"  → GWAF_LOCAL_DB（核心库，预留）
//
// 特殊表处理：
//   - "ip_tags"：由全局变量 GDATA_IP_TAG_DB 动态决定归属库（stats 或 core），
//     始终调用 global.GetIPTagDB() 获取正确连接，忽略 DbType 字段。
//
// 未知值或对应连接为 nil 时返回 nil，调用方负责处理。
func getDBForPolicy(dbType, tableName string) *gorm.DB {
	// ip_tags 特殊处理：归属库由运行时全局配置决定，不依赖策略字段
	if tableName == "ip_tags" {
		return global.GetIPTagDB()
	}

	switch dbType {
	case "log":
		return global.GWAF_LOCAL_LOG_DB
	case "core":
		return global.GWAF_LOCAL_DB
	case "stats":
		return global.GWAF_LOCAL_STATS_DB
	default:
		// 兜底：空值或历史遗留数据默认走 stats 库
		if dbType == "" {
			return global.GWAF_LOCAL_STATS_DB
		}
		return nil
	}
}

// cleanByDays 按天数清理旧数据，返回已删除行数
func cleanByDays(db *gorm.DB, policy *model.DataRetentionPolicy) (int64, error) {
	table := policy.TableName
	totalDeleted := int64(0)

	switch policy.DayFieldType {
	case "int_day":
		// 计算阈值：YYYYMMDD 格式的整数
		threshold := calcIntDayThreshold(policy.RetainDays)
		zlog.Info("cleanByDays(int_day)", "table", table, "threshold", threshold, "field", policy.DayField)

		for {
			sql := dialect.Get().BatchDeleteSQL(
				table, fmt.Sprintf("%s < ?", policy.DayField), cleanupBatchSize,
			)
			result := db.Exec(sql, threshold)
			if result.Error != nil {
				return totalDeleted, result.Error
			}
			totalDeleted += result.RowsAffected
			if result.RowsAffected == 0 {
				break
			}
			time.Sleep(cleanupBatchSleep)
		}

	case "datetime":
		// 计算阈值：时间类型
		threshold := time.Now().AddDate(0, 0, -int(policy.RetainDays))
		zlog.Info("cleanByDays(datetime)", "table", table, "threshold", threshold.Format("2006-01-02"), "field", policy.DayField)

		for {
			sql := dialect.Get().BatchDeleteSQL(
				table, fmt.Sprintf("%s < ?", policy.DayField), cleanupBatchSize,
			)
			result := db.Exec(sql, threshold)
			if result.Error != nil {
				return totalDeleted, result.Error
			}
			totalDeleted += result.RowsAffected
			if result.RowsAffected == 0 {
				break
			}
			time.Sleep(cleanupBatchSleep)
		}

	default:
		return 0, fmt.Errorf("未知的 day_field_type: %s", policy.DayFieldType)
	}

	return totalDeleted, nil
}

// cleanByRows 按行数清理超出保留上限的旧数据，返回已删除行数
func cleanByRows(db *gorm.DB, policy *model.DataRetentionPolicy) (int64, error) {
	table := policy.TableName
	totalDeleted := int64(0)

	// 查询当前总行数
	var currentCount int64
	if err := db.Table(table).Count(&currentCount).Error; err != nil {
		return 0, fmt.Errorf("查询 %s 总行数失败: %w", table, err)
	}

	excess := currentCount - policy.RetainRows
	if excess <= 0 {
		zlog.Info("cleanByRows: 行数未超限，跳过", "table", table, "current", currentCount, "retain", policy.RetainRows)
		return 0, nil
	}

	zlog.Info("cleanByRows: 开始行数清理", "table", table, "current", currentCount, "retain", policy.RetainRows, "excess", excess)

	// 第1步：通过索引找截断阈值（只扫描 retain_rows 个索引条目）
	orderClause := fmt.Sprintf("%s %s", policy.RowOrderField, policy.RowOrderDir)
	thresholdSQL := fmt.Sprintf(
		"SELECT %s FROM %s ORDER BY %s LIMIT 1 OFFSET %d",
		policy.RowOrderField, table, orderClause, policy.RetainRows,
	)

	// 第2步：按阈值范围删除
	// 若排序方向为 DESC（保留值最大的），则删除 <= 阈值的记录
	// 若排序方向为 ASC（保留值最小的），则删除 >= 阈值的记录
	var compareOp string
	if policy.RowOrderDir == "DESC" {
		compareOp = "<="
	} else {
		compareOp = ">="
	}

	// 根据字段类型选择合适的 scan 目标
	if policy.DayFieldType == "int_day" || policy.RowOrderField == "day" || policy.RowOrderField == "cnt" {
		var thresholdVal int64
		if err := db.Raw(thresholdSQL).Scan(&thresholdVal).Error; err != nil {
			return 0, fmt.Errorf("查询行数阈值失败 (%s): %w", table, err)
		}
		if thresholdVal == 0 {
			zlog.Info("cleanByRows: 阈值查询为空，跳过", "table", table)
			return 0, nil
		}

		deleteSQL := dialect.Get().BatchDeleteSQL(
			table, fmt.Sprintf("%s %s ?", policy.RowOrderField, compareOp), cleanupBatchSize,
		)
		for {
			result := db.Exec(deleteSQL, thresholdVal)
			if result.Error != nil {
				return totalDeleted, result.Error
			}
			totalDeleted += result.RowsAffected
			if result.RowsAffected == 0 {
				break
			}
			time.Sleep(cleanupBatchSleep)
		}
	} else {
		// datetime 类型字段
		var thresholdVal time.Time
		if err := db.Raw(thresholdSQL).Scan(&thresholdVal).Error; err != nil {
			return 0, fmt.Errorf("查询行数阈值失败 (%s): %w", table, err)
		}
		if thresholdVal.IsZero() {
			zlog.Info("cleanByRows: 阈值查询为空，跳过", "table", table)
			return 0, nil
		}

		deleteSQL := dialect.Get().BatchDeleteSQL(
			table, fmt.Sprintf("%s %s ?", policy.RowOrderField, compareOp), cleanupBatchSize,
		)
		for {
			result := db.Exec(deleteSQL, thresholdVal)
			if result.Error != nil {
				return totalDeleted, result.Error
			}
			totalDeleted += result.RowsAffected
			if result.RowsAffected == 0 {
				break
			}
			time.Sleep(cleanupBatchSleep)
		}
	}

	return totalDeleted, nil
}

// calcIntDayThreshold 计算 YYYYMMDD 格式的天数阈值
func calcIntDayThreshold(retainDays int64) int64 {
	cutoff := time.Now().AddDate(0, 0, -int(retainDays))
	year, month, day := cutoff.Date()
	return int64(year*10000 + int(month)*100 + day)
}
