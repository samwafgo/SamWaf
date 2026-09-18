package wafdb

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"fmt"
	"net/url"
	"os"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// 日志导出的可选层
const (
	ExportTierAccess  = "access"  // access_log 窄行
	ExportTierEvent   = "event"   // security_event 安全事件
	ExportTierPayload = "payload" // event_payload 报文（event/sample/watch）
	ExportTierWeblog  = "weblog"  // 存量 web_logs（只读到期删的那部分）
)

const exportBatchSize = 1000

// exportTierCopy 一个待导出的层：模型（导出文件建表用）+ 源表名
type exportTierCopy struct {
	name     string
	model    interface{}
	srcTable string
}

// ExportLogRangeDb 把实时日志库按时间段导出成一个新的加密 SQLite 文件（C11）。
//
// 分层后「导出一个 .db」不再是备份整个库文件：按选定层 + 时间段导出行，
// 导出件自带表结构（AutoMigrate），可直接用同一套密钥打开查阅。
// startTime/endTime 为 "2006-01-02 15:04:05"，空 = 不限制。返回每层导出的行数。
func ExportLogRangeDb(outPath, startTime, endTime string, tiers map[string]bool) (map[string]int64, error) {
	counts := map[string]int64{}
	if !dialect.Get().SupportsBackup() {
		return counts, fmt.Errorf("按时间段导出仅在 SQLite 模式下可用，当前驱动: %s", dialect.Get().Name())
	}
	if _, err := os.Stat(outPath); err == nil {
		return counts, fmt.Errorf("导出文件已存在: %s", outPath)
	}

	key := url.QueryEscape(global.GWAF_PWD_LOGDB)
	dst, err := gorm.Open(sqlite.Open(fmt.Sprintf("%s?_db_key=%s", outPath, key)),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return counts, fmt.Errorf("创建导出文件失败: %w", err)
	}
	defer func() {
		if sqlDB, err := dst.DB(); err == nil {
			sqlDB.Close()
		}
	}()

	src := global.GWAF_LOCAL_LOG_DB
	if src == nil {
		return counts, fmt.Errorf("日志库未初始化")
	}

	// 各层：模型 + 源表存在性。web_logs 边界切割后可能已不在实时库
	copies := []exportTierCopy{}
	if tiers[ExportTierAccess] && dialect.Get().TableExists(src, model.AccessLogTableName) {
		copies = append(copies, exportTierCopy{ExportTierAccess, &model.AccessLog{}, model.AccessLogTableName})
	}
	if tiers[ExportTierEvent] && dialect.Get().TableExists(src, model.SecurityEventTableName) {
		copies = append(copies, exportTierCopy{ExportTierEvent, &model.SecurityEvent{}, model.SecurityEventTableName})
	}
	if tiers[ExportTierPayload] && dialect.Get().TableExists(src, model.EventPayload{}.TableName()) {
		copies = append(copies, exportTierCopy{ExportTierPayload, &model.EventPayload{}, model.EventPayloadTableName})
	}
	if tiers[ExportTierWeblog] && dialect.Get().TableExists(src, LogTableName) {
		copies = append(copies, exportTierCopy{ExportTierWeblog, &innerbean.WebLog{}, LogTableName})
	}

	for _, tc := range copies {
		if err := dst.AutoMigrate(tc.model); err != nil {
			return counts, fmt.Errorf("导出文件建表 %s 失败: %w", tc.srcTable, err)
		}
		n, err := exportCopyTier(src, dst, tc, startTime, endTime)
		if err != nil {
			return counts, err
		}
		counts[tc.name] = n
	}
	return counts, nil
}

// exportCopyTier 按 create_time 区间分批读源表、批量写导出文件。主键冲突保留先到的（重复导出同一区间不会翻倍）。
func exportCopyTier(src, dst *gorm.DB, tc exportTierCopy, startTime, endTime string) (int64, error) {
	var total int64
	q := src.Table(tc.srcTable)
	if startTime != "" {
		q = q.Where("create_time >= ?", startTime)
	}
	if endTime != "" {
		q = q.Where("create_time <= ?", endTime)
	}
	// 用目标模型接住行，保证列名与导出表一致（web_logs 列比新表多，互不影响）
	rows := []map[string]interface{}{}
	result := q.FindInBatches(&rows, exportBatchSize, func(tx *gorm.DB, batch int) error {
		if len(rows) == 0 {
			return nil
		}
		if err := dst.Table(tc.srcTable).Clauses(clause.OnConflict{DoNothing: true}).
			Create(rows).Error; err != nil {
			return fmt.Errorf("写入导出文件 %s 失败: %w", tc.srcTable, err)
		}
		total += int64(len(rows))
		return nil
	})
	if result.Error != nil {
		return total, fmt.Errorf("读取 %s 失败: %w", tc.srcTable, result.Error)
	}
	return total, nil
}
