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

// exportInsertBatch 单条 INSERT 的最大行数：驱动有效变量上限是 999，
// 列最多的表（web_logs，60+ 列）按 10 行一批也只占 600+ 个变量，留有余量。
const exportInsertBatch = 10

// ExportSource 一个导出数据源：分片连接 + 该分片各层实际的表名（空 = 该分片没有这一层）。
// 来源列表由 service 层按时间段扇出得出（与列表查询同一套选片逻辑）：
// 只导实时库会在「时间段落在已归档分区」时导出空表。
type ExportSource struct {
	Shard  string
	Tables TierTables
}

// exportTierDef 一个可导出的层：模型（导出文件建表用）+ 导出件里的标准表名 + 从分片取源表名
type exportTierDef struct {
	name     string
	model    interface{}
	dstTable string
	pick     func(TierTables) string
}

var exportTierDefs = []exportTierDef{
	{ExportTierAccess, &model.AccessLog{}, model.AccessLogTableName, func(t TierTables) string { return t.Access }},
	{ExportTierEvent, &model.SecurityEvent{}, model.SecurityEventTableName, func(t TierTables) string { return t.Event }},
	{ExportTierPayload, &model.EventPayload{}, model.EventPayloadTableName, func(t TierTables) string { return t.Payload }},
	{ExportTierWeblog, &innerbean.WebLog{}, LogTableName, func(t TierTables) string { return t.WebLog }},
}

// ExportLogRangeDb 把各数据源（实时库 + 命中的归档分区）按时间段导出成一个新的加密 SQLite 文件（C11）。
//
// 分层后「导出一个 .db」不再是备份整个库文件：按选定层 + 时间段导出行，
// 导出件自带表结构（AutoMigrate），可直接用同一套密钥打开查阅。
// startTime/endTime 为 "2006-01-02 15:04:05"，空 = 不限制。返回每层导出的行数。
func ExportLogRangeDb(outPath, startTime, endTime string, tiers map[string]bool, sources []ExportSource) (map[string]int64, error) {
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

	for _, td := range exportTierDefs {
		if !tiers[td.name] {
			continue
		}
		// 有任何一个源带着这一层才建表：一张都没有时导出件里不留空表，
		// 打开导出件一眼能看出这次确实没选/没有这一层
		migrated := false
		for _, s := range sources {
			if s.Tables.DB == nil {
				continue
			}
			srcTable := td.pick(s.Tables)
			if srcTable == "" || !dialect.Get().TableExists(s.Tables.DB, srcTable) {
				continue
			}
			if !migrated {
				if err := dst.AutoMigrate(td.model); err != nil {
					return counts, fmt.Errorf("导出文件建表 %s 失败: %w", td.dstTable, err)
				}
				migrated = true
			}
			var n int64
			var err error
			switch td.name {
			case ExportTierAccess:
				n, err = exportCopyTier[model.AccessLog](s.Tables.DB, dst, srcTable, td.dstTable, startTime, endTime)
			case ExportTierEvent:
				n, err = exportCopyTier[model.SecurityEvent](s.Tables.DB, dst, srcTable, td.dstTable, startTime, endTime)
			case ExportTierPayload:
				n, err = exportCopyTier[model.EventPayload](s.Tables.DB, dst, srcTable, td.dstTable, startTime, endTime)
			case ExportTierWeblog:
				n, err = exportCopyTier[innerbean.WebLog](s.Tables.DB, dst, srcTable, td.dstTable, startTime, endTime)
			}
			if err != nil {
				return counts, fmt.Errorf("分片 %s: %w", s.Shard, err)
			}
			counts[td.name] += n
		}
	}
	return counts, nil
}

// ResolveExportTables 导出专用的层解析：每层独立按「表存在且有行」判断。
// 读侧的 ResolveTierTables 是「选一个年代」——分层数据有行时 web_logs 存量行被忽略；
// 导出要把数据都带上，边界分片里新旧两层并存时两层都导。
// 仅支持文件型（SQLite）：导出本身就只在 SQLite 下开放。
func ResolveExportTables(currentDbName string) TierTables {
	if isLiveIdent(currentDbName) {
		return TierTables{
			DB:      global.GWAF_LOCAL_LOG_DB,
			Access:  model.AccessLogTableName,
			Event:   model.SecurityEventTableName,
			Payload: model.EventPayloadTableName,
			WebLog:  LogTableName,
		}
	}
	if !dialect.Get().IsFileBased() {
		return TierTables{Err: fmt.Errorf("导出仅支持 SQLite，认不出的分区标识: %q", currentDbName)}
	}
	db, _, err := ResolveLogDB(currentDbName)
	if err != nil {
		return TierTables{Err: err}
	}
	has := func(name string) string {
		if tableHasRows(db, name) {
			return name
		}
		return ""
	}
	t := TierTables{DB: db}
	t.Access = has(model.AccessLogTableName)
	t.Event = has(model.SecurityEventTableName)
	t.Payload = has(model.EventPayloadTableName)
	t.WebLog = has(LogTableName)
	t.Empty = t.Access == "" && t.Event == "" && t.Payload == "" && t.WebLog == ""
	return t
}

// exportCopyTier 按 create_time 区间分批读源表、批量写导出文件。主键冲突保留先到的（重复导出同一区间不会翻倍）。
//
// 必须用带主键的模型切片接行：FindInBatches 靠目标类型的主键续批（WHERE pk > 上一批最大主键），
// 导出期间实时表仍在写入也不会错位；用 map 接行没有主键信息，GORM 会报 model value required。
func exportCopyTier[T any](src, dst *gorm.DB, srcTable, dstTable, startTime, endTime string) (int64, error) {
	var total int64
	q := src.Table(srcTable)
	if startTime != "" {
		q = q.Where("create_time >= ?", startTime)
	}
	if endTime != "" {
		q = q.Where("create_time <= ?", endTime)
	}
	rows := []T{}
	result := q.FindInBatches(&rows, exportBatchSize, func(tx *gorm.DB, batch int) error {
		if len(rows) == 0 {
			return nil
		}
		// 一批 1000 行 × 几十列远超变量上限，按 exportInsertBatch 拆成小 INSERT；
		// 切片 Create 默认包在一个事务里，拆开不会引入逐行提交的开销。
		if err := dst.Session(&gorm.Session{CreateBatchSize: exportInsertBatch}).
			Table(dstTable).Clauses(clause.OnConflict{DoNothing: true}).
			Create(&rows).Error; err != nil {
			return fmt.Errorf("写入导出文件 %s 失败: %w", dstTable, err)
		}
		total += int64(len(rows))
		return nil
	})
	if result.Error != nil {
		return total, fmt.Errorf("读取 %s 失败: %w", srcTable, result.Error)
	}
	return total, nil
}
