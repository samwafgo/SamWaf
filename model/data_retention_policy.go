package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

// DataRetentionPolicy 数据保留策略
//
// DbType 枚举值：
//   - "stats" → GWAF_LOCAL_STATS_DB（统计库，默认）
//   - "log"   → GWAF_LOCAL_LOG_DB（日志库）
//   - "core"  → GWAF_LOCAL_DB（核心库，预留）
type DataRetentionPolicy struct {
	baseorm.BaseOrm
	TableName     string              `json:"table_name"`      // 目标表名，如 stats_ip_days
	DbType        string              `json:"db_type"`         // 归属库类型：stats / log / core
	RetainDays    int64               `json:"retain_days"`     // 保留天数，0=不按天清理
	RetainRows    int64               `json:"retain_rows"`     // 保留行数，0=不按行清理
	DayField      string              `json:"day_field"`       // 天数清理依赖的字段名，如 "day" 或 "create_time"
	DayFieldType  string              `json:"day_field_type"`  // 天数字段类型：int_day(YYYYMMDD整数) / datetime(时间类型)
	RowOrderField string              `json:"row_order_field"` // 行数清理的排序字段，如 "day"、"update_time"、"cnt"
	RowOrderDir   string              `json:"row_order_dir"`   // 排序方向：DESC=保留值最大的(最新)，ASC=保留值最小的
	CleanEnabled  int64               `json:"clean_enabled"`   // 1=启用 0=禁用
	LastCleanTime customtype.JsonTime `json:"last_clean_time"` // 上次清理时间
	LastCleanRows int64               `json:"last_clean_rows"` // 上次清理的行数
	Remarks       string              `json:"remarks"`         // 备注
}
