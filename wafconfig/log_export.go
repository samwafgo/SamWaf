package wafconfig

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

func loadLogExportConfig(config *viper.Viper) {
	budget := global.DefaultLogExportConfig()
	settings := []struct {
		key      string
		value    *int
		min, max int
	}{
		{"queue_limit", &budget.QueueLimit, 0, 10},
		{"timeout_minutes", &budget.TimeoutMinutes, 1, 120},
		{"max_uncompressed_gib", &budget.MaxUncompressedGiB, 1, 1024},
		{"temp_quota_gib", &budget.TempQuotaGiB, 1, 2048},
		{"min_free_gib", &budget.MinFreeGiB, 1, 1024},
		{"retention_hours", &budget.RetentionHours, 1, 168},
		{"sqlite_wal_max_gib", &budget.SQLiteWALMaxGiB, 1, 1024},
	}
	for _, setting := range settings {
		key := "log_export." + setting.key
		if !config.IsSet(key) {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(config.GetString(key)))
		if err != nil || value < setting.min || value > setting.max {
			zlog.Warn("日志导出预算配置超出范围，使用默认值", key)
			continue
		}
		*setting.value = value
	}
	global.GLOG_EXPORT_CONFIG = budget
}
