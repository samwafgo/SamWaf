package wafconfig

import (
	"SamWaf/global"
	"testing"

	"github.com/spf13/viper"
)

func TestLogExportBudgetConfig(t *testing.T) {
	previous := global.GLOG_EXPORT_CONFIG
	t.Cleanup(func() { global.GLOG_EXPORT_CONFIG = previous })
	defaults := global.DefaultLogExportConfig()
	for _, tc := range []struct {
		name   string
		values map[string]interface{}
		want   global.LogExportConfig
	}{
		{"defaults", nil, defaults},
		{"invalid", map[string]interface{}{
			"queue_limit": -1, "timeout_minutes": 121, "max_uncompressed_gib": "invalid",
			"temp_quota_gib": 2049, "min_free_gib": 0, "retention_hours": 169, "sqlite_wal_max_gib": 0,
		}, defaults},
		{"lower_bound", map[string]interface{}{
			"queue_limit": 0, "timeout_minutes": 1, "max_uncompressed_gib": 1,
			"temp_quota_gib": 1, "min_free_gib": 1, "retention_hours": 1, "sqlite_wal_max_gib": 1,
		}, global.LogExportConfig{QueueLimit: 0, TimeoutMinutes: 1, MaxUncompressedGiB: 1, TempQuotaGiB: 1, MinFreeGiB: 1, RetentionHours: 1, SQLiteWALMaxGiB: 1}},
		{"upper_bound", map[string]interface{}{
			"queue_limit": 10, "timeout_minutes": 120, "max_uncompressed_gib": 1024,
			"temp_quota_gib": 2048, "min_free_gib": 1024, "retention_hours": 168, "sqlite_wal_max_gib": 1024,
		}, global.LogExportConfig{QueueLimit: 10, TimeoutMinutes: 120, MaxUncompressedGiB: 1024, TempQuotaGiB: 2048, MinFreeGiB: 1024, RetentionHours: 168, SQLiteWALMaxGiB: 1024}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := viper.New()
			for key, value := range tc.values {
				config.Set("log_export."+key, value)
			}
			loadLogExportConfig(config)
			if got := global.GLOG_EXPORT_CONFIG; got != tc.want {
				t.Fatalf("budget=%+v want=%+v", got, tc.want)
			}
		})
	}
}
