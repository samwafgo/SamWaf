package global

// LogExportConfig 仅由部署配置加载。
type LogExportConfig struct {
	QueueLimit         int
	TimeoutMinutes     int
	MaxUncompressedGiB int
	TempQuotaGiB       int
	MinFreeGiB         int
	RetentionHours     int
	SQLiteWALMaxGiB    int
}

func DefaultLogExportConfig() LogExportConfig {
	return LogExportConfig{
		QueueLimit: 2, TimeoutMinutes: 30, MaxUncompressedGiB: 10,
		TempQuotaGiB: 20, MinFreeGiB: 2, RetentionHours: 24, SQLiteWALMaxGiB: 2,
	}
}

var GLOG_EXPORT_CONFIG = DefaultLogExportConfig()
