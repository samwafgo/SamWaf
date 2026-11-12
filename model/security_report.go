package model

// SecurityReportSettings 保存实例报告设置。
// user_code 必须落库：core 库查询回调会给所有查询附加 tenant_id + user_code 条件，
// 缺列会导致生产环境读不到本表（测试库不注册该回调，问题只在线上暴露）。
type SecurityReportSettings struct {
	TenantID       string `gorm:"size:64;primaryKey" json:"-"`
	UserCode       string `gorm:"column:user_code;size:64;primaryKey" json:"-"`
	SettingsCipher string `gorm:"type:text" json:"-"`
	StartedAt      int64  `json:"-"`
	Revision       int64  `json:"-"`
}

func (SecurityReportSettings) TableName() string { return "security_report_settings" }

// SecurityReportTask 保存生成状态及加密产物索引。
type SecurityReportTask struct {
	ID           string `gorm:"size:64;primaryKey" json:"id"`
	TenantID     string `gorm:"size:64;index:idx_report_tenant_created,priority:1" json:"-"`
	UserCode     string `gorm:"column:user_code;size:64;index:idx_report_tenant_created,priority:2" json:"-"`
	DedupKey     string `gorm:"size:64;uniqueIndex:idx_report_dedup" json:"-"`
	Kind         string `gorm:"size:16" json:"kind"`
	RangeStart   int64  `json:"range_start"`
	RangeEnd     int64  `json:"range_end"`
	CreatedAt    int64  `gorm:"index:idx_report_tenant_created,priority:3" json:"created_at"`
	CompletedAt  int64  `json:"completed_at"`
	Status       string `gorm:"size:16;index:idx_report_status" json:"status"`
	Source       string `gorm:"size:16" json:"source"`
	RetryCount   int64  `json:"-"`
	SizeBytes    int64  `json:"size_bytes"`
	ErrorMessage string `gorm:"size:256" json:"error_message"`
	ConfigCipher string `gorm:"type:text" json:"-"`
	ArtifactKey  string `gorm:"type:text" json:"-"`
}

func (SecurityReportTask) TableName() string { return "security_report_tasks" }
