package model

import "time"

// LogExportTask 保存导出任务元数据。
type LogExportTask struct {
	Id           string     `gorm:"size:64;primaryKey" json:"-"`
	UserCode     string     `gorm:"column:user_code;size:64" json:"-"`
	TenantID     string     `gorm:"column:tenant_id;size:64;uniqueIndex:idx_log_export_request,priority:1;index:idx_log_export_creator,priority:1" json:"-"`
	CreatorID    string     `gorm:"column:creator_id;size:64;uniqueIndex:idx_log_export_request,priority:2;index:idx_log_export_creator,priority:2" json:"-"`
	RequestID    string     `gorm:"size:64;uniqueIndex:idx_log_export_request,priority:3" json:"-"`
	Format       string     `gorm:"size:16" json:"-"`
	TablesJSON   string     `gorm:"type:text" crypto:"aes" json:"-"`
	RangeMode    string     `gorm:"type:text" crypto:"aes" json:"-"`
	StartTime    string     `gorm:"type:text" crypto:"aes" json:"-"`
	EndTime      string     `gorm:"type:text" crypto:"aes" json:"-"`
	Status       string     `gorm:"size:24;index:idx_log_export_status" json:"-"`
	Phase        string     `gorm:"size:32" json:"-"`
	RowsWritten  int64      `json:"-"`
	BytesWritten int64      `json:"-"`
	SourceDone   int        `json:"-"`
	SourceTotal  int        `json:"-"`
	ParamsJSON   string     `gorm:"type:text" crypto:"aes" json:"-"`
	ErrorCode    string     `gorm:"size:64" json:"-"`
	ErrorMessage string     `gorm:"size:512" json:"-"`
	CreatedAt    time.Time  `gorm:"index:idx_log_export_creator,priority:3" json:"-"`
	StartedAt    *time.Time `json:"-"`
	HeartbeatAt  *time.Time `json:"-"`
	FinishedAt   *time.Time `json:"-"`
	ExpiresAt    *time.Time `gorm:"index:idx_log_export_expiry" json:"-"`
	Owner        string     `gorm:"size:128" json:"-"`
	ArtifactKey  string     `gorm:"type:text" crypto:"aes" json:"-"`
	ArtifactName string     `gorm:"size:128" json:"-"`
	Checksum     string     `gorm:"size:64" json:"-"`
}

func (LogExportTask) TableName() string { return "log_export_task" }
