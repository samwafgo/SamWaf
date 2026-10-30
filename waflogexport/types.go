package waflogexport

import "time"

type Options struct {
	Dir            string
	Format         string
	Tables         []string
	Key            string
	TaskID         string
	MaxBytes       int64
	TempQuotaBytes int64
	MinFreeBytes   uint64
	PartBytes      int64
	CSVMaxRows     int64
	Manifest       Manifest
}

type SourceStatus struct {
	ID             string   `json:"id"`
	Driver         string   `json:"driver"`
	Table          string   `json:"table,omitempty"`
	Status         string   `json:"status"`
	SnapshotTime   string   `json:"snapshot_time,omitempty"`
	MissingColumns []string `json:"missing_columns,omitempty"`
	ErrorCode      string   `json:"error_code,omitempty"`
}

type TableCount struct {
	Read      int64 `json:"read"`
	Skipped   int64 `json:"deduplicated"`
	Conflicts int64 `json:"conflicts"`
	Written   int64 `json:"written"`
}

type FileInfo struct {
	Name   string `json:"name"`
	Rows   int64  `json:"rows"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion      string                `json:"schema_version"`
	ApplicationVersion string                `json:"application_version"`
	TaskID             string                `json:"task_id"`
	Format             string                `json:"format"`
	Tables             []string              `json:"tables"`
	RequestedStart     string                `json:"requested_start,omitempty"`
	RequestedEnd       string                `json:"requested_end,omitempty"`
	ActualStart        string                `json:"actual_start,omitempty"`
	ActualEnd          string                `json:"actual_end,omitempty"`
	Timezone           string                `json:"timezone"`
	SourceDriver       string                `json:"source_driver"`
	Consistency        string                `json:"consistency"`
	GeneratedAt        time.Time             `json:"generated_at"`
	Sources            []SourceStatus        `json:"sources"`
	MissingColumns     map[string][]string   `json:"missing_columns,omitempty"`
	Counts             map[string]TableCount `json:"counts"`
	Files              []FileInfo            `json:"files"`
	Fields             map[string][]Field    `json:"fields"`
	Notes              []string              `json:"notes"`
}

type Stats struct {
	Counts map[string]TableCount
	Bytes  int64
}
type Result struct {
	Path       string
	Manifest   Manifest
	Size       int64
	ZIPBytes   int64
	SHA256     string
	WrappedKey string
}
