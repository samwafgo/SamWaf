package dialect

import (
	"time"

	"gorm.io/gorm"
)

// ColumnMeta holds metadata for a single table column.
type ColumnMeta struct {
	Cid        int
	Name       string
	Type       string
	NotNull    bool
	DefaultVal string
	PrimaryKey bool
}

// IndexColumnMeta describes a column participating in an index.
type IndexColumnMeta struct {
	SeqNo int
	Cid   int
	Name  string
}

// IndexMeta holds metadata for a table index.
type IndexMeta struct {
	Name    string
	Unique  bool
	Origin  string // SQLite: "c"=created, "u"=unique, "pk"=primary; empty for others
	Columns []IndexColumnMeta
}

// DBMetrics holds runtime performance metrics. Fields are driver-specific;
// irrelevant fields are zero-valued (omitempty in JSON output).
type DBMetrics struct {
	DatabaseName     string    `json:"database_name"`
	DatabasePath     string    `json:"database_path,omitempty"` // file-based only
	FileSize         int64     `json:"file_size,omitempty"`
	FileSizeMB       float64   `json:"file_size_mb,omitempty"`
	ConnectionCount  int       `json:"connection_count"`
	MaxConnections   int       `json:"max_connections"`
	IdleConnections  int       `json:"idle_connections"`
	InUseConnections int       `json:"in_use_connections"`
	Timestamp        time.Time `json:"timestamp"`

	// SQLite-specific (PRAGMA)
	PageCount       int64   `json:"page_count,omitempty"`
	PageSize        int64   `json:"page_size,omitempty"`
	FreelistCount   int64   `json:"freelist_count,omitempty"`
	CacheSize       int64   `json:"cache_size,omitempty"`
	JournalMode     string  `json:"journal_mode,omitempty"`
	SynchronousMode string  `json:"synchronous_mode,omitempty"`
	TempStore       string  `json:"temp_store,omitempty"`
	CacheHitRatio   float64 `json:"cache_hit_ratio,omitempty"`

	// MySQL / SQL Server specific
	EngineVersion string  `json:"engine_version,omitempty"`
	DataSizeMB    float64 `json:"data_size_mb,omitempty"`
	IndexSizeMB   float64 `json:"index_size_mb,omitempty"`
	CurrentConns  int     `json:"current_connections,omitempty"`
}

// DBDialect abstracts SQL dialect differences so business logic stays
// database-agnostic. Each database engine provides one implementation.
// Register the active implementation once at startup via Register().
type DBDialect interface {
	// Name returns the driver identifier: "sqlite" | "mysql" | "sqlserver".
	Name() string

	// IsFileBased returns true for file-based databases (SQLite).
	// Used to guard backup/repair operations that operate on files.
	IsFileBased() bool

	// SupportsBackup reports whether the built-in backup tool is available.
	SupportsBackup() bool

	// SupportsRepair reports whether the built-in repair tool is available.
	SupportsRepair() bool

	// ForceIndexClause returns the table reference with an index hint.
	//   SQLite:    "tbl INDEXED BY idx"
	//   MySQL:     "tbl FORCE INDEX (idx)"
	//   SQL Server:"tbl WITH (INDEX(idx))"
	ForceIndexClause(table, idx string) string

	// FormatLocalTime returns a SQL expression that renders a DATETIME column as
	// 'YYYY-MM-DD HH:MM:SS' in local time, matching customtype.JsonTime.MarshalJSON.
	//
	// Storage contract: SamWaf writes time.Time in LOCAL time, never UTC.
	//   MySQL:  DSN carries loc=Local, so the DATETIME column holds the local
	//           wall clock with no zone info — format it as-is, no CONVERT_TZ.
	//   SQLite: go-wxsqlite3 binds time.Time as '2006-01-02 15:04:05.999999999-07:00',
	//           so the text carries a zone suffix that SQLite normalizes to UTC;
	//           the local offset has to be added back.
	FormatLocalTime(colExpr string) string

	// RenameTable renames src to dst within the same schema.
	// For SQLite the caller handles file-level rename; this handles in-DB rename
	// for server databases (MySQL: RENAME TABLE; MSSQL: sp_rename).
	RenameTable(db *gorm.DB, src, dst string) error

	// ShardSwapTable atomically archives liveTable to archiveTable and leaves an
	// empty liveTable in place (same structure + indexes), used for log table
	// sharding on server databases.
	//   MySQL: CREATE TABLE <live>_tmp LIKE <live>; RENAME TABLE <live> TO <archive>, <live>_tmp TO <live>
	// File-based databases (SQLite) shard via OS-level file rename instead and
	// return an error here ("not supported").
	ShardSwapTable(db *gorm.DB, liveTable, archiveTable string) error

	// TableSizeMB returns the on-disk size (data + index) of a table in MB,
	// used by the sharding task to detect the size threshold on server databases.
	// File-based databases (SQLite) return 0 (the caller uses the file size instead).
	TableSizeMB(db *gorm.DB, table string) (int64, error)

	// ListTables returns all user-defined table names in the current schema.
	ListTables(db *gorm.DB) ([]string, error)

	// TableExists reports whether the named table exists.
	TableExists(db *gorm.DB, name string) bool

	// ColumnInfo returns column metadata for the given table.
	ColumnInfo(db *gorm.DB, table string) ([]ColumnMeta, error)

	// IndexInfo returns index metadata for the given table.
	IndexInfo(db *gorm.DB, table string) ([]IndexMeta, error)

	// CollectMetrics gathers runtime performance metrics.
	// name is a human-readable label; path is the file path (SQLite) or empty.
	CollectMetrics(db *gorm.DB, name, path string) (*DBMetrics, error)
}
