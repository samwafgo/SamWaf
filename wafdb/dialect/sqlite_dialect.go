package dialect

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
)

// SQLiteDialect implements DBDialect for SQLite databases.
type SQLiteDialect struct{}

func (d *SQLiteDialect) Name() string         { return "sqlite" }
func (d *SQLiteDialect) IsFileBased() bool    { return true }
func (d *SQLiteDialect) SupportsBackup() bool { return true }
func (d *SQLiteDialect) SupportsRepair() bool { return true }

func (d *SQLiteDialect) ForceIndexClause(table, idx string) string {
	return fmt.Sprintf("%s INDEXED BY %s", table, idx)
}

func (d *SQLiteDialect) Quote(ident string) string { return sqliteQuote(ident) }

// BatchDeleteSQL uses SQLite's implicit rowid pseudo-column, which works even on
// tables without a declared primary key (web_logs).
func (d *SQLiteDialect) BatchDeleteSQL(table, where string, limit int) string {
	q := sqliteQuote(table)
	return fmt.Sprintf(
		"DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s LIMIT %d)",
		q, q, where, limit,
	)
}

func (d *SQLiteDialect) GroupConcatDistinct(expr string) string {
	return fmt.Sprintf("GROUP_CONCAT(DISTINCT %s)", expr)
}

func (d *SQLiteDialect) InsertIgnoreSQL(table, quotedCols, rowPlaceholders string) string {
	return fmt.Sprintf("INSERT OR IGNORE INTO %s (%s) VALUES %s",
		sqliteQuote(table), quotedCols, rowPlaceholders)
}

// FormatLocalTime adds the local UTC offset back: go-wxsqlite3 stores time.Time
// as text carrying a zone suffix ('+08:00'), which SQLite normalizes to UTC
// before applying the modifier.
func (d *SQLiteDialect) FormatLocalTime(colExpr string) string {
	_, offset := time.Now().Zone()
	offsetMin := offset / 60
	if offsetMin >= 0 {
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:%%M:%%S', %s, '+%d minutes')", colExpr, offsetMin)
	}
	return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:%%M:%%S', %s, '%d minutes')", colExpr, offsetMin)
}

// RenameTable uses SQLite's ALTER TABLE … RENAME TO syntax.
// Note: for WAL-mode databases the caller must also rename the companion
// .db-shm and .db-wal files at the OS level after closing the connection.
func (d *SQLiteDialect) RenameTable(db *gorm.DB, src, dst string) error {
	return db.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s", sqliteQuote(src), sqliteQuote(dst))).Error
}

// ShardSwapTable is not used for SQLite: sharding is done by renaming the whole
// .db file at the OS level (see waftask.TaskShareDbInfo). Returns an error to
// guard against accidental use.
func (d *SQLiteDialect) ShardSwapTable(db *gorm.DB, liveTable, archiveTable string) error {
	return fmt.Errorf("ShardSwapTable 不适用于 SQLite（按文件改名分库），当前驱动: sqlite")
}

// TableSizeMB returns 0 for SQLite; the caller uses the .db file size instead.
func (d *SQLiteDialect) TableSizeMB(db *gorm.DB, table string) (int64, error) {
	return 0, nil
}

func (d *SQLiteDialect) ListTables(db *gorm.DB) ([]string, error) {
	rows, err := db.Raw(
		"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
	).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if scanErr := rows.Scan(&name); scanErr == nil {
			tables = append(tables, name)
		}
	}
	return tables, nil
}

func (d *SQLiteDialect) TableExists(db *gorm.DB, name string) bool {
	var count int64
	db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&count)
	return count > 0
}

func (d *SQLiteDialect) ColumnInfo(db *gorm.DB, table string) ([]ColumnMeta, error) {
	rows, err := db.Raw("PRAGMA table_info(" + sqliteQuote(table) + ")").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []ColumnMeta
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt sql.NullString
		if scanErr := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); scanErr == nil {
			cols = append(cols, ColumnMeta{
				Cid:        cid,
				Name:       name,
				Type:       typ,
				NotNull:    notNull == 1,
				DefaultVal: dflt.String,
				PrimaryKey: pk > 0,
			})
		}
	}
	return cols, nil
}

func (d *SQLiteDialect) IndexInfo(db *gorm.DB, table string) ([]IndexMeta, error) {
	idxRows, err := db.Raw("PRAGMA index_list(" + sqliteQuote(table) + ")").Rows()
	if err != nil {
		return nil, err
	}
	defer idxRows.Close()

	var indexes []IndexMeta
	for idxRows.Next() {
		var seq int
		var idxName, origin string
		var unique, partial int
		if scanErr := idxRows.Scan(&seq, &idxName, &unique, &origin, &partial); scanErr != nil {
			continue
		}
		meta := IndexMeta{
			Name:   idxName,
			Unique: unique == 1,
			Origin: origin,
		}
		colRows, colErr := db.Raw("PRAGMA index_info(" + sqliteQuote(idxName) + ")").Rows()
		if colErr == nil {
			for colRows.Next() {
				var seqNo, cid int
				var colName sql.NullString
				if scanErr2 := colRows.Scan(&seqNo, &cid, &colName); scanErr2 == nil {
					meta.Columns = append(meta.Columns, IndexColumnMeta{
						SeqNo: seqNo,
						Cid:   cid,
						Name:  colName.String,
					})
				}
			}
			colRows.Close()
		}
		indexes = append(indexes, meta)
	}
	return indexes, nil
}

func (d *SQLiteDialect) CollectMetrics(db *gorm.DB, name, path string) (*DBMetrics, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil: %s", name)
	}
	m := &DBMetrics{
		DatabaseName: name,
		DatabasePath: path,
		Timestamp:    time.Now(),
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB failed: %v", err)
	}
	stats := sqlDB.Stats()
	m.ConnectionCount = stats.OpenConnections
	m.MaxConnections = stats.MaxOpenConnections
	m.IdleConnections = stats.Idle
	m.InUseConnections = stats.InUse

	if fi, statErr := os.Stat(path); statErr == nil {
		m.FileSize = fi.Size()
		m.FileSizeMB = float64(fi.Size()) / (1024 * 1024)
	}

	db.Raw("PRAGMA page_count").Scan(&m.PageCount)
	db.Raw("PRAGMA page_size").Scan(&m.PageSize)
	db.Raw("PRAGMA freelist_count").Scan(&m.FreelistCount)
	db.Raw("PRAGMA cache_size").Scan(&m.CacheSize)
	db.Raw("PRAGMA journal_mode").Scan(&m.JournalMode)
	db.Raw("PRAGMA synchronous").Scan(&m.SynchronousMode)
	db.Raw("PRAGMA temp_store").Scan(&m.TempStore)

	var cacheHit, cacheMiss int64
	db.Raw("PRAGMA cache_hit").Scan(&cacheHit)
	db.Raw("PRAGMA cache_miss").Scan(&cacheMiss)
	if cacheHit+cacheMiss > 0 {
		m.CacheHitRatio = float64(cacheHit) / float64(cacheHit+cacheMiss) * 100
	}

	return m, nil
}

// sqliteQuote wraps a SQLite identifier in double quotes.
func sqliteQuote(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
