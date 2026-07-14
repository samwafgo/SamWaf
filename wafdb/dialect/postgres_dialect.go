package dialect

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// PostgresDialect implements DBDialect for PostgreSQL 12+ databases.
type PostgresDialect struct{}

func (d *PostgresDialect) Name() string         { return "postgres" }
func (d *PostgresDialect) IsFileBased() bool    { return false }
func (d *PostgresDialect) SupportsBackup() bool { return false }
func (d *PostgresDialect) SupportsRepair() bool { return false }

// ForceIndexClause returns the bare table name: PostgreSQL has no index hints.
// The planner picks the index itself. Callers feed the result to .Table(), which
// still works — they just lose the hint.
func (d *PostgresDialect) ForceIndexClause(table, idx string) string {
	return table
}

// FormatLocalTime renders a timestamptz column in the session time zone.
//
// Storage contract: SamWaf writes time.Time in LOCAL time. GORM maps
// customtype.JsonTime to timestamptz, which stores the true instant; to_char then
// renders it in whatever zone the session is set to. The session zone is pinned by
// the TimeZone DSN parameter (see BuildPostgresDSN), so as long as that matches the
// host's local zone this yields the same wall clock the app wrote — no manual offset
// arithmetic needed (unlike SQLite, which stores a zone suffix as text).
func (d *PostgresDialect) FormatLocalTime(colExpr string) string {
	return fmt.Sprintf("to_char(%s, 'YYYY-MM-DD HH24:MI:SS')", colExpr)
}

func (d *PostgresDialect) Quote(ident string) string { return pgQuote(ident) }

// BatchDeleteSQL uses ctid, PostgreSQL's physical row identifier. web_logs has no
// primary key, so there is no id column to key the delete on.
func (d *PostgresDialect) BatchDeleteSQL(table, where string, limit int) string {
	q := pgQuote(table)
	return fmt.Sprintf(
		"DELETE FROM %s WHERE ctid IN (SELECT ctid FROM %s WHERE %s LIMIT %d)",
		q, q, where, limit,
	)
}

// GroupConcatDistinct maps to string_agg; PostgreSQL has no GROUP_CONCAT.
// The expression is cast to text because string_agg has no overload for the
// non-text types a CASE arm may produce.
func (d *PostgresDialect) GroupConcatDistinct(expr string) string {
	return fmt.Sprintf("string_agg(DISTINCT (%s)::text, ',')", expr)
}

// InsertIgnoreSQL uses ON CONFLICT DO NOTHING with no conflict target, which skips
// rows violating ANY unique constraint. With no unique key there is nothing to
// conflict on and this degrades to a plain INSERT (true of INSERT IGNORE too).
func (d *PostgresDialect) InsertIgnoreSQL(table, quotedCols, rowPlaceholders string) string {
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES %s ON CONFLICT DO NOTHING",
		pgQuote(table), quotedCols, rowPlaceholders)
}

func (d *PostgresDialect) RenameTable(db *gorm.DB, src, dst string) error {
	return db.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s", pgQuote(src), pgQuote(dst))).Error
}

// ShardSwapTable archives liveTable to archiveTable and leaves an empty liveTable.
//
// Unlike MySQL there is no atomic multi-table RENAME, but PostgreSQL DDL is
// transactional, so wrapping the steps in one transaction gives the same guarantee.
//
// The subtlety is index names. Renaming a table carries its indexes along WITH THEIR
// NAMES, and "CREATE TABLE ... (LIKE ... INCLUDING ALL)" auto-generates fresh names
// rather than reusing them. Do it naively and the archive table walks off with the
// canonical names (idx_web_time_desc_tenant_user_code, ...) while the new live table
// gets web_logs_shardtmp_*_idx. On the next boot safeCreateIndex's HasIndex() lookup
// misses and recreates them — duplicate indexes accumulate on the hottest table in
// the system, one set per shard cycle.
//
// So: snapshot the live table's index DDL first, rename the archive's indexes out of
// the way to free the canonical names, create the new live table WITHOUT indexes, then
// replay the captured DDL verbatim (it names the live table, which now points at the
// new empty one).
func (d *PostgresDialect) ShardSwapTable(db *gorm.DB, liveTable, archiveTable string) error {
	type indexDef struct {
		IndexName string
		IndexDef  string
	}
	var defs []indexDef
	if err := db.Raw(
		"SELECT indexname AS index_name, indexdef AS index_def FROM pg_indexes "+
			"WHERE schemaname = current_schema() AND tablename = ?", liveTable,
	).Scan(&defs).Error; err != nil {
		return fmt.Errorf("postgres: 读取 %s 索引定义失败: %w", liveTable, err)
	}

	// Suffix used to park the archived table's index names (e.g. "20260714_120000").
	suffix := strings.TrimPrefix(archiveTable, liveTable+"_")

	return db.Transaction(func(tx *gorm.DB) error {
		// 1. Rename live → archive. Indexes follow and keep their (canonical) names.
		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s",
			pgQuote(liveTable), pgQuote(archiveTable))).Error; err != nil {
			return fmt.Errorf("postgres: 重命名 %s → %s 失败: %w", liveTable, archiveTable, err)
		}

		// 2. Park the archived indexes, freeing the canonical names for the new live table.
		for _, def := range defs {
			newName := truncateIdent(def.IndexName+"_"+suffix, pgMaxIdentLen)
			if err := tx.Exec(fmt.Sprintf("ALTER INDEX %s RENAME TO %s",
				pgQuote(def.IndexName), pgQuote(newName))).Error; err != nil {
				return fmt.Errorf("postgres: 重命名索引 %s 失败: %w", def.IndexName, err)
			}
		}

		// 3. New empty live table: structure only, no indexes (they come from the replay).
		if err := tx.Exec(fmt.Sprintf(
			"CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS INCLUDING CONSTRAINTS)",
			pgQuote(liveTable), pgQuote(archiveTable))).Error; err != nil {
			return fmt.Errorf("postgres: 创建新的 %s 失败: %w", liveTable, err)
		}

		// 4. Replay the captured DDL. Each statement names liveTable, which now refers
		//    to the fresh empty table, and the canonical index names are free again.
		for _, def := range defs {
			if err := tx.Exec(def.IndexDef).Error; err != nil {
				return fmt.Errorf("postgres: 重建索引 %s 失败: %w", def.IndexName, err)
			}
		}
		return nil
	})
}

// TableSizeMB returns the total on-disk size (table + indexes + TOAST) in MB.
// to_regclass yields NULL for a missing table, hence the COALESCE.
func (d *PostgresDialect) TableSizeMB(db *gorm.DB, table string) (int64, error) {
	var sizeMB int64
	err := db.Raw(
		"SELECT COALESCE(pg_total_relation_size(to_regclass(?)), 0) / (1024*1024)", table,
	).Scan(&sizeMB).Error
	return sizeMB, err
}

func (d *PostgresDialect) ListTables(db *gorm.DB) ([]string, error) {
	var tables []string
	err := db.Raw(
		"SELECT table_name FROM information_schema.tables " +
			"WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY table_name",
	).Scan(&tables).Error
	return tables, err
}

func (d *PostgresDialect) TableExists(db *gorm.DB, name string) bool {
	var count int64
	db.Raw(
		"SELECT COUNT(*) FROM information_schema.tables "+
			"WHERE table_schema = current_schema() AND table_name = ?", name,
	).Scan(&count)
	return count > 0
}

// ColumnInfo returns column metadata. The Type strings are PostgreSQL's
// information_schema.data_type values ("boolean", "integer", "bigint",
// "character varying", "text", "timestamp with time zone", "numeric", "bytea", ...).
// The migrate tool's type coercion keys off exactly these strings.
func (d *PostgresDialect) ColumnInfo(db *gorm.DB, table string) ([]ColumnMeta, error) {
	rows, err := db.Raw(`
		SELECT c.ordinal_position - 1,
		       c.column_name,
		       c.data_type,
		       CASE WHEN c.is_nullable = 'NO' THEN 1 ELSE 0 END,
		       COALESCE(c.column_default, ''),
		       CASE WHEN pk.column_name IS NOT NULL THEN 1 ELSE 0 END
		FROM information_schema.columns c
		LEFT JOIN (
			SELECT kcu.column_name
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu
			  ON kcu.constraint_name = tc.constraint_name
			 AND kcu.table_schema   = tc.table_schema
			WHERE tc.table_schema    = current_schema()
			  AND tc.table_name      = ?
			  AND tc.constraint_type = 'PRIMARY KEY'
		) pk ON pk.column_name = c.column_name
		WHERE c.table_schema = current_schema() AND c.table_name = ?
		ORDER BY c.ordinal_position`, table, table,
	).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []ColumnMeta
	for rows.Next() {
		var c ColumnMeta
		var notNull, pk int
		if err := rows.Scan(&c.Cid, &c.Name, &c.Type, &notNull, &c.DefaultVal, &pk); err == nil {
			c.NotNull = notNull == 1
			c.PrimaryKey = pk == 1
			cols = append(cols, c)
		}
	}
	return cols, nil
}

// IndexInfo returns index metadata, mirroring the SQLite Origin semantics
// ("pk" / "u" / "c") that the frontend DB-info page expects.
func (d *PostgresDialect) IndexInfo(db *gorm.DB, table string) ([]IndexMeta, error) {
	rows, err := db.Raw(`
		SELECT i.relname                AS index_name,
		       ix.indisunique           AS is_unique,
		       ix.indisprimary          AS is_primary,
		       k.ord - 1                AS seq_no,
		       a.attname                AS column_name
		FROM pg_class t
		JOIN pg_namespace n  ON n.oid = t.relnamespace
		JOIN pg_index ix     ON ix.indrelid = t.oid
		JOIN pg_class i      ON i.oid = ix.indexrelid
		JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
		JOIN pg_attribute a  ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE t.relname = ? AND n.nspname = current_schema()
		ORDER BY i.relname, k.ord`, table,
	).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	idxMap := make(map[string]*IndexMeta)
	var order []string
	for rows.Next() {
		var idxName, colName string
		var isUnique, isPrimary bool
		var seqNo int
		if err := rows.Scan(&idxName, &isUnique, &isPrimary, &seqNo, &colName); err != nil {
			continue
		}
		if _, ok := idxMap[idxName]; !ok {
			origin := "c"
			switch {
			case isPrimary:
				origin = "pk"
			case isUnique:
				origin = "u"
			}
			idxMap[idxName] = &IndexMeta{Name: idxName, Unique: isUnique, Origin: origin}
			order = append(order, idxName)
		}
		idxMap[idxName].Columns = append(idxMap[idxName].Columns,
			IndexColumnMeta{SeqNo: seqNo, Name: colName})
	}

	result := make([]IndexMeta, 0, len(order))
	for _, name := range order {
		result = append(result, *idxMap[name])
	}
	return result, nil
}

func (d *PostgresDialect) CollectMetrics(db *gorm.DB, name, path string) (*DBMetrics, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil: %s", name)
	}
	m := &DBMetrics{
		DatabaseName: name,
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

	db.Raw("SELECT version()").Scan(&m.EngineVersion)

	// Whole-database size doubles as the "file size" for the UI.
	var dbSizeBytes int64
	db.Raw("SELECT pg_database_size(current_database())").Scan(&dbSizeBytes)
	m.FileSize = dbSizeBytes
	m.FileSizeMB = float64(dbSizeBytes) / 1024 / 1024

	// Split table vs index bytes across the current schema.
	row := db.Raw(`
		SELECT COALESCE(SUM(pg_relation_size(c.oid)), 0) / 1024.0 / 1024.0,
		       COALESCE(SUM(pg_indexes_size(c.oid)), 0) / 1024.0 / 1024.0
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind = 'r'`).Row()
	_ = row.Scan(&m.DataSizeMB, &m.IndexSizeMB)

	db.Raw("SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()").
		Scan(&m.CurrentConns)

	// Shared-buffer hit ratio, the closest analogue to SQLite's cache hit ratio.
	db.Raw(`
		SELECT CASE WHEN (blks_hit + blks_read) > 0
		            THEN blks_hit::float8 / (blks_hit + blks_read)
		            ELSE 0 END
		FROM pg_stat_database WHERE datname = current_database()`).Scan(&m.CacheHitRatio)

	return m, nil
}

// pgMaxIdentLen is PostgreSQL's NAMEDATALEN-1. Longer identifiers are silently
// truncated by the server, which would turn a rename into a collision.
const pgMaxIdentLen = 63

// truncateIdent trims an identifier to max bytes so PostgreSQL does not do it for us.
func truncateIdent(name string, max int) string {
	if len(name) <= max {
		return name
	}
	return name[:max]
}

// BuildPostgresDSN returns a PostgreSQL connection URL.
//
// The URL form is used rather than the keyword/value form ("host=... password=...")
// because url.UserPassword escapes the password — the keyword/value form breaks on
// passwords containing spaces or quotes.
//
// timeZone pins the session time zone and is load-bearing: timestamptz values are
// returned in the session zone, and customtype.JsonTime formats whatever Location it
// receives. A wrong TimeZone silently shifts every timestamp in the UI.
func BuildPostgresDSN(host string, port int, user, password, dbName, sslMode, timeZone string) string {
	if sslMode == "" {
		sslMode = "disable"
	}

	// The query string is assembled by hand rather than with url.Values.Encode()
	// because Encode() percent-escapes the '/' in a zone name ("Asia/Shanghai" ->
	// "Asia%2FShanghai"). gorm.io/driver/postgres pulls the time zone out of the RAW
	// DSN with a regex (TimeZone=(.*?)($|&| )) and forwards the match to the server
	// verbatim, without URL-decoding it — so an escaped '/' reaches PostgreSQL as
	// literal "Asia%2FShanghai" and the connection dies with "unknown time zone".
	// '/' is legal unescaped in a query string (RFC 3986), so leaving it alone is safe
	// for pgx's own URL parsing too.
	//
	// The password still goes through url.UserPassword, which escapes it correctly —
	// that lives in the userinfo section, not the query.
	raw := "sslmode=" + sslMode + "&connect_timeout=10"
	if timeZone != "" {
		raw += "&TimeZone=" + timeZone
	}

	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     fmt.Sprintf("%s:%s", host, strconv.Itoa(port)),
		Path:     "/" + dbName,
		RawQuery: raw,
	}
	return u.String()
}

// BuildPostgresMaintenanceDSN connects to the maintenance database (usually "postgres")
// rather than a SamWaf database. PostgreSQL has no "CREATE DATABASE IF NOT EXISTS" and
// cannot create a database from within a connection to that database, so ensuring the
// SamWaf databases exist requires connecting somewhere else first.
func BuildPostgresMaintenanceDSN(host string, port int, user, password, maintenanceDB, sslMode string) string {
	if maintenanceDB == "" {
		maintenanceDB = "postgres"
	}
	return BuildPostgresDSN(host, port, user, password, maintenanceDB, sslMode, "")
}

// pgQuote wraps a PostgreSQL identifier in double quotes.
func pgQuote(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
