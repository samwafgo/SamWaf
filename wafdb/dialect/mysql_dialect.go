package dialect

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// MySQLDialect implements DBDialect for MySQL 8.0+ databases.
type MySQLDialect struct{}

func (d *MySQLDialect) Name() string         { return "mysql" }
func (d *MySQLDialect) IsFileBased() bool    { return false }
func (d *MySQLDialect) SupportsBackup() bool { return false }
func (d *MySQLDialect) SupportsRepair() bool { return false }

func (d *MySQLDialect) ForceIndexClause(table, idx string) string {
	return fmt.Sprintf("%s FORCE INDEX (%s)", table, idx)
}

// FormatLocalTime formats the column as-is: with loc=Local in the DSN the
// DATETIME column already holds the local wall clock, so any timezone
// conversion here would shift the value a second time.
func (d *MySQLDialect) FormatLocalTime(colExpr string) string {
	return fmt.Sprintf("DATE_FORMAT(%s,'%%Y-%%m-%%d %%H:%%i:%%s')", colExpr)
}

func (d *MySQLDialect) RenameTable(db *gorm.DB, src, dst string) error {
	return db.Exec(fmt.Sprintf("RENAME TABLE %s TO %s", mysqlQuote(src), mysqlQuote(dst))).Error
}

// ShardSwapTable archives liveTable to archiveTable and leaves an empty liveTable.
// It first creates an empty clone of the live table (structure + all indexes via
// CREATE TABLE ... LIKE), then atomically swaps the two names in a single
// RENAME TABLE statement so there is no window where the live table is missing
// (avoids losing concurrent log inserts).
func (d *MySQLDialect) ShardSwapTable(db *gorm.DB, liveTable, archiveTable string) error {
	tmpTable := liveTable + "_shardtmp"

	// Clean up any leftover temp table from a previously failed attempt.
	if err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", mysqlQuote(tmpTable))).Error; err != nil {
		return fmt.Errorf("mysql: 清理临时分表 %s 失败: %w", tmpTable, err)
	}
	// Create an empty clone with identical structure and indexes.
	if err := db.Exec(fmt.Sprintf("CREATE TABLE %s LIKE %s", mysqlQuote(tmpTable), mysqlQuote(liveTable))).Error; err != nil {
		return fmt.Errorf("mysql: 创建临时分表 %s 失败: %w", tmpTable, err)
	}
	// Atomic swap: live → archive, tmp → live (single statement).
	swapSQL := fmt.Sprintf("RENAME TABLE %s TO %s, %s TO %s",
		mysqlQuote(liveTable), mysqlQuote(archiveTable),
		mysqlQuote(tmpTable), mysqlQuote(liveTable))
	if err := db.Exec(swapSQL).Error; err != nil {
		// Best-effort cleanup so a retry can succeed.
		db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", mysqlQuote(tmpTable)))
		return fmt.Errorf("mysql: 原子换表失败 (%s→%s): %w", liveTable, archiveTable, err)
	}
	return nil
}

// TableSizeMB returns (DATA_LENGTH + INDEX_LENGTH) of the table in MB.
func (d *MySQLDialect) TableSizeMB(db *gorm.DB, table string) (int64, error) {
	var sizeMB int64
	err := db.Raw(
		"SELECT COALESCE((DATA_LENGTH + INDEX_LENGTH), 0) DIV (1024*1024) "+
			"FROM information_schema.TABLES "+
			"WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
		table,
	).Scan(&sizeMB).Error
	return sizeMB, err
}

func (d *MySQLDialect) ListTables(db *gorm.DB) ([]string, error) {
	var tables []string
	err := db.Raw(
		"SELECT TABLE_NAME FROM information_schema.TABLES " +
			"WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME",
	).Scan(&tables).Error
	return tables, err
}

func (d *MySQLDialect) TableExists(db *gorm.DB, name string) bool {
	var count int64
	db.Raw(
		"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?", name,
	).Scan(&count)
	return count > 0
}

func (d *MySQLDialect) ColumnInfo(db *gorm.DB, table string) ([]ColumnMeta, error) {
	rows, err := db.Raw(
		"SELECT ORDINAL_POSITION - 1, COLUMN_NAME, DATA_TYPE, "+
			"IF(IS_NULLABLE='NO',1,0), IFNULL(COLUMN_DEFAULT,''), IF(COLUMN_KEY='PRI',1,0) "+
			"FROM information_schema.COLUMNS "+
			"WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION",
		table,
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
			c.PrimaryKey = pk > 0
			cols = append(cols, c)
		}
	}
	return cols, nil
}

func (d *MySQLDialect) IndexInfo(db *gorm.DB, table string) ([]IndexMeta, error) {
	rows, err := db.Raw(
		"SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX - 1, COLUMN_NAME "+
			"FROM information_schema.STATISTICS "+
			"WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? "+
			"ORDER BY INDEX_NAME, SEQ_IN_INDEX",
		table,
	).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	idxMap := make(map[string]*IndexMeta)
	var order []string
	for rows.Next() {
		var idxName, colName string
		var nonUnique, seqNo int
		if err := rows.Scan(&idxName, &nonUnique, &seqNo, &colName); err != nil {
			continue
		}
		if _, ok := idxMap[idxName]; !ok {
			idxMap[idxName] = &IndexMeta{Name: idxName, Unique: nonUnique == 0}
			order = append(order, idxName)
		}
		idxMap[idxName].Columns = append(idxMap[idxName].Columns, IndexColumnMeta{SeqNo: seqNo, Name: colName})
	}

	result := make([]IndexMeta, 0, len(order))
	for _, name := range order {
		result = append(result, *idxMap[name])
	}
	return result, nil
}

func (d *MySQLDialect) CollectMetrics(db *gorm.DB, name, path string) (*DBMetrics, error) {
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

	db.Raw("SELECT @@VERSION").Scan(&m.EngineVersion)

	// Data and index size from information_schema
	row := db.Raw(
		"SELECT COALESCE(SUM(DATA_LENGTH),0)/1024/1024, COALESCE(SUM(INDEX_LENGTH),0)/1024/1024 " +
			"FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()",
	).Row()
	_ = row.Scan(&m.DataSizeMB, &m.IndexSizeMB)

	return m, nil
}

// BuildMySQLDSN returns a MySQL DSN string. Always includes parseTime=True and loc=Local
// so customtype.JsonTime deserialises correctly.
func BuildMySQLDSN(host string, port int, user, password, dbName, charset string) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local&timeout=10s&readTimeout=30s&writeTimeout=30s",
		user, password, host, port, dbName, charset,
	)
}

// BuildMySQLRootDSN returns a DSN that connects to the server without selecting a database,
// used for CREATE DATABASE IF NOT EXISTS.
func BuildMySQLRootDSN(host string, port int, user, password, charset string) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/?charset=%s&parseTime=True&loc=Local&timeout=10s&readTimeout=30s&writeTimeout=30s",
		user, password, host, port, charset,
	)
}

// mysqlQuote wraps a MySQL identifier in back-ticks.
func mysqlQuote(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}
