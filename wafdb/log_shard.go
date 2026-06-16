package wafdb

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/wafdb/dialect"

	"gorm.io/gorm"
)

// LogTableName is the live web access log table name (model innerbean.WebLog).
const LogTableName = "web_logs"

// LiveLogName returns the ShareDb.FileName that identifies the current/live log
// store for the active driver: SQLite → "local_log.db", others (MySQL) → "web_logs".
// Used to mark the default selection in the front-end archive dropdown.
func LiveLogName() string {
	if dialect.Get().IsFileBased() {
		return enums.DB_LOG // "local_log.db"
	}
	return LogTableName // "web_logs"
}

// ResolveLogDB returns the *gorm.DB connection and table name to query for the
// given log shard identifier (ShareDb.FileName, passed from the front-end as
// current_db_name).
//
//   - empty / live identifier  → live log DB + "web_logs"
//   - SQLite historical shard  → on-demand opened shard .db file + "web_logs"
//   - MySQL  historical shard  → same log DB connection + shard table name
//
// It never returns a nil *gorm.DB: if a SQLite shard cannot be opened it falls
// back to the live connection, guarding against the nil-map dereference panic
// that the previous inline read paths were exposed to under MySQL.
func ResolveLogDB(currentDbName string) (*gorm.DB, string) {
	// Treat as "live" (current log store): the empty value, the legacy default
	// "local_log.db" (still sent by the front-end as its default selection under
	// any driver), and the MySQL live table name "web_logs".
	if len(currentDbName) == 0 || currentDbName == enums.DB_LOG || currentDbName == LogTableName {
		return global.GWAF_LOCAL_LOG_DB, LogTableName
	}

	// Historical shard.
	if dialect.Get().IsFileBased() {
		// SQLite: open the archived .db file on demand and query its web_logs table.
		InitManaulLogDb("", currentDbName)
		if db := global.GDATA_CURRENT_LOG_DB_MAP[currentDbName]; db != nil {
			return db, LogTableName
		}
		// Shard file unavailable — degrade to live DB instead of panicking.
		return global.GWAF_LOCAL_LOG_DB, LogTableName
	}

	// MySQL: the archived shard is a table (web_logs_<ts>) in the same database.
	// Guard against a non-existent table name (e.g. stale share_dbs rows that
	// stored the database name instead of a table name) by falling back to live.
	if dialect.Get().TableExists(global.GWAF_LOCAL_LOG_DB, currentDbName) {
		return global.GWAF_LOCAL_LOG_DB, currentDbName
	}
	return global.GWAF_LOCAL_LOG_DB, LogTableName
}
