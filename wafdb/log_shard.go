package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"strings"
	"sync"

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
		if err := InitManaulLogDb("", currentDbName); err != nil {
			zlog.Warn("归档分片不可用，降级查实时库", "file", currentDbName, "error", err.Error())
			return global.GWAF_LOCAL_LOG_DB, LogTableName
		}
		if db := getShardDB(currentDbName); db != nil {
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

// payloadTableSeen 记住哪些分片确认有报文表。只缓存"有"这一侧：
// 归档分片一旦有就永远有，而"没有"可能只是升级迁移还没跑到，缓存下来会一直读不到报文。
var payloadTableSeen sync.Map

// ResolveLogTables 在 ResolveLogDB 的基础上再给出该分片的报文表名。
//
// 报文表与日志表同进同出：
//   - SQLite 按文件分片，归档文件里自带 event_payload
//   - MySQL / PostgreSQL 按表分片，web_logs_<ts> 对应 event_payload_<ts>
//
// 返回空表名表示这个分片没有报文表——本次改造之前切出去的归档都是这样，
// 它们的报文还在 web_logs 自己的列里，读侧照旧读原列即可。
func ResolveLogTables(currentDbName string) (*gorm.DB, string, string) {
	db, logTable := ResolveLogDB(currentDbName)
	if db == nil {
		return db, logTable, ""
	}

	// SQLite 的归档分片是整个文件，连上去之后表名仍是 web_logs / event_payload
	if logTable == LogTableName {
		return db, logTable, probePayloadTable(db, currentDbName, model.EventPayloadTableName)
	}

	// MySQL / PostgreSQL：web_logs_<ts> 对应 event_payload_<ts>
	shardPayload := model.EventPayloadTableName + strings.TrimPrefix(logTable, LogTableName)
	if t := probePayloadTable(db, currentDbName, shardPayload); t != "" {
		return db, logTable, t
	}
	// 分表时报文表没能一起换过去（换表失败或这批日志早于本次改造）：
	// 报文按 req_uuid 寻址，留在实时表里照样找得到，退回去查它。
	return db, logTable, probePayloadTable(db, currentDbName, model.EventPayloadTableName)
}

// probePayloadTable 探一次表存不存在，存在则返回表名。
// 只缓存"存在"这一侧：归档分片一旦有就永远有，而"没有"可能只是升级迁移还没跑到，
// 缓存下来会一直读不到报文。
func probePayloadTable(db *gorm.DB, shard, table string) string {
	key := shard + "|" + table
	if _, ok := payloadTableSeen.Load(key); ok {
		return table
	}
	if !dialect.Get().TableExists(db, table) {
		return ""
	}
	payloadTableSeen.Store(key, struct{}{})
	return table
}
