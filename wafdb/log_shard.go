package wafdb

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

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

// ensureLiveShardRecord 确保 share_dbs 里有一条实时分片记录（file_name = liveName），没有才补。
// 按这一行在不在判断，不看表里总数：已有历史分片时总数不为 0，实时记录缺了也永远补不回来。
func ensureLiveShardRecord(coreDB, logDB *gorm.DB, liveName string) {
	var liveCount int64
	if err := coreDB.Model(&model.ShareDb{}).Where("file_name = ?", liveName).Count(&liveCount).Error; err != nil {
		zlog.Error("查询实时分片记录失败", "file_name", liveName, "error", err.Error())
		return
	}
	if liveCount > 0 {
		return
	}
	var logTotal int64
	logDB.Model(&innerbean.WebLog{}).Count(&logTotal)
	now := customtype.JsonTime(time.Now())
	coreDB.Create(&model.ShareDb{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: now,
			UPDATE_TIME: now,
		},
		DbLogicType: "log",
		StartTime:   now,
		EndTime:     now,
		FileName:    liveName,
		Cnt:         logTotal,
	})
}

// ErrShardMissing 归档分区的存储已不在：SQLite 文件不存在，或 MySQL/PG 下该分区的表一张都没有。
var ErrShardMissing = errors.New("归档分区的存储已不存在")

// archiveFileRe SQLite 归档文件名：local_log_<周期或时间戳>[_序号].db，只允许纯文件名
var archiveFileRe = regexp.MustCompile(`^local_log_[0-9]+(_[0-9]+)?\.db$`)

// isLiveIdent 实时库的几种标识：空值、SQLite 库名、两张实时表名
func isLiveIdent(name string) bool {
	return name == "" || name == enums.DB_LOG || name == LogTableName || name == model.AccessLogTableName
}

// ShardFilePath SQLite 归档文件的完整路径；名字不是合法的归档文件名时返回错误。
func ShardFilePath(name string) (string, error) {
	if !archiveFileRe.MatchString(name) {
		return "", fmt.Errorf("不是合法的归档文件名: %q", name)
	}
	return utils.GetCurrentDir() + "/data/" + name, nil
}

// ShardFileMissing SQLite 归档文件是否已不在（只看文件，不打开）。名字不合法也按缺失算。
func ShardFileMissing(name string) bool {
	path, err := ShardFilePath(name)
	if err != nil {
		return true
	}
	_, err = os.Stat(path)
	return os.IsNotExist(err)
}

// ResolveLogDB 返回某个分片标识对应的连接与表名。
//
//   - 空值 / 实时标识 → 实时库 + web_logs
//   - SQLite 归档文件 → 按需只读打开该文件 + web_logs
//   - MySQL/PG 归档表 → 实时库连接 + 该表名
//
// 打不开（文件不在、表不在、名字不合法）时返回错误，不回落实时库：
// 回落会把实时数据当成这个分区的内容显示出来。
func ResolveLogDB(currentDbName string) (*gorm.DB, string, error) {
	if isLiveIdent(currentDbName) {
		return global.GWAF_LOCAL_LOG_DB, LogTableName, nil
	}
	if dialect.Get().IsFileBased() {
		if err := InitManaulLogDb("", currentDbName); err != nil {
			return nil, "", err
		}
		if db := getShardDB(currentDbName); db != nil {
			return db, LogTableName, nil
		}
		return nil, "", fmt.Errorf("归档分片 %s 连接不可用", currentDbName)
	}
	if dialect.Get().TableExists(global.GWAF_LOCAL_LOG_DB, currentDbName) {
		return global.GWAF_LOCAL_LOG_DB, currentDbName, nil
	}
	return nil, "", fmt.Errorf("%w: %s", ErrShardMissing, currentDbName)
}

// TierTables 一个分片上各层实际要读的表名；空字符串 = 这个分片没有那一层。
type TierTables struct {
	DB      *gorm.DB
	Access  string // access_log / access_log_<ts>
	Event   string // security_event / security_event_<ts>
	Payload string // event_payload / event_payload_<ts>
	WebLog  string // web_logs / web_logs_<ts>（分层改造之前的分片才有值）
	Empty   bool   // 归档里一行数据都没有
	Err     error  // 分片打不开；errors.Is(Err, ErrShardMissing) 表示存储已不在
}

// shardTierNames 选层结果，按分片缓存。归档只读，内容不再变；
// 分区被删或按层过期时由 InvalidateShardTierCache / forgetShardTiers 作废。
type shardTierNames struct {
	Access, Event, Payload, WebLog string
	Empty                          bool
}

var shardTierCache sync.Map

func forgetShardTiers(name string) { shardTierCache.Delete(name) }

// InvalidateShardTierCache 分区构成变化后清空选层与索引缓存。
func InvalidateShardTierCache() {
	shardTierCache.Range(func(k, _ any) bool { shardTierCache.Delete(k); return true })
	shardIndexCache.Range(func(k, _ any) bool { shardIndexCache.Delete(k); return true })
}

// tableHasRows 表存在且至少有一行（当前租户可见的）。
func tableHasRows(db *gorm.DB, table string) bool {
	if !dialect.Get().TableExists(db, table) {
		return false
	}
	var one []int
	res := db.Table(table).Select("1 AS x").Limit(1).Find(&one)
	return res.Error == nil && res.RowsAffected > 0
}

// classifyShardTiers 按数据判断分片属于哪个年代，而不是按表在不在：
// 分层改造边界切出来的分片（以及被旧版打开过、跑过迁移的归档）同时有 web_logs 与空的新表，
// 按存在性选会读到空的新表。新表里有行才按新表读，否则读 web_logs。
func classifyShardTiers(db *gorm.DB, shard, access, event, payload, weblog string) shardTierNames {
	exists := func(t string) string {
		if dialect.Get().TableExists(db, t) {
			return t
		}
		return ""
	}
	var r shardTierNames
	if tableHasRows(db, access) || tableHasRows(db, event) {
		r.Access, r.Event, r.Payload = exists(access), exists(event), exists(payload)
		if tableHasRows(db, weblog) {
			zlog.Warn("归档分片同时有分层数据与 web_logs 存量行，按分层读取", "shard", shard)
		}
		return r
	}
	r.WebLog = exists(weblog)
	if tableHasRows(db, payload) {
		r.Payload = payload
	}
	r.Empty = r.WebLog == "" || !tableHasRows(db, weblog)
	return r
}

// ResolveTierTables 把分片标识（ShareDb.FileName，前端 current_db_name）解析成各层表名。
//
//   - 空 / local_log.db / web_logs / access_log → 实时库
//   - SQLite 归档文件名（local_log_<ts>.db）→ 只读打开整个文件，表名不带后缀
//   - MySQL/PG 归档表名：改造前是 web_logs_<ts>，改造后是 access_log_<ts>，按后缀推同分片其余表
//
// MySQL/PG 下分片自带的报文表没有时回落实时 event_payload：换表失败时报文留在那里，按 req_uuid 仍找得到。
func ResolveTierTables(currentDbName string) TierTables {
	if isLiveIdent(currentDbName) {
		return TierTables{
			DB:      global.GWAF_LOCAL_LOG_DB,
			Access:  model.AccessLogTableName,
			Event:   model.SecurityEventTableName,
			Payload: model.EventPayloadTableName,
			WebLog:  LogTableName, // 详情按识别码点查时兜底读改造前的存量行
		}
	}

	var db *gorm.DB
	suffix := ""
	if dialect.Get().IsFileBased() {
		d, _, err := ResolveLogDB(currentDbName)
		if err != nil {
			return TierTables{Err: err}
		}
		db = d
	} else {
		switch {
		case strings.HasPrefix(currentDbName, LogTableName+"_"):
			suffix = strings.TrimPrefix(currentDbName, LogTableName)
		case strings.HasPrefix(currentDbName, model.AccessLogTableName+"_"):
			suffix = strings.TrimPrefix(currentDbName, model.AccessLogTableName)
		default:
			return TierTables{Err: fmt.Errorf("认不出的归档分区标识: %q", currentDbName)}
		}
		db = global.GWAF_LOCAL_LOG_DB
		if db == nil {
			return TierTables{Err: errors.New("日志库未就绪")}
		}
	}

	var names shardTierNames
	if v, ok := shardTierCache.Load(currentDbName); ok {
		names = v.(shardTierNames)
	} else {
		names = classifyShardTiers(db, currentDbName,
			model.AccessLogTableName+suffix, model.SecurityEventTableName+suffix,
			model.EventPayloadTableName+suffix, LogTableName+suffix)
		if suffix != "" {
			if names.Access == "" && names.Event == "" && names.WebLog == "" && names.Payload == "" {
				return TierTables{Err: fmt.Errorf("%w: %s", ErrShardMissing, currentDbName)}
			}
			if names.Payload == "" && dialect.Get().TableExists(db, model.EventPayloadTableName) {
				names.Payload = model.EventPayloadTableName
			}
		}
		shardTierCache.Store(currentDbName, names)
	}
	return TierTables{DB: db, Access: names.Access, Event: names.Event, Payload: names.Payload,
		WebLog: names.WebLog, Empty: names.Empty}
}

// ResolveLogTables 给报文补全用：返回分片连接、主日志表与报文表。打不开时连接为 nil。
func ResolveLogTables(currentDbName string) (*gorm.DB, string, string) {
	t := ResolveTierTables(currentDbName)
	if t.Err != nil || t.DB == nil {
		return nil, "", ""
	}
	logTable := t.WebLog
	if logTable == "" {
		logTable = t.Access
	}
	return t.DB, logTable, t.Payload
}

// shardIndexCache 分片上某个索引在不在，按 分片|表|索引 缓存
var shardIndexCache sync.Map

// ShardHasIndex 分片上有没有这个索引。强制索引前必须先问：历史文件不再跑迁移，
// 更早切出来的分片可能没有后来才加的索引，强制一个不存在的索引整条 SQL 会报错。
func ShardHasIndex(db *gorm.DB, shard, table, index string) bool {
	if db == nil {
		return false
	}
	if isLiveIdent(shard) {
		shard = "live"
	}
	key := shard + "|" + table + "|" + index
	if v, ok := shardIndexCache.Load(key); ok {
		return v.(bool)
	}
	has := db.Migrator().HasIndex(table, index)
	shardIndexCache.Store(key, has)
	return has
}
