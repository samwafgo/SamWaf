package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/partition"
	"os"
	"time"
)

// 过期回收 = 丢整个分区（M3 E3）。
//
// 原来只有 SQLite 的归档文件会被删，MySQL/PG 的归档表**没人清**（注释里写的
// 「由其各自策略处理」并不存在），归档表会一直堆着。现在两边统一：
//
//   - SQLite：一个分区就是一个 .db 文件，整体删除。文件里装着三层，只能按**较长**的
//     那个保留期（日志保留天数）回收——要更快回收窄行，就把日志保留天数调短，
//     或者换到服务型数据库。
//   - MySQL/PG：一个分区是每层各一张表，可以**按层各走各的保留期**：
//     窄行 access_log_* 走访问日志保留天数（默认 30 天，通常更短），
//     安全事件 / 报文 / 存量 web_logs 走日志保留天数。某一层先过期就先丢那一层，
//     整个分区都没了才删掉分片记录。
//
// 实时库里的过期数据仍然按行删（DeleteHistory）：保留期可能短于一个周期，
// 这时候当前周期的分区里就有该删的行，丢分区帮不上。丢分区省掉的是**历史**那一大堆
// 逐行 DELETE + VACUUM。

// tierRetention 一层存储 + 它该用哪个保留期
type tierRetention struct {
	base string
	days int
}

// archiveTiers 归档分区里可能有的四层，以及各自的保留期来源
func archiveTiers() []tierRetention {
	logDays := int(global.GDATA_DELETE_INTERVAL)
	accessDays := int(global.GDATA_ACCESS_LOG_RETENTION_DAYS)
	if accessDays <= 0 {
		accessDays = logDays
	}
	return []tierRetention{
		{model.AccessLogTableName, accessDays},
		{model.SecurityEventTableName, logDays},
		{model.EventPayloadTableName, logDays},
		{wafdb.LogTableName, logDays},
	}
}

// shardEnd 给出一个分片里数据的结束时刻：优先用 share_dbs 记的 EndTime（真实数据边界），
// 缺失时回落到周期键算出来的周期终点。两个都没有就返回 false —— 认不出时间范围的分片宁可留着。
func shardEnd(shard model.ShareDb) (time.Time, bool) {
	if end := time.Time(shard.EndTime); !end.IsZero() && end.Unix() > 0 {
		return end, true
	}
	if key, ok := partition.KeyFromName(shard.FileName); ok {
		if _, end, err := partition.Range(key); err == nil {
			return end, true
		}
	}
	return time.Time{}, false
}

// expiredBy 数据结束时刻早于「现在 - 保留天数」即过期。days<=0 表示不按天清理。
func expiredBy(end time.Time, days int, now time.Time) bool {
	if days <= 0 {
		return false
	}
	return end.Before(now.AddDate(0, 0, -days))
}

// isLiveShardName / archiveSuffix 与「分区管理」用的是同一套判定（waf_service 里），
// 这里只是转调：回收与主动删除对「什么是实时库」「后缀怎么取」必须完全一致，
// 各写一份早晚会漂。
func isLiveShardName(name string) bool { return waf_service.IsLiveShardName(name) }

func archiveSuffix(name string) string { return waf_service.ArchiveSuffix(name) }

// CleanExpiredArchiveShard 回收过期的归档分区。
func CleanExpiredArchiveShard() {
	innerLogName := "CleanExpiredArchiveShard"
	now := time.Now()

	shards, err := waf_service.WafShareDbServiceApp.GetAllShareDbApi()
	if err != nil {
		zlog.Error(innerLogName, "获取分库列表失败", err)
		return
	}

	removed := 0
	for _, shard := range shards {
		if shard.DbLogicType != "" && shard.DbLogicType != "log" {
			continue
		}
		if isLiveShardName(shard.FileName) {
			continue
		}
		end, ok := shardEnd(shard)
		if !ok {
			zlog.Debug(innerLogName, "分片没有可判断的时间范围，跳过", "name", shard.FileName)
			continue
		}

		if dialect.Get().IsFileBased() {
			if !expiredBy(end, int(global.GDATA_DELETE_INTERVAL), now) {
				continue
			}
			if dropShardFile(innerLogName, shard) {
				removed++
			}
			continue
		}

		if dropShardTables(innerLogName, shard, end, now) {
			removed++
		}
	}

	// 孤儿分区：库里有分区表、share_dbs 里却没有对应记录（记录被手工删了、或切表时记录没写成）。
	// 只处理名字能算出周期键的，按周期终点判过期——认不出周期的一律不动。
	orphan := dropOrphanPartitions(innerLogName, shards, now)

	if removed > 0 || orphan > 0 {
		waf_service.InvalidateShardCounts()
		zlog.Info(innerLogName, "归档回收完成", "分片", removed, "孤儿分区表", orphan)
	}
}

// dropShardFile 删除 SQLite 分区文件（含 -wal / -shm）与分片记录
func dropShardFile(innerLogName string, shard model.ShareDb) bool {
	// 删除前先关掉可能已按需打开的连接，避免删正在被查询的文件
	wafdb.CloseManualLogDb(shard.FileName)

	dbPath := utils.GetCurrentDir() + "/data/" + shard.FileName
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			zlog.Warn(innerLogName, "删除归档文件失败", "file", p, "error", err.Error())
		}
	}
	if err := waf_service.WafShareDbServiceApp.DeleteById(shard.Id); err != nil {
		zlog.Warn(innerLogName, "删除归档记录失败", "file", shard.FileName, "error", err.Error())
		return false
	}
	zlog.Info(innerLogName, "已回收过期归档分区", "file", shard.FileName,
		"end_time", time.Time(shard.EndTime).Format("2006-01-02 15:04:05"))
	return true
}

// dropShardTables 丢掉 MySQL/PG 分区里已过期的那些层。
// 返回 true 表示这个分片已经整体没了、分片记录也删掉了。
func dropShardTables(innerLogName string, shard model.ShareDb, end, now time.Time) bool {
	suffix := archiveSuffix(shard.FileName)
	if suffix == "" {
		zlog.Debug(innerLogName, "认不出归档标识，跳过", "name", shard.FileName)
		return false
	}
	db := global.GWAF_LOCAL_LOG_DB
	if db == nil {
		return false
	}

	left := 0
	dropped := 0
	for _, tier := range archiveTiers() {
		part := tier.base + "_" + suffix
		if !dialect.Get().TableExists(db, part) {
			continue
		}
		if !expiredBy(end, tier.days, now) {
			left++
			continue
		}
		// DropPartition 自己会校验「分区必须属于该基表」，实时表传不进来
		if err := dialect.Get().DropPartition(db, tier.base, part); err != nil {
			zlog.Warn(innerLogName, "丢分区表失败", "table", part, "error", err.Error())
			left++
			continue
		}
		dropped++
		zlog.Info(innerLogName, "已丢过期分区表", "table", part, "保留天数", tier.days,
			"数据截止", end.Format("2006-01-02 15:04:05"))
	}

	if left > 0 || dropped == 0 {
		return false
	}
	if err := waf_service.WafShareDbServiceApp.DeleteById(shard.Id); err != nil {
		zlog.Warn(innerLogName, "删除归档记录失败", "name", shard.FileName, "error", err.Error())
		return false
	}
	return true
}

// dropOrphanPartitions 丢掉没有分片记录、且周期已过期的分区表。
// 保守起见只动「名字能算出周期键」的表：认不出周期的可能是用户自己建的表。
func dropOrphanPartitions(innerLogName string, shards []model.ShareDb, now time.Time) int {
	if dialect.Get().IsFileBased() || global.GWAF_LOCAL_LOG_DB == nil {
		return 0
	}
	known := make(map[string]struct{}, len(shards)*4)
	for _, s := range shards {
		if suffix := archiveSuffix(s.FileName); suffix != "" {
			for _, tier := range archiveTiers() {
				known[tier.base+"_"+suffix] = struct{}{}
			}
		}
	}

	dropped := 0
	for _, tier := range archiveTiers() {
		parts, err := dialect.Get().ListPartitions(global.GWAF_LOCAL_LOG_DB, tier.base)
		if err != nil {
			zlog.Warn(innerLogName, "列分区失败", "base", tier.base, "error", err.Error())
			continue
		}
		for _, part := range parts {
			if _, ok := known[part]; ok {
				continue
			}
			key, ok := partition.KeyFromName(part)
			if !ok {
				continue // 认不出周期：不是我们切的，别动
			}
			if !partition.Expired(key, tier.days, now) {
				continue
			}
			if err := dialect.Get().DropPartition(global.GWAF_LOCAL_LOG_DB, tier.base, part); err != nil {
				zlog.Warn(innerLogName, "丢孤儿分区表失败", "table", part, "error", err.Error())
				continue
			}
			dropped++
			zlog.Info(innerLogName, "已丢无记录的过期分区表", "table", part, "周期", key, "保留天数", tier.days)
		}
	}
	return dropped
}
