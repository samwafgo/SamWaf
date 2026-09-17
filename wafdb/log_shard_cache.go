package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"sync"
	"time"

	"gorm.io/gorm"
)

// 归档分片连接缓存。
//
// 这些连接原本直接读写 global.GDATA_CURRENT_LOG_DB_MAP 这张裸 map：并发查两个不同分片
// 会命中 Go 的并发读写检测直接崩进程，且句柄一旦打开就永不释放。这里统一收口，
// 加锁之外再给两条上限：最多同时握 shardCacheMax 个连接，空闲超过 shardIdleTTL 的关掉。
const (
	shardCacheMax = 8
	shardIdleTTL  = 30 * time.Minute
)

var (
	shardMu      sync.Mutex
	shardLastUse = map[string]time.Time{}
)

// getShardDB 取一个已打开的分片连接并刷新它的使用时间；没有则返回 nil。
func getShardDB(name string) *gorm.DB {
	shardMu.Lock()
	defer shardMu.Unlock()
	if global.GDATA_CURRENT_LOG_DB_MAP == nil {
		return nil
	}
	db := global.GDATA_CURRENT_LOG_DB_MAP[name]
	if db != nil {
		shardLastUse[name] = time.Now()
	}
	return db
}

// putShardDB 登记一个新打开的连接。若同名连接已被别的协程抢先放入，
// 返回那一个并让调用方关掉自己开的，避免同一个文件握两份句柄。
func putShardDB(name string, db *gorm.DB) (kept *gorm.DB, duplicated bool) {
	shardMu.Lock()
	defer shardMu.Unlock()
	if global.GDATA_CURRENT_LOG_DB_MAP == nil {
		global.GDATA_CURRENT_LOG_DB_MAP = map[string]*gorm.DB{}
	}
	if exist := global.GDATA_CURRENT_LOG_DB_MAP[name]; exist != nil {
		shardLastUse[name] = time.Now()
		return exist, true
	}
	global.GDATA_CURRENT_LOG_DB_MAP[name] = db
	shardLastUse[name] = time.Now()
	evictLocked()
	return db, false
}

// closeShardDB 关闭并移除一个分片连接。归档清理删文件前必须先调用，
// 否则 Windows 下文件被占用删不掉。
func closeShardDB(name string) {
	shardMu.Lock()
	db := global.GDATA_CURRENT_LOG_DB_MAP[name]
	delete(global.GDATA_CURRENT_LOG_DB_MAP, name)
	delete(shardLastUse, name)
	shardMu.Unlock()

	closeShardConn(name, db)
}

// snapshotShardDBs 返回当前连接的快照，供监控之类只读遍历使用，
// 免得调用方直接遍历 map 时撞上并发写。
func snapshotShardDBs() map[string]*gorm.DB {
	shardMu.Lock()
	defer shardMu.Unlock()
	out := make(map[string]*gorm.DB, len(global.GDATA_CURRENT_LOG_DB_MAP))
	for k, v := range global.GDATA_CURRENT_LOG_DB_MAP {
		out[k] = v
	}
	return out
}

// evictLocked 在持锁状态下淘汰：先按空闲时间清，再按数量清最久未用的。
// 实际关闭放到锁外做，关连接可能阻塞。
func evictLocked() {
	var victims []string
	now := time.Now()
	for name, last := range shardLastUse {
		if now.Sub(last) > shardIdleTTL {
			victims = append(victims, name)
		}
	}
	for _, name := range victims {
		db := global.GDATA_CURRENT_LOG_DB_MAP[name]
		delete(global.GDATA_CURRENT_LOG_DB_MAP, name)
		delete(shardLastUse, name)
		go closeShardConn(name, db)
	}

	for len(global.GDATA_CURRENT_LOG_DB_MAP) > shardCacheMax {
		oldest := ""
		var oldestAt time.Time
		for name, last := range shardLastUse {
			if oldest == "" || last.Before(oldestAt) {
				oldest, oldestAt = name, last
			}
		}
		if oldest == "" {
			return
		}
		db := global.GDATA_CURRENT_LOG_DB_MAP[oldest]
		delete(global.GDATA_CURRENT_LOG_DB_MAP, oldest)
		delete(shardLastUse, oldest)
		go closeShardConn(oldest, db)
	}
}

func closeShardConn(name string, db *gorm.DB) {
	if db == nil {
		return
	}
	sqlDB, err := db.DB()
	if err != nil {
		return
	}
	if cerr := sqlDB.Close(); cerr != nil {
		zlog.Warn("关闭归档分片连接失败", "file", name, "error", cerr.Error())
		return
	}
	zlog.Debug("已释放归档分片连接", "file", name)
}
