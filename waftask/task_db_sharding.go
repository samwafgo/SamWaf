package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/partition"
	"fmt"
	"os"
	"time"
)

// livePeriodKey 返回实时库里最早一条日志所属的周期键。
//
// 「实时库现在装的是哪个周期」这件事不另存状态，直接问数据本身：
// 最早一条落在上一个周期，就说明周期边界已经过了、该切了。这样重启、停机几天、
// 手工删表都不会让状态和事实脱节（存一个全局变量反而要处理这些不一致）。
// 表不存在或没有数据时返回 false —— 没数据就没什么可切的。
func livePeriodKey() (string, bool) {
	db := global.GWAF_LOCAL_LOG_DB
	if db == nil {
		return "", false
	}
	table := model.AccessLogTableName
	if !dialect.Get().TableExists(db, table) {
		table = "web_logs"
		if !dialect.Get().TableExists(db, table) {
			return "", false
		}
	}
	var oldest *int64
	if err := db.Table(table).Select("MIN(unix_add_time)").Scan(&oldest).Error; err != nil {
		zlog.Debug("TaskDBSharding", "取最早日志时间失败", err.Error())
		return "", false
	}
	if oldest == nil || *oldest <= 0 {
		return "", false
	}
	// UNIX_ADD_TIME 是毫秒
	return partition.KeyOf(time.UnixMilli(*oldest)), true
}

// nextPeriodSeq 返回某个周期下一个可用的序号：正常是 1（一个周期一个分区），
// 已经有同周期分区时才往上加——那是「同周期内体积超限被迫再切」的异常兜底。
func nextPeriodSeq(periodKey string) int {
	if global.GWAF_LOCAL_DB == nil {
		return 1
	}
	var cnt int64
	if err := global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).
		Where("db_logic_type = ? and period_key = ?", "log", periodKey).Count(&cnt).Error; err != nil {
		zlog.Debug("TaskDBSharding", "统计同周期分区数失败", err.Error())
		return 1
	}
	return int(cnt) + 1
}

// 检测库是否切换。
//
// 切分口径（M3 E2）：**按时间周期切**，一个月一个分区。
// 行数与体积超限降级为异常兜底——同一个周期内真被写爆了才提前切，分区名带序号
// （access_log_202609_02）。这样「一段时间落在哪些分区上」是算出来的而不是猜的，
// 过期也变成丢整个分区（见 CleanExpiredArchiveShard）。
func TaskShareDbInfo() {
	innerLogName := "TaskDBSharding"
	zlog.Debug(innerLogName, "检测是否需要进行分库")

	if global.GDATA_CURRENT_CHANGE {
		//如果正在切换库 跳过
		zlog.Debug(innerLogName, "切库状态")
		return
	}

	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil {
		zlog.Debug(innerLogName, "数据库没有初始化完成呢")
		return
	}

	// 启动时已同步做过一次（CutTierBoundaryIfNeeded），这里是兜底
	if CutTierBoundaryIfNeeded() {
		return
	}

	// 周期边界优先：实时库里最早一条日志落在上一个周期，就把这一段整体切成那个周期的分区。
	// 放在体积判断之前——常态就该按周期切，体积只是兜底。
	curKey := partition.KeyOf(time.Now())
	if oldKey, ok := livePeriodKey(); ok && oldKey != curKey {
		doLogShardCut(innerLogName, fmt.Sprintf("跨周期切分（%s → %s）", oldKey, curKey), false, oldKey)
		return
	}

	//获取当前日志数量（分层的写入主体是 access_log；老表不再写入，只作兜底）
	var total int64 = 0
	if dialect.Get().TableExists(global.GWAF_LOCAL_LOG_DB, model.AccessLogTableName) {
		global.GWAF_LOCAL_LOG_DB.Table(dialect.Get().ForceIndexClause(model.AccessLogTableName, "idx_al_time")).Count(&total)
	} else {
		global.GWAF_LOCAL_LOG_DB.Table(dialect.Get().ForceIndexClause("web_logs", "idx_tenant_usercode_web_logs")).Count(&total)
	}

	//获取当前数据库文件大小
	currentDir := utils.GetCurrentDir()
	oldDBFilename := "local_log.db"
	dbFilePath := currentDir + "/data/" + oldDBFilename

	needSharding := false
	var shardingReason string

	// 检查记录数量是否超过限制
	if total > global.GDATA_SHARE_DB_SIZE {
		needSharding = true
		shardingReason = fmt.Sprintf("记录数量(%d)超过限制(%d)", total, global.GDATA_SHARE_DB_SIZE)
	}

	// 检查大小是否超过限制：SQLite 用 .db 文件大小，MySQL/PG 用 access_log 表(数据+索引)大小
	if dialect.Get().IsFileBased() {
		fileInfo, err := os.Stat(dbFilePath)
		if err == nil {
			totalBytes := fileInfo.Size()
			// 把 -wal 大小一并计入：WAL 模式下数据可能暂存在 wal 文件，主库文件显小会导致漏判
			if walInfo, werr := os.Stat(dbFilePath + "-wal"); werr == nil {
				totalBytes += walInfo.Size()
			}
			fileSizeMB := totalBytes / (1024 * 1024) // 转换为MB
			if fileSizeMB > global.GDATA_SHARE_DB_FILE_SIZE {
				needSharding = true
				shardingReason = fmt.Sprintf("文件大小(%dMB,含WAL)超过限制(%dMB)", fileSizeMB, global.GDATA_SHARE_DB_FILE_SIZE)
			}
		} else {
			zlog.Error(innerLogName, "获取数据库文件大小失败:", err)
		}
	} else {
		sizeTable := model.AccessLogTableName
		if !dialect.Get().TableExists(global.GWAF_LOCAL_LOG_DB, sizeTable) {
			sizeTable = "web_logs"
		}
		tableSizeMB, err := dialect.Get().TableSizeMB(global.GWAF_LOCAL_LOG_DB, sizeTable)
		if err == nil {
			if tableSizeMB > global.GDATA_SHARE_DB_FILE_SIZE {
				needSharding = true
				shardingReason = fmt.Sprintf("表大小(%dMB)超过限制(%dMB)", tableSizeMB, global.GDATA_SHARE_DB_FILE_SIZE)
			}
		} else {
			zlog.Error(innerLogName, "获取"+sizeTable+"表大小失败:", err)
		}
	}

	if needSharding {
		// 同周期内被写爆了：仍然按当前周期命名，序号从 02 起，读侧与过期判断照样认得出周期
		doLogShardCut(innerLogName, shardingReason+"（同周期内兜底切分）", false, curKey)
	}
}

// CutTierBoundaryIfNeeded 分层改造的一次性边界：升级后 web_logs 里还躺着改造前的数据，而写入已切到
// access_log / security_event / event_payload。先把它整体切成一个归档分片，新表从空开始——
// 此后「实时」与「归档」各归各位，旧数据照旧能在归档下拉里读（D6）。
//
// 必须在开始接流量之前调用：判定条件是 access_log 为空，一旦有新请求写进来就不再成立，
// 存量数据会一直留在实时库的 web_logs 里，而实时视图只读新表。
// 无标记可记：web_logs 不再写入，access_log 一旦有行就说明边界已经切过，天然幂等。
// 返回 true 表示本次做了切分。
func CutTierBoundaryIfNeeded() bool {
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil {
		return false
	}
	if !dialect.Get().TableExists(global.GWAF_LOCAL_LOG_DB, model.AccessLogTableName) {
		return false
	}
	var legacyCnt, accessCnt int64
	global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&legacyCnt)
	global.GWAF_LOCAL_LOG_DB.Model(&model.AccessLog{}).Count(&accessCnt)
	if legacyCnt == 0 || accessCnt > 0 {
		return false
	}
	// 存量 web_logs 里的数据跨很多个月，给它安一个周期键是假的，沿用时间戳命名
	doLogShardCut("TaskDBSharding", fmt.Sprintf("分层改造边界切换（存量 %d 行转入归档）", legacyCnt), true, "")
	return true
}

// doLogShardCut 执行一次日志库切分。swapWebLog=true 只用于分层改造的一次性边界切换
// （把存量 web_logs + event_payload 切出去）；常规切分换的是三层新表，
// web_logs 不再写入也就无需再换。
//
// periodKey 非空则按周期命名（local_log_202609.db / access_log_202609，同周期第二个起带 _02 序号），
// 为空则沿用 14 位时间戳命名——只有分层改造的边界切换会走后者，那批存量数据跨很多个月，
// 安一个周期键是假的。
//
// 归档标识：SQLite 为新文件名(.db)，MySQL/PG 为归档表名（边界切换是 web_logs_<ts>，
// 常规切分是 access_log_<周期或时间戳>；读侧 ResolveTierTables 按前缀两种都认）。
// 注意：MySQL/PG 的归档表不再被 gormigrate 跟踪，今后给这些表加列时读旧分片可能缺列——
// 读侧已按分片实际列取交集（webLogSelect），无需同步 ALTER。
func doLogShardCut(innerLogName, reason string, swapWebLog bool, periodKey string) {
	global.GDATA_CURRENT_CHANGE = true
	defer func() { global.GDATA_CURRENT_CHANGE = false }()
	zlog.Info(innerLogName, "开始分库，原因:", reason)

	ts := time.Now().Format("20060102150405")

	cutTable := model.AccessLogTableName
	if swapWebLog {
		cutTable = "web_logs"
	}
	var total int64
	if swapWebLog {
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&total)
	} else {
		global.GWAF_LOCAL_LOG_DB.Model(&model.AccessLog{}).Count(&total)
	}

	// 分区命名：有周期键按周期来，同周期第二个起带序号；没有则沿用时间戳
	suffix := ts
	seq := 1
	if periodKey != "" {
		seq = nextPeriodSeq(periodKey)
		suffix = periodKey
		if seq > 1 {
			suffix = fmt.Sprintf("%s_%02d", periodKey, seq)
		}
	}
	newDBFilename := fmt.Sprintf("local_log_%v.db", suffix)
	archiveName := newDBFilename
	if !dialect.Get().IsFileBased() {
		if swapWebLog {
			archiveName = "web_logs_" + suffix
		} else {
			archiveName = model.AccessLogTableName + "_" + suffix
		}
	}

	// 起止时间用**这批数据自己的**最早/最晚时间，而不是「上一个分片的结束时间 → 现在」。
	// 过期回收按 EndTime 判（见 CleanExpiredArchiveShard），拿真实边界才不会把还在保留期内的
	// 数据算成过期；停机几天再启动、或同周期内兜底切分时，这个差别很要紧。
	startTime := customtype.JsonTime(time.Now())
	endTime := customtype.JsonTime(time.Now())
	if lo, hi, ok := cutDataRange(cutTable); ok {
		startTime, endTime = customtype.JsonTime(lo), customtype.JsonTime(hi)
	} else {
		var lastedDb model.ShareDb
		if err := global.GWAF_LOCAL_DB.Limit(1).Order("create_time desc").Find(&lastedDb).Error; err == nil {
			startTime = lastedDb.EndTime
		}
	}
	sharDbBean := model.ShareDb{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		DbLogicType: "log",
		StartTime:   startTime,
		EndTime:     endTime,
		FileName:    archiveName,
		Cnt:         total,
		PeriodKey:   periodKey,
	}

	zlog.Info(innerLogName, "正在切库中...")
	if dialect.Get().IsFileBased() {
		// SQLite：关闭连接 → 重命名三个 WAL 文件 → 重建 LogDb
		currentDir := utils.GetCurrentDir()
		oldPath := currentDir + "/data/local_log.db"
		newPath := currentDir + "/data/" + newDBFilename

		sqlDB, err := global.GWAF_LOCAL_LOG_DB.DB()
		if err != nil {
			zlog.Error(innerLogName, "切换关闭时候错误", err)
		} else {
			if err := sqlDB.Close(); err != nil {
				zlog.Error(innerLogName, "切换关闭时候错误", err)
			}
		}
		// 等待连接彻底关闭（Count 报错即连接已关闭，可安全重命名文件）。
		// 加最大重试上限，避免连接异常未报错时无限循环卡住切库（高频切库后该段执行更频繁）。
		var testTotal int64
		for attempt := 0; attempt < 10; attempt++ {
			testError := global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&testTotal).Error
			if testError != nil {
				zlog.Debug(innerLogName, "连接已关闭，可切库", testError)
				break
			}
			if attempt == 9 {
				zlog.Warn(innerLogName, "等待日志库连接关闭超时，强制继续切库")
				break
			}
			time.Sleep(1 * time.Second)
		}

		if err := os.Rename(oldPath, newPath); err != nil {
			zlog.Error(innerLogName, "Error renaming database file:", err)
		}
		if err := os.Rename(oldPath+"-shm", newPath+"-shm"); err != nil {
			zlog.Error(innerLogName, "Error renaming .db-shm file:", err)
		}
		if err := os.Rename(oldPath+"-wal", newPath+"-wal"); err != nil {
			zlog.Error(innerLogName, "Error renaming .db-wal file:", err)
		}
		global.GWAF_LOCAL_DB.Create(sharDbBean)
		global.GWAF_LOCAL_LOG_DB = nil
		wafdb.InitLogDb("")
	} else {
		// MySQL/PG：CREATE TABLE LIKE + 单语句原子 RENAME 换表，换表期间无写入空窗。
		// 任一张换失败不回滚：报文按 req_uuid 寻址、窄行按时间查，留在实时表里读侧照样找得到。
		swap := func(table string) {
			if !dialect.Get().TableExists(global.GWAF_LOCAL_LOG_DB, table) {
				return
			}
			if err := dialect.Get().ShardSwapTable(global.GWAF_LOCAL_LOG_DB, table, table+"_"+ts); err != nil {
				zlog.Warn(innerLogName, "分表失败，数据留在实时表:", "table", table, "error", err)
			}
		}
		if swapWebLog {
			swap("web_logs")
			swap(model.EventPayloadTableName)
		} else {
			swap(model.AccessLogTableName)
			swap(model.SecurityEventTableName)
			swap(model.EventPayloadTableName)
		}
		global.GWAF_LOCAL_DB.Create(sharDbBean)
		zlog.Info(innerLogName, "分表完成，归档表:", archiveName)
	}
	// 分区构成变了，归档计数缓存跟着作废
	waf_service.InvalidateShardCounts()
	zlog.Info(innerLogName, "切库完成...")
}

// cutDataRange 返回待切表里数据的真实时间边界 [最早, 最晚]。
// 表空或查不到返回 false，调用方回落到旧口径。
func cutDataRange(table string) (time.Time, time.Time, bool) {
	db := global.GWAF_LOCAL_LOG_DB
	if db == nil || !dialect.Get().TableExists(db, table) {
		return time.Time{}, time.Time{}, false
	}
	var row struct {
		Lo *int64
		Hi *int64
	}
	if err := db.Table(table).Select("MIN(unix_add_time) as lo, MAX(unix_add_time) as hi").Scan(&row).Error; err != nil {
		zlog.Debug("TaskDBSharding", "取数据时间边界失败", err.Error())
		return time.Time{}, time.Time{}, false
	}
	if row.Lo == nil || row.Hi == nil || *row.Lo <= 0 || *row.Hi <= 0 {
		return time.Time{}, time.Time{}, false
	}
	// UNIX_ADD_TIME 是毫秒
	return time.UnixMilli(*row.Lo), time.UnixMilli(*row.Hi), true
}
