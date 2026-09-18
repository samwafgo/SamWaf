package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"fmt"
	"os"
	"time"
)

// 检测库是否切换
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

	// 分层改造的一次性边界：升级后 web_logs 里还躺着改造前的数据，而写入已切到
	// access_log / security_event / event_payload。先把它整体切成一个归档分片，
	// 新表从空开始——此后「实时」与「归档」各归各位，旧数据照旧能在归档下拉里读（D6）。
	// 无标记可记：web_logs 不再写入，access_log 一旦有行就说明边界已经切过，天然幂等。
	if dialect.Get().TableExists(global.GWAF_LOCAL_LOG_DB, model.AccessLogTableName) {
		var legacyCnt, accessCnt int64
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&legacyCnt)
		global.GWAF_LOCAL_LOG_DB.Model(&model.AccessLog{}).Count(&accessCnt)
		if legacyCnt > 0 && accessCnt == 0 {
			doLogShardCut(innerLogName, fmt.Sprintf("分层改造边界切换（存量 %d 行转入归档）", legacyCnt), true)
			return
		}
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
		doLogShardCut(innerLogName, shardingReason, false)
	}
}

// doLogShardCut 执行一次日志库切分。swapWebLog=true 只用于分层改造的一次性边界切换
// （把存量 web_logs + event_payload 切出去）；常规切分换的是三层新表，
// web_logs 不再写入也就无需再换。
//
// 归档标识：SQLite 为新文件名(.db)，MySQL/PG 为归档表名（边界切换是 web_logs_<ts>，
// 常规切分是 access_log_<ts>；读侧 ResolveTierTables 按前缀两种都认）。
// 注意：MySQL/PG 的归档表不再被 gormigrate 跟踪，今后给这些表加列时读旧分片可能缺列——
// 读侧已按分片实际列取交集（webLogSelect），无需同步 ALTER。
func doLogShardCut(innerLogName, reason string, swapWebLog bool) {
	global.GDATA_CURRENT_CHANGE = true
	defer func() { global.GDATA_CURRENT_CHANGE = false }()
	zlog.Info(innerLogName, "开始分库，原因:", reason)

	ts := time.Now().Format("20060102150405")

	var total int64
	if swapWebLog {
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&total)
	} else {
		global.GWAF_LOCAL_LOG_DB.Model(&model.AccessLog{}).Count(&total)
	}

	newDBFilename := fmt.Sprintf("local_log_%v.db", ts)
	archiveName := newDBFilename
	if !dialect.Get().IsFileBased() {
		if swapWebLog {
			archiveName = fmt.Sprintf("web_logs_%v", ts)
		} else {
			archiveName = fmt.Sprintf("access_log_%v", ts)
		}
	}

	var lastedDb model.ShareDb
	err := global.GWAF_LOCAL_DB.Limit(1).Order("create_time desc").Find(&lastedDb).Error
	startTime := customtype.JsonTime(time.Now())
	if err == nil {
		startTime = lastedDb.EndTime
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
		EndTime:     customtype.JsonTime(time.Now()),
		FileName:    archiveName,
		Cnt:         total,
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
	zlog.Info(innerLogName, "切库完成...")
}
