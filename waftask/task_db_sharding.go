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
	zlog.Info(innerLogName, "检测是否需要进行分库")

	if global.GDATA_CURRENT_CHANGE {
		//如果正在切换库 跳过
		zlog.Debug(innerLogName, "切库状态")
		return
	}

	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil {
		zlog.Debug(innerLogName, "数据库没有初始化完成呢")
		return
	}

	//获取当前日志数量
	var total int64 = 0
	global.GWAF_LOCAL_LOG_DB.Table(dialect.Get().ForceIndexClause("web_logs", "idx_tenant_usercode_web_logs")).Count(&total)

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

	// 检查大小是否超过限制：SQLite 用 .db 文件大小，MySQL 用 web_logs 表(数据+索引)大小
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
		tableSizeMB, err := dialect.Get().TableSizeMB(global.GWAF_LOCAL_LOG_DB, "web_logs")
		if err == nil {
			if tableSizeMB > global.GDATA_SHARE_DB_FILE_SIZE {
				needSharding = true
				shardingReason = fmt.Sprintf("表大小(%dMB)超过限制(%dMB)", tableSizeMB, global.GDATA_SHARE_DB_FILE_SIZE)
			}
		} else {
			zlog.Error(innerLogName, "获取web_logs表大小失败:", err)
		}
	}

	if needSharding {
		global.GDATA_CURRENT_CHANGE = true
		zlog.Info(innerLogName, "开始分库，原因:", shardingReason)

		ts := time.Now().Format("20060102150405")
		newDBFilename := fmt.Sprintf("local_log_%v.db", ts)
		// 归档标识：SQLite 为新文件名(.db)，MySQL 为归档表名(web_logs_<ts>)
		archiveName := newDBFilename
		if !dialect.Get().IsFileBased() {
			archiveName = fmt.Sprintf("web_logs_%v", ts)
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
			oldDBFilename = currentDir + "/data/" + oldDBFilename
			newDBFilename = currentDir + "/data/" + newDBFilename

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

			if err := os.Rename(oldDBFilename, newDBFilename); err != nil {
				zlog.Error(innerLogName, "Error renaming database file:", err)
			}
			if err := os.Rename(oldDBFilename+"-shm", newDBFilename+"-shm"); err != nil {
				zlog.Error(innerLogName, "Error renaming .db-shm file:", err)
			}
			if err := os.Rename(oldDBFilename+"-wal", newDBFilename+"-wal"); err != nil {
				zlog.Error(innerLogName, "Error renaming .db-wal file:", err)
			}
			global.GWAF_LOCAL_DB.Create(sharDbBean)
			global.GWAF_LOCAL_LOG_DB = nil
			wafdb.InitLogDb("")
		} else {
			// MySQL：CREATE TABLE LIKE + 单语句原子 RENAME 换表。
			// 把 web_logs 归档为 archiveName 并重建同结构空表，换表期间无写入空窗，
			// 同一连接、表已重建为空，无需像 SQLite 那样置 nil 重连。
			// 注意：归档表(web_logs_<ts>)不再被 gormigrate 跟踪，今后给 web_logs 加列时
			// 需同步 ALTER 历史分表，否则读旧分片可能缺列（见 ResolveLogDB 注释）。
			if err := dialect.Get().ShardSwapTable(global.GWAF_LOCAL_LOG_DB, "web_logs", archiveName); err != nil {
				zlog.Error(innerLogName, "分表失败:", err)
			} else {
				global.GWAF_LOCAL_DB.Create(sharDbBean)
				zlog.Info(innerLogName, "分表完成，归档表:", archiveName)
			}
		}
		global.GDATA_CURRENT_CHANGE = false
		zlog.Info(innerLogName, "切库完成...")
	}

}
