package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"os"
	"time"
)

// TaskDeleteHistoryInfo 定时删除指定历史信息 通过开关操作
func TaskDeleteHistoryInfo() {
	zlog.Debug("TaskDeleteHistoryInfo")
	deleteBeforeDay := time.Now().AddDate(0, 0, -int(global.GDATA_DELETE_INTERVAL)).Format("2006-01-02 15:04")
	waf_service.WafLogServiceApp.DeleteHistory(deleteBeforeDay)

	// 清理过期的归档分片文件（高频切库后 live 库只存最近数据，真正的保留期回收靠删归档文件）
	CleanExpiredArchiveShard()

	// 仅 SQLite：DELETE 不会收缩文件，主动 checkpoint 截断 WAL 并 VACUUM 回收空间。
	// 本任务在低峰(05:00)执行，且 live 库已被高频切库控制在阈值内，VACUUM 成本可控。
	if dialect.Get().IsFileBased() && global.GWAF_LOCAL_LOG_DB != nil {
		if err := global.GWAF_LOCAL_LOG_DB.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error; err != nil {
			zlog.Warn("TaskDeleteHistoryInfo wal_checkpoint 失败", "error", err.Error())
		}
		if err := global.GWAF_LOCAL_LOG_DB.Exec("VACUUM;").Error; err != nil {
			zlog.Warn("TaskDeleteHistoryInfo VACUUM 失败", "error", err.Error())
		}
	}
}

// TaskHistoryDownload 删除老旧数据
func TaskHistoryDownload() {
	currentDir := utils.GetCurrentDir()
	downLoadDir := currentDir + "/download"
	// 判断备份目录是否存在，不存在则创建
	if _, err := os.Stat(downLoadDir); os.IsNotExist(err) {
		if err := os.MkdirAll(downLoadDir, os.ModePerm); err != nil {
			zlog.Error("创建下载目录失败:", err)
			return
		}
	}
	//处理老旧数据
	duration := 30 * time.Minute
	utils.DeleteOldFiles(downLoadDir, duration)
}
