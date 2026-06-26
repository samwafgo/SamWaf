package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"os"
	"time"
)

// CleanExpiredArchiveShard 清理超过保留期(GDATA_DELETE_INTERVAL 天)的归档日志分片文件。
//
// 背景：高频切库(见 TaskShareDbInfo)后会产生大量 local_log_<ts>.db 归档文件，
// 而原有的删历史逻辑只对 live 库做 DELETE，从不清理归档文件，会很快堆满磁盘。
// 真正的 N 天保留改由本函数按分片 EndTime 删除整个过期归档文件实现。
//
// 仅 SQLite(文件型驱动)生效；MySQL 的归档是表，由其各自策略处理。
func CleanExpiredArchiveShard() {
	innerLogName := "CleanExpiredArchiveShard"
	if !dialect.Get().IsFileBased() {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -int(global.GDATA_DELETE_INTERVAL))
	currentDir := utils.GetCurrentDir()

	shards, err := waf_service.WafShareDbServiceApp.GetAllShareDbApi()
	if err != nil {
		zlog.Error(innerLogName, "获取分库列表失败", err)
		return
	}

	removedFiles := 0
	for _, shard := range shards {
		// 只处理日志分片；跳过 live 库本身
		if shard.DbLogicType != "log" {
			continue
		}
		if shard.FileName == "" || shard.FileName == enums.DB_LOG || shard.FileName == "local_log.db" {
			continue
		}
		// 整个分片(截止 EndTime)早于保留期才删除
		if !time.Time(shard.EndTime).Before(cutoff) {
			continue
		}

		// 删除前先关闭可能已按需打开的连接，避免删正在查询的文件
		wafdb.CloseManualLogDb(shard.FileName)

		dbPath := currentDir + "/data/" + shard.FileName
		for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				zlog.Warn(innerLogName, "删除归档文件失败", "file", p, "error", err.Error())
			}
		}
		removedFiles++

		// 删除归档元数据记录
		if err := waf_service.WafShareDbServiceApp.DeleteById(shard.Id); err != nil {
			zlog.Warn(innerLogName, "删除归档记录失败", "file", shard.FileName, "error", err.Error())
		} else {
			zlog.Info(innerLogName, "已清理过期归档分片", "file", shard.FileName,
				"end_time", time.Time(shard.EndTime).Format("2006-01-02 15:04:05"))
		}
	}

	if removedFiles > 0 {
		zlog.Info(innerLogName, "归档清理完成", "removed", removedFiles, "cutoff", cutoff.Format("2006-01-02"))
	}
}
