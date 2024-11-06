package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"os"
	"time"
)

// TaskDeleteHistoryInfo 定时删除指定历史信息 通过开关操作
func TaskDeleteHistoryInfo() {
	zlog.Debug("TaskDeleteHistoryInfo")
	deleteBeforeDay := time.Now().AddDate(0, 0, -int(global.GDATA_DELETE_INTERVAL)).Format("2006-01-02 15:04")
	waf_service.WafLogServiceApp.DeleteHistory(deleteBeforeDay)
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
