package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"fmt"
	uuid "github.com/satori/go.uuid"
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
	global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&total)
	if total > global.GDATA_SHARE_DB_SIZE {
		global.GDATA_CURRENT_CHANGE = true
		oldDBFilename := "local_log.db"
		newDBFilename := fmt.Sprintf("local_log_%v.db", time.Now().Format("20060102150405"))

		var lastedDb model.ShareDb
		err := global.GWAF_LOCAL_DB.Limit(1).Order("create_time desc").Find(&lastedDb).Error
		startTime := customtype.JsonTime(time.Now())
		if err == nil {
			startTime = lastedDb.EndTime
		}
		sharDbBean := model.ShareDb{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.NewV4().String(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			DbLogicType: "log",
			StartTime:   startTime,
			EndTime:     customtype.JsonTime(time.Now()),
			FileName:    newDBFilename,
			Cnt:         total,
		}

		currentDir := utils.GetCurrentDir()
		oldDBFilename = currentDir + "/data/" + oldDBFilename
		newDBFilename = currentDir + "/data/" + newDBFilename
		zlog.Info(innerLogName, "正在切库中...")
		sqlDB, err := global.GWAF_LOCAL_LOG_DB.DB()

		if err != nil {
			zlog.Error(innerLogName, "切换关闭时候错误", err)
		} else {

			// 关闭数据库连接
			if err := sqlDB.Close(); err != nil {
				zlog.Error(innerLogName, "切换关闭时候错误", err)
			}
		}
		var testTotal int64
		for {
			testError := global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&testTotal).Error
			if testError != nil {
				zlog.Error(innerLogName, "检测数据", testError)
				break
			}
			time.Sleep(1 * time.Second)
		}

		// 关闭与数据库相关的连接或程序
		// 重命名数据库文件
		if err := os.Rename(oldDBFilename, newDBFilename); err != nil {
			zlog.Error(innerLogName, "Error renaming database file:", err)
		}

		// 重命名 .db-shm 文件
		if err := os.Rename(oldDBFilename+"-shm", newDBFilename+"-shm"); err != nil {
			zlog.Error(innerLogName, "Error renaming .db-shm file:", err)
			// 如果有必要，可以选择回滚数据库文件的重命名

		}

		// 重命名 .db-wal 文件
		if err := os.Rename(oldDBFilename+"-wal", newDBFilename+"-wal"); err != nil {
			zlog.Error(innerLogName, "Error renaming .db-wal file:", err)
			// 如果有必要，可以选择回滚数据库文件的重命名
		}
		global.GWAF_LOCAL_DB.Create(sharDbBean)
		global.GWAF_LOCAL_LOG_DB = nil
		wafdb.InitLogDb("")
		global.GDATA_CURRENT_CHANGE = false
		zlog.Info(innerLogName, "切库完成...")
	}

}
