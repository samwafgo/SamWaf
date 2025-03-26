package wafsafeclear

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
)

func SafeClear() {
	if global.GWAF_LOCAL_DB != nil {
		sqlDB, err := global.GWAF_LOCAL_DB.DB()
		if err != nil {
			zlog.Error("清理异常", err)
		} else {

			// 关闭数据库连接
			if err := sqlDB.Close(); err != nil {
				zlog.Error("清理异常关闭错误", err)
			}
		}
	}

	if global.GWAF_LOCAL_LOG_DB != nil {
		sqlDB, err := global.GWAF_LOCAL_LOG_DB.DB()
		if err != nil {
			zlog.Error("清理log退出异常", err)
		} else {

			// 关闭数据库连接
			if err := sqlDB.Close(); err != nil {
				zlog.Error("清理log异常关闭错误", err)
			}
		}
	}
	if global.GWAF_LOCAL_STATS_DB != nil {
		sqlDB, err := global.GWAF_LOCAL_STATS_DB.DB()
		if err != nil {
			zlog.Error("清理stat退出异常", err)
		} else {

			// 关闭数据库连接
			if err := sqlDB.Close(); err != nil {
				zlog.Error("清理stat异常关闭错误", err)
			}
		}
	}
	if global.GDATA_CURRENT_LOG_DB_MAP != nil {
		for _, value := range global.GDATA_CURRENT_LOG_DB_MAP {
			sqlDB, err := value.DB()
			if err != nil {
				zlog.Error("清理异常错误存档", err)
			} else {

				// 关闭数据库连接
				if err := sqlDB.Close(); err != nil {
					zlog.Error("清理异常错误存档关闭错误", err)
				}
			}
		}
	}

	zlog.Info("退出清理完成")
}
