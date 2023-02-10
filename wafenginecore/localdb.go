package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils/zlog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func InitDb() {
	if global.GWAF_LOCAL_DB == nil {
		db, err := gorm.Open(sqlite.Open("data/local.db"), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		global.GWAF_LOCAL_DB = db
		// Migrate the schema
		db.AutoMigrate(&model.Hosts{})
		db.AutoMigrate(&model.Rules{})

		//隐私处理
		db.AutoMigrate(&model.LDPUrl{})

		//白名单处理
		db.AutoMigrate(&model.IPWhiteList{})
		db.AutoMigrate(&model.URLWhiteList{})

		//限制处理
		db.AutoMigrate(&model.IPBlockList{})
		db.AutoMigrate(&model.URLBlockList{})

		//抵抗CC
		db.AutoMigrate(&model.AntiCC{})

		//waf自身账号
		db.AutoMigrate(&model.TokenInfo{})
		db.AutoMigrate(&model.Account{})
		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)

		//重启需要删除无效规则
		db.Debug().Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})

	}
	if global.GWAF_LOCAL_LOG_DB == nil {
		logDB, err := gorm.Open(sqlite.Open("data/local_log.db"), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		global.GWAF_LOCAL_LOG_DB = logDB
		// Migrate the schema
		//统计处理
		logDB.AutoMigrate(&model.StatsTotal{})
		logDB.AutoMigrate(&model.StatsDay{})
		logDB.AutoMigrate(&model.StatsIPDay{})
		logDB.AutoMigrate(&model.StatsIPCityDay{})
		logDB.AutoMigrate(&innerbean.WebLog{})
		logDB.AutoMigrate(&model.AccountLog{})
		global.GWAF_LOCAL_LOG_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)

	}
}
func before_query(db *gorm.DB) {
	db.Debug()
	db.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	zlog.Info("before_query")
}
