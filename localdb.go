package main

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
		db.AutoMigrate(&innerbean.WebLog{})
		db.AutoMigrate(&model.Hosts{})
		db.AutoMigrate(&model.Rules{})
		//统计处理
		db.AutoMigrate(&model.StatsTotal{})
		db.AutoMigrate(&model.StatsDay{})

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

		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)

		//重启需要删除无效规则
		db.Debug().Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})

	}
}
func before_query(db *gorm.DB) {
	db.Debug()
	db.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	zlog.Info("before_query")
}
