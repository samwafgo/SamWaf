package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
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
		//重启需要删除无效规则
		db.Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})

	}
}
