package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
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

	}
}
