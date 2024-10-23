package wafdb

import (
	"SamWaf/common/zlog"
	"gorm.io/gorm"
)

/*
*
一些后续补丁
*/
func pathLogSql(db *gorm.DB) {
	// 20241018 创建联合索引 weblog
	err := db.Exec("CREATE INDEX IF NOT EXISTS idx_web_logs_task_flag_time ON web_logs (task_flag, unix_add_time)").Error
	if err != nil {
		panic("failed to create index: " + err.Error())
	} else {
		zlog.Info("db", "idx_web_logs_task_flag_time created")
	}
	// 创建联合索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_web_time_tenant_user_code ON web_logs (unix_add_time, tenant_id,user_code)").Error
	if err != nil {
		panic("failed to create index: " + err.Error())
	} else {
		zlog.Info("db", "idx_web_time_tenant_user_code created")
	}
}
func pathCoreSql(db *gorm.DB) {
	// 20241018 创建联合索引 weblog
	err := db.Exec("UPDATE system_configs SET item_class = 'system' WHERE item_class IS NULL or item_class='' ").Error
	if err != nil {
		panic("failed to system_config :item_class " + err.Error())
	} else {
		zlog.Info("db", "system_config :item_class init successfully")
	}
}
