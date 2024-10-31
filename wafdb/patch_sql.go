package wafdb

import (
	"SamWaf/common/zlog"
	"gorm.io/gorm"
	"time"
)

/*
*
一些后续补丁
*/
func pathLogSql(db *gorm.DB) {
	// 20241018 创建联合索引 weblog
	startTime := time.Now()

	zlog.Info("ready create index maybe use a few minutes ")
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
	// 详情索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_req_uuid_web_logs ON web_logs (REQ_UUID, tenant_id, user_code)").Error
	if err != nil {
		panic("failed to create index: " + err.Error())
	} else {
		zlog.Info("db", "idx_unique_req_uuid_web_logs created")
	}
	// 整体索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_tenant_usercode_web_logs ON web_logs ( tenant_id, user_code)").Error
	if err != nil {
		panic("failed to create index: " + err.Error())
	} else {
		zlog.Info("db", "idx_tenant_usercode_web_logs created")
	}
	// 记录结束时间并计算耗时
	duration := time.Since(startTime)
	zlog.Info("create index completely", "duration", duration.String())
}
func pathCoreSql(db *gorm.DB) {
	// 20241018 创建联合索引 weblog
	err := db.Exec("UPDATE system_configs SET item_class = 'system' WHERE item_class IS NULL or item_class='' ").Error
	if err != nil {
		panic("failed to system_config :item_class " + err.Error())
	} else {
		zlog.Info("db", "system_config :item_class init successfully")
	}
	// 20241026 是否自动跳转https站点
	err = db.Exec("UPDATE hosts SET auto_jump_http_s=0 WHERE auto_jump_http_s IS NULL ").Error
	if err != nil {
		panic("failed to hosts :auto_jump_https " + err.Error())
	} else {
		zlog.Info("db", "hosts :auto_jump_https init successfully")
	}
	//20241030 初始化一次状态信息
	err = db.Exec("UPDATE hosts SET start_status=0 WHERE start_status IS NULL ").Error
	if err != nil {
		panic("failed to hosts :start_status " + err.Error())
	} else {
		zlog.Info("db", "hosts :start_status init successfully")
	}
}
