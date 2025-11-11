package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"time"
)

// TaskCreateIndex  创建索引
func TaskCreateIndex() {

	//主库索引创建
	createMainDbIndex()
	//日志库索引创建
	createLogDbIndex()
	//统计库索引创建
	createStatDbIndex()
}

// TaskCreateIndexByDbName  创建索引通过数据库名称
func TaskCreateIndexByDbName(dbName string) {

	//主库索引创建
	if dbName == enums.DB_MAIN {
		createMainDbIndex()
	}

	//日志库索引创建
	if dbName == enums.DB_LOG {
		createLogDbIndex()
	}
	//统计库索引创建
	if dbName == enums.DB_STATS {
		createStatDbIndex()
	}
}

func createMainDbIndex() {
	db := global.GWAF_LOCAL_DB
	if db == nil {
		return
	}
	startTime := time.Now()

	zlog.Info("ready create core index maybe use a few minutes ")

	//20241106 创建iptagtag索引
	err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uni_iptags_full ON ip_tags (user_code, tenant_id, ip, ip_tag)").Error
	if err != nil {
		panic("failed to create index : uni_iptags_full " + err.Error())
	} else {
		zlog.Info("db", "uni_iptags_full created")
	}
	// 创建iptag ip索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_iptag_ip ON ip_tags ( user_code, tenant_id, ip)").Error
	if err != nil {
		panic("failed to create index: idx_iptag_ip " + err.Error())
	} else {
		zlog.Info("db", "idx_iptag_ip created")
	}
	// 记录结束时间并计算耗时
	duration := time.Since(startTime)
	zlog.Info("create core index completely", "duration", duration.String())
}
func createLogDbIndex() {
	db := global.GWAF_LOCAL_LOG_DB
	if db == nil {
		return
	}
	// 20241018 创建联合索引 weblog
	startTime := time.Now()

	zlog.Info("ready create log index maybe use a few minutes ")
	err := db.Exec("CREATE INDEX IF NOT EXISTS idx_web_logs_task_flag_time ON web_logs (task_flag, unix_add_time)").Error
	if err != nil {
		panic("failed to create index: idx_web_logs_task_flag_time " + err.Error())
	} else {
		zlog.Info("db", "idx_web_logs_task_flag_time created")
	}
	// 创建联合索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_web_time_tenant_user_code ON web_logs (unix_add_time, tenant_id,user_code)").Error
	if err != nil {
		panic("failed to create index: idx_web_time_tenant_user_code " + err.Error())
	} else {
		zlog.Info("db", "idx_web_time_tenant_user_code created")
	}
	// 详情索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_req_uuid_web_logs ON web_logs (REQ_UUID, tenant_id, user_code)").Error
	if err != nil {
		panic("failed to create index:idx_req_uuid_web_logs " + err.Error())
	} else {
		zlog.Info("db", "idx_unique_req_uuid_web_logs created")
	}
	// 整体索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_tenant_usercode_web_logs ON web_logs ( tenant_id, user_code)").Error
	if err != nil {
		panic("failed to create index: idx_tenant_usercode_web_logs " + err.Error())
	} else {
		zlog.Info("db", "idx_tenant_usercode_web_logs created")
	}

	// 20250123 创建联合索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_web_time_desc_tenant_user_code ON web_logs (unix_add_time desc, tenant_id,user_code)").Error
	if err != nil {
		panic("failed to create index: idx_web_time_desc_tenant_user_code " + err.Error())
	} else {
		zlog.Info("db", "idx_web_time_desc_tenant_user_code created")
	}
	//20250123 建立带IP得
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_web_time_desc_tenant_user_code_ip ON web_logs (unix_add_time desc, tenant_id,user_code,src_ip)").Error
	if err != nil {
		panic("failed to create index: idx_web_time_desc_tenant_user_code_ip " + err.Error())
	} else {
		zlog.Info("db", "idx_web_time_desc_tenant_user_code_ip created")
	}

	// 2025-05-02 添加新索引：为guest_id_entification字段创建索引，优化机器人识别查询
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_web_guest_id_entification ON web_logs (guest_id_entification, day, is_bot, host_code)").Error
	if err != nil {
		panic("failed to create index: idx_web_guest_id_entification " + err.Error())
	} else {
		zlog.Info("db", "idx_web_guest_id_entification created")
	}

	// 记录结束时间并计算耗时
	duration := time.Since(startTime)
	zlog.Info("create log index completely", "duration", duration.String())
}
func createStatDbIndex() {
	// ============ 已废弃：索引创建已迁移到 gormigrate ============
	// 从 2025-11-11 开始，stats 数据库索引通过 gormigrate 在数据库初始化时自动创建
	// ============================================================

	zlog.Info("createStatDbIndex 已废弃，索引由 gormigrate 自动管理")
	return
}
