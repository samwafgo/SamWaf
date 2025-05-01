package waftask

import (
	"SamWaf/common/zlog"
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

	// 记录结束时间并计算耗时
	duration := time.Since(startTime)
	zlog.Info("create log index completely", "duration", duration.String())
}
func createStatDbIndex() {
	db := global.GWAF_LOCAL_STATS_DB
	if db == nil {
		return
	}
	startTime := time.Now()

	zlog.Info("ready create stats index maybe use a few minutes, ")

	// 为stats_days表创建索引
	err := db.Exec("CREATE INDEX IF NOT EXISTS idx_stats_days_lookup ON stats_days (tenant_id, user_code, host_code, type, day)").Error
	if err != nil {
		panic("failed to create index: idx_stats_days_lookup " + err.Error())
	} else {
		zlog.Info("db", "idx_stats_days_lookup created")
	}

	// 为stats_ip_days表创建索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_stats_ip_days_lookup ON stats_ip_days (tenant_id, user_code, host_code, ip, type, day)").Error
	if err != nil {
		panic("failed to create index: idx_stats_ip_days_lookup " + err.Error())
	} else {
		zlog.Info("db", "idx_stats_ip_days_lookup created")
	}

	// 为stats_ip_city_days表创建索引
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_stats_ip_city_days_lookup ON stats_ip_city_days (tenant_id, user_code, host_code, country, province, city, type, day)").Error
	if err != nil {
		panic("failed to create index: idx_stats_ip_city_days_lookup " + err.Error())
	} else {
		zlog.Info("db", "idx_stats_ip_city_days_lookup created")
	}

	// 记录结束时间并计算耗时
	duration := time.Since(startTime)
	zlog.Info("create stats index completely", "duration", duration.String())
}
