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
	// ============ 已废弃：索引创建已迁移到 gormigrate ============
	// 从 2025-11-14 开始，log 数据库索引通过 gormigrate 在数据库初始化时自动创建
	// ============================================================

	zlog.Info("createStatDbIndex 已废弃，索引由 gormigrate 自动管理")
	return
}
func createStatDbIndex() {
	// ============ 已废弃：索引创建已迁移到 gormigrate ============
	// 从 2025-11-11 开始，stats 数据库索引通过 gormigrate 在数据库初始化时自动创建
	// ============================================================

	zlog.Info("createStatDbIndex 已废弃，索引由 gormigrate 自动管理")
	return
}
