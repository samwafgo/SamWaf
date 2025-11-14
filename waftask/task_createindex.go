package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
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
	// ============ 已废弃：索引创建已迁移到 gormigrate ============
	// 从 2025-11-14 开始，core 数据库索引通过 gormigrate 在数据库初始化时自动创建
	// ============================================================

	zlog.Info("createMainDbIndex 已废弃，索引由 gormigrate 自动管理")
	return
}
func createLogDbIndex() {
	// ============ 已废弃：索引创建已迁移到 gormigrate ============
	// 从 2025-11-14 开始，log 数据库索引通过 gormigrate 在数据库初始化时自动创建
	// ============================================================

	zlog.Info("createLogDbIndex 已废弃，索引由 gormigrate 自动管理")
	return
}
func createStatDbIndex() {
	// ============ 已废弃：索引创建已迁移到 gormigrate ============
	// 从 2025-11-11 开始，stats 数据库索引通过 gormigrate 在数据库初始化时自动创建
	// ============================================================

	zlog.Info("createStatDbIndex 已废弃，索引由 gormigrate 自动管理")
	return
}
