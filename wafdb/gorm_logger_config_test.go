package wafdb

import (
	"testing"

	"SamWaf/global"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 护栏：db_debug_enable 关闭时主库挂载的必须是 Error 级且忽略 record not found 的 GormZLogger。
// 若退回 gorm.Config{} 的内置默认 logger（Warn 级、不忽略），First()/Take() 未命中会把
// "record not found" 连同完整 SQL 直写 stdout（gorm 级别数值越大越啰嗦，Warn>=Error 即触发）。
func TestGormZLoggerForConfigLevels(t *testing.T) {
	old := global.GWAF_LOG_DEBUG_DB_ENABLE
	defer func() { global.GWAF_LOG_DEBUG_DB_ENABLE = old }()

	global.GWAF_LOG_DEBUG_DB_ENABLE = false
	l := NewGormZLoggerForConfig()
	if l.LogLevel != logger.Error {
		t.Fatalf("debug 关闭时应为 Error 级， got %v", l.LogLevel)
	}
	if !l.IgnoreRecordNotFound {
		t.Fatal("debug 关闭时必须忽略 record not found")
	}

	global.GWAF_LOG_DEBUG_DB_ENABLE = true
	l = NewGormZLoggerForConfig()
	if l.LogLevel != logger.Info {
		t.Fatalf("debug 开启时应为 Info 级， got %v", l.LogLevel)
	}
}

// 挂了 Error 级 logger 后，record not found 照常返回给调用方，只是不再落地。
func TestGormZLoggerRecordNotFoundStillReturned(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	type task struct {
		Id     int
		Status string
	}
	if err := db.AutoMigrate(&task{}); err != nil {
		t.Fatal(err)
	}
	db = db.Session(&gorm.Session{Logger: NewGormZLoggerForConfig()})
	var v task
	if err := db.Where("status = ?", "queued").First(&v).Error; err == nil {
		t.Fatal("应返回 record not found")
	}
}
