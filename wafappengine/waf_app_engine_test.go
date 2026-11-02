package wafappengine

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/wafappmodel"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openAppEngineTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlitedriver.Open(filepath.Join(t.TempDir(), "app_engine_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开 sqlite 测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.WafApp{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func insertApp(t *testing.T, app model.WafApp) {
	t.Helper()
	app.BaseOrm = baseorm.BaseOrm{
		Id:          app.Code,
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_DB.Create(&app).Error; err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
}

func TestStartAppFailureExposesRuntimeError(t *testing.T) {
	priorDB := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = openAppEngineTestDB(t)
	t.Cleanup(func() { global.GWAF_LOCAL_DB = priorDB })

	e := NewWafAppEngine()
	// 目标位置预置文件，创建工作目录必然失败
	dir := filepath.Join(t.TempDir(), "blocked")
	if err := writeTestFile(dir); err != nil {
		t.Fatalf("预置文件失败: %v", err)
	}
	insertApp(t, model.WafApp{Code: "app-err", Name: "app-err", AppDir: dir, StartCmd: "true", StartStatus: 1})

	err := e.StartApp("app-err")
	if err == nil {
		t.Fatal("创建目录失败必须返回错误")
	}
	rt := e.GetRuntimeStatus("app-err")
	if rt.Status != wafappmodel.AppStatusStopped {
		t.Fatalf("状态=%d want stopped", rt.Status)
	}
	if !strings.Contains(rt.LastError, "创建工作目录失败") {
		t.Fatalf("LastError=%q 应包含阶段", rt.LastError)
	}
	if rt.ErrorTime.IsZero() {
		t.Fatal("ErrorTime 必须记录失败时间")
	}
}

func TestRuntimeErrorClearsOnSuccessfulStart(t *testing.T) {
	priorDB := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = openAppEngineTestDB(t)
	t.Cleanup(func() { global.GWAF_LOCAL_DB = priorDB })

	e := NewWafAppEngine()
	dir := filepath.Join(t.TempDir(), "ok")
	insertApp(t, model.WafApp{Code: "app-ok", Name: "app-ok", AppDir: dir, StartCmd: "true", StartStatus: 1})
	rt := &wafappmodel.AppRuntime{Code: "app-ok", Status: wafappmodel.AppStatusStopped, LastError: "旧错误", ErrorTime: time.Now(), StopChan: make(chan struct{})}
	e.runtimes["app-ok"] = rt

	if err := e.startProcess(model.WafApp{Code: "app-ok", Name: "app-ok", AppDir: dir, StartCmd: "true", StartStatus: 1}, rt); err != nil {
		t.Fatalf("启动应成功: %v", err)
	}
	if rt.LastError != "" || !rt.ErrorTime.IsZero() {
		t.Fatalf("成功启动应清除旧错误: last=%q time=%v", rt.LastError, rt.ErrorTime)
	}
	if rt.Done == nil {
		t.Fatal("Done 通道必须提前初始化，避免 stop 等待永久阻塞")
	}
	insertApp(t, model.WafApp{Code: "app-ok-stop", Name: "app-ok-stop", AppDir: dir, StartCmd: "true", StartStatus: 1, StopTimeout: 1})
	if err := e.StopApp("app-ok"); err != nil {
		t.Fatalf("StopApp err=%v", err)
	}
	if rt.Status != wafappmodel.AppStatusStopped || rt.Pid != 0 {
		t.Fatalf("StopApp 后状态=%d pid=%d", rt.Status, rt.Pid)
	}
}

func writeTestFile(path string) error {
	return os.WriteFile(path, []byte("x"), 0644)
}
