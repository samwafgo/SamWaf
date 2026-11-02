package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"os"
	"path/filepath"
	"testing"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openAppTestDB 打开临时 sqlite 库并建 WafApp 表，测试不触碰真实配置/数据库
func openAppTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlitedriver.Open(filepath.Join(t.TempDir(), "app_test.db")),
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

// setupAppDirEnv 准备独立允许根 + 临时库，并还原 global 状态
func setupAppDirEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	priorDB, priorDirs := global.GWAF_LOCAL_DB, global.GWAF_APP_ALLOW_DIRS
	global.GWAF_LOCAL_DB = openAppTestDB(t)
	global.GWAF_APP_ALLOW_DIRS = root
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_APP_ALLOW_DIRS = priorDB, priorDirs
	})
	return root
}

func appCount(t *testing.T) int64 {
	t.Helper()
	var total int64
	if err := global.GWAF_LOCAL_DB.Model(&model.WafApp{}).Count(&total).Error; err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	return total
}

func TestAppAddEmptyDirResolvesDefault(t *testing.T) {
	root := setupAppDirEnv(t)
	req := request.WafAppAddReq{Code: "app-add-ok", Name: "app-add-ok", StartCmd: "run"}
	app, err := WafAppServiceApp.AddApi(req)
	if err != nil {
		t.Fatalf("AddApi err=%v", err)
	}
	want := filepath.Join(root, "app-add-ok")
	if app.AppDir != want {
		t.Fatalf("app_dir=%q want %q", app.AppDir, want)
	}
	if info, err := os.Stat(want); err != nil || !info.IsDir() {
		t.Fatalf("目录应已创建: err=%v", err)
	}
	if appCount(t) != 1 {
		t.Fatal("应已入库 1 条")
	}
}

func TestAppAddRejectsDirOutsideAllowed(t *testing.T) {
	setupAppDirEnv(t)
	outside := t.TempDir()
	req := request.WafAppAddReq{Code: "app-add-out", Name: "app-add-out", StartCmd: "run", AppDir: outside}
	if _, err := WafAppServiceApp.AddApi(req); err == nil {
		t.Fatal("越界目录必须报错")
	}
	if appCount(t) != 0 {
		t.Fatal("越界目录不得入库")
	}
}

func TestAppAddMkdirFailureNotPersisted(t *testing.T) {
	root := setupAppDirEnv(t)
	// 在默认目录目标位置预先放一个普通文件，MkdirAll 必然失败
	target := filepath.Join(root, "app-add-block")
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatalf("预置文件失败: %v", err)
	}
	req := request.WafAppAddReq{Code: "app-add-block", Name: "app-add-block", StartCmd: "run"}
	if _, err := WafAppServiceApp.AddApi(req); err == nil {
		t.Fatal("目录创建失败必须报错")
	}
	if appCount(t) != 0 {
		t.Fatal("目录创建失败不得入库")
	}
}

func TestAppEditDirFailureKeepsRecord(t *testing.T) {
	root := setupAppDirEnv(t)
	// 先成功新增：目录 root/app-edit-ok
	addReq := request.WafAppAddReq{Code: "app-edit-ok", Name: "app-edit-ok", StartCmd: "run"}
	app, err := WafAppServiceApp.AddApi(addReq)
	if err != nil {
		t.Fatalf("AddApi err=%v", err)
	}
	oldDir := app.AppDir

	// 目标位置放文件阻塞 MkdirAll
	blocked := filepath.Join(root, "app-edit-block")
	if err := os.WriteFile(blocked, []byte("x"), 0644); err != nil {
		t.Fatalf("预置文件失败: %v", err)
	}
	editReq := request.WafAppEditReq{Id: app.Id, WafAppAddReq: request.WafAppAddReq{
		Code: "app-edit-ok", Name: "app-edit-ok", StartCmd: "run", AppDir: blocked,
	}}
	if err := WafAppServiceApp.ModifyApi(editReq); err == nil {
		t.Fatal("目录预检失败必须报错")
	}
	var got model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("id = ?", app.Id).First(&got).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if got.AppDir != oldDir {
		t.Fatalf("失败编辑不得改记录: got=%q want=%q", got.AppDir, oldDir)
	}

	// 合法编辑应成功并更新目录
	newDir := filepath.Join(root, "app-edit-new")
	editReq.AppDir = newDir
	if err := WafAppServiceApp.ModifyApi(editReq); err != nil {
		t.Fatalf("合法编辑 err=%v", err)
	}
	if err := global.GWAF_LOCAL_DB.Where("id = ?", app.Id).First(&got).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if got.AppDir != newDir {
		t.Fatalf("编辑后 app_dir=%q want %q", got.AppDir, newDir)
	}
}

func TestAppEditRejectsDirOutsideAllowed(t *testing.T) {
	setupAppDirEnv(t)
	addReq := request.WafAppAddReq{Code: "app-edit-out", Name: "app-edit-out", StartCmd: "run"}
	app, err := WafAppServiceApp.AddApi(addReq)
	if err != nil {
		t.Fatalf("AddApi err=%v", err)
	}
	outside := t.TempDir()
	editReq := request.WafAppEditReq{Id: app.Id, WafAppAddReq: request.WafAppAddReq{
		Code: "app-edit-out", Name: "app-edit-out", StartCmd: "run", AppDir: outside,
	}}
	if err := WafAppServiceApp.ModifyApi(editReq); err == nil {
		t.Fatal("越界目录必须报错")
	}
	var got model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("id = ?", app.Id).First(&got).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if got.AppDir != app.AppDir {
		t.Fatal("越界编辑不得改记录")
	}
}
