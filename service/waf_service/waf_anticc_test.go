package waf_service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"

	sqlite "github.com/samwafgo/sqlitedriver"
	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openAntiCCTestDB 打开测试 DB（sqlite 临时文件 / mysql 需 SAMWAF_TEST_MYSQL_DSN 指向可丢弃测试库）。
func openAntiCCTestDB(t *testing.T, driver string) *gorm.DB {
	t.Helper()
	cfg := &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}
	var (
		db  *gorm.DB
		err error
	)
	switch driver {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "anticc_test.db")), cfg)
	case "mysql":
		dsn := os.Getenv("SAMWAF_TEST_MYSQL_DSN")
		if dsn == "" {
			t.Skip("跳过 MySQL 用例：未设置 SAMWAF_TEST_MYSQL_DSN（请指向可丢弃的测试库）")
		}
		db, err = gorm.Open(mysqldriver.Open(dsn), cfg)
	default:
		t.Fatalf("未知驱动: %s", driver)
	}
	if err != nil {
		t.Fatalf("打开 %s 测试库失败: %v", driver, err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// TestWafAntiCCService_AddAndCheck 回归 anticc 新增链路：
// CheckIsExistApi/AddApi 曾因 "host_code = ?" 多传已废弃的 req.Url 参数，导致参数整体
// 顺移、报 "expected N arguments, got N+1"。此用例验证修复后在 sqlite/mysql 下均正常。
func TestWafAntiCCService_AddAndCheck(t *testing.T) {
	for _, driver := range []string{"sqlite", "mysql"} {
		driver := driver
		t.Run(driver, func(t *testing.T) {
			db := openAntiCCTestDB(t, driver)

			// 建表（迁移阶段尚未注册租户回调）
			_ = db.Migrator().DropTable(&model.AntiCC{})
			if err := db.AutoMigrate(&model.AntiCC{}); err != nil {
				t.Fatalf("AutoMigrate 失败: %v", err)
			}
			t.Cleanup(func() { _ = db.Migrator().DropTable(&model.AntiCC{}) })

			// 注册与生产一致的租户过滤回调（迁移之后）
			if err := db.Callback().Query().Before("gorm:query").
				Register("tenant_plugin:before_query", func(d *gorm.DB) {
					d.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
				}); err != nil {
				t.Fatalf("注册租户回调失败: %v", err)
			}

			// 切换全局 DB 与租户，结束后恢复，避免污染其他用例
			oldDB, oldTenant, oldUser := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
			global.GWAF_LOCAL_DB = db
			global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-0001"
			t.Cleanup(func() {
				global.GWAF_LOCAL_DB = oldDB
				global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
			})

			svc := WafAntiCCServiceApp
			addReq := request.WafAntiCCAddReq{HostCode: "host-x", Rate: 10, Limit: 100, LockIPMinutes: 5, LimitMode: "rate"}

			// 1) 新增前检查：不存在时不应报 SQL 参数错误，应为“未找到”
			if err := svc.CheckIsExistApi(addReq); err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("CheckIsExistApi 返回异常错误（疑似参数错位回归）: %v", err)
			}

			// 2) 新增成功
			if err := svc.AddApi(addReq); err != nil {
				t.Fatalf("AddApi 失败: %v", err)
			}

			// 3) 再次新增同 host 应被拒绝（已存在）
			if err := svc.AddApi(addReq); err == nil {
				t.Errorf("重复新增未被拒绝，应返回“已存在”错误")
			}

			// 4) 已存在时 CheckIsExistApi 应返回 nil（找到记录）
			if err := svc.CheckIsExistApi(addReq); err != nil {
				t.Errorf("CheckIsExistApi 在记录已存在时应返回 nil，实际: %v", err)
			}
		})
	}
}
