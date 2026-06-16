package wafdb

import (
	"os"
	"path/filepath"
	"testing"

	"SamWaf/global"
	"SamWaf/model/baseorm"

	sqlite "github.com/samwafgo/sqlitedriver"
	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// tenantScopeTestModel 仅供本测试使用的独立表，避免误碰生产表(anti_ccs 等)。
// 字段结构与受 before_query 影响的真实表一致：tenant_id / user_code / host_code。
type tenantScopeTestModel struct {
	baseorm.BaseOrm
	HostCode string `gorm:"column:host_code;size:64"`
}

func (tenantScopeTestModel) TableName() string { return "samwaf_tenant_scope_test" }

// openTenantTestDB 打开测试 DB（暂不注册租户回调，注册时机与生产一致：迁移之后）。
//   - sqlite：临时文件库，测试结束自动清理
//   - mysql：需设置环境变量 SAMWAF_TEST_MYSQL_DSN（务必指向可丢弃的测试库），否则跳过
func openTenantTestDB(t *testing.T, driver string) *gorm.DB {
	t.Helper()
	cfg := &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}
	var (
		db  *gorm.DB
		err error
	)
	switch driver {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "tenant_scope_test.db")), cfg)
	case "mysql":
		dsn := os.Getenv("SAMWAF_TEST_MYSQL_DSN")
		if dsn == "" {
			t.Skip("跳过 MySQL 用例：未设置 SAMWAF_TEST_MYSQL_DSN（示例 user:pass@tcp(127.0.0.1:3306)/samwaf_test?charset=utf8mb4&parseTime=True&loc=Local，请指向可丢弃的测试库）")
		}
		db, err = gorm.Open(mysqldriver.Open(dsn), cfg)
	default:
		t.Fatalf("未知驱动: %s", driver)
	}
	if err != nil {
		t.Fatalf("打开 %s 测试库失败: %v", driver, err)
	}
	// 关闭底层连接，确保（sqlite）临时文件在 t.TempDir() 清理前已释放，避免 Windows 文件占用
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// seedTenantScopeData 重建测试表并写入两个租户、相同 host_code 的数据。
// 此时尚未注册 before_query，AutoMigrate/Create 不受租户过滤影响。
func seedTenantScopeData(t *testing.T, db *gorm.DB) {
	t.Helper()
	_ = db.Migrator().DropTable(&tenantScopeTestModel{})
	if err := db.AutoMigrate(&tenantScopeTestModel{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}
	rows := []tenantScopeTestModel{
		{BaseOrm: baseorm.BaseOrm{Id: "a1", Tenant_ID: "tenantA", USER_CODE: "userA"}, HostCode: "host-1"},
		{BaseOrm: baseorm.BaseOrm{Id: "b1", Tenant_ID: "tenantB", USER_CODE: "userB"}, HostCode: "host-1"},
		{BaseOrm: baseorm.BaseOrm{Id: "a2", Tenant_ID: "tenantA", USER_CODE: "userA"}, HostCode: "host-2"},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("写入测试数据失败: %v", err)
		}
	}
}

// TestTenantScopeQuery 验证 before_query 租户过滤在 sqlite / mysql 下均正确，
// 并回归 “host_code 单占位符 + 回调补 tenant/user” 这条查询路径——它曾因 service
// 层多传参数（如 anticc 误传 req.Url、log/rule 误传 tenant/user）导致参数整体顺移，
// 报 "expected N arguments, got N+1" 且租户值错位。
func TestTenantScopeQuery(t *testing.T) {
	for _, driver := range []string{"sqlite", "mysql"} {
		driver := driver
		t.Run(driver, func(t *testing.T) {
			db := openTenantTestDB(t, driver)

			// 先建表插数据（无租户回调）
			seedTenantScopeData(t, db)

			// 设定当前租户；结束后恢复全局并清理测试表
			oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
			global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "tenantA", "userA"
			t.Cleanup(func() {
				global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
				_ = db.Migrator().DropTable(&tenantScopeTestModel{})
			})

			// 注册与生产一致的 before_query 租户回调（迁移之后才注册）
			if err := db.Callback().Query().Before("gorm:query").
				Register("tenant_plugin:before_query", before_query); err != nil {
				t.Fatalf("注册 before_query 回调失败: %v", err)
			}

			// 1) First by host_code：回归参数错位 bug，应不报错且只命中当前租户
			var rec tenantScopeTestModel
			if err := db.Where("host_code = ?", "host-1").First(&rec).Error; err != nil {
				t.Fatalf("First 查询失败（疑似参数错位回归）: %v", err)
			}
			if rec.Id != "a1" {
				t.Errorf("租户隔离失败：期望命中当前租户 a1，实际 id=%s tenant=%s", rec.Id, rec.Tenant_ID)
			}

			// 2) Find：当前租户只应看到自己的 2 行（a1/a2），看不到 tenantB 的 b1
			var list []tenantScopeTestModel
			if err := db.Find(&list).Error; err != nil {
				t.Fatalf("Find 查询失败: %v", err)
			}
			if len(list) != 2 {
				t.Errorf("租户隔离失败：期望 2 行，实际 %d 行", len(list))
			}
			for _, r := range list {
				if r.Tenant_ID != "tenantA" {
					t.Errorf("查询到非当前租户数据：id=%s tenant=%s", r.Id, r.Tenant_ID)
				}
			}

			// 3) Count：host-1 在当前租户下应为 1 行（仅 a1，不含 tenantB 的 b1）
			var cnt int64
			if err := db.Model(&tenantScopeTestModel{}).Where("host_code = ?", "host-1").Count(&cnt).Error; err != nil {
				t.Fatalf("Count 查询失败: %v", err)
			}
			if cnt != 1 {
				t.Errorf("租户隔离失败：host-1 当前租户应为 1 行，实际 %d", cnt)
			}
		})
	}
}
