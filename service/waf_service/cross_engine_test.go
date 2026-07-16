//go:build crossdb

// 跨三种数据库（SQLite / MySQL / PostgreSQL）兼容回归测试。
//
// 目的：验证「修改」类接口的 Updates(map) 列名在三种引擎下都能落库。
// PostgreSQL 对加引号的标识符大小写敏感，历史上写错大小写的 map key
// （如 "Host_Code"）在 SQLite/MySQL 上碰巧能跑、在 PG 上会报 42703。
//
// 运行（三种库都开着时）：
//
//	go test -tags crossdb ./service/waf_service/ -run CrossEngine -v
//
// 连接可用环境变量覆盖：
//
//	SAMWAF_TEST_MYSQL_DSN="root:canteen1@tcp(127.0.0.1:3306)/"
//	SAMWAF_TEST_PG_DSN="postgres://postgres:postgres@127.0.0.1:5432/"
//
// 未就绪的引擎会被自动 Skip，不影响其它引擎。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	mysqldriver "gorm.io/driver/mysql"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	xtestDBName = "samwaf_xtest_core"
	xtestUser   = "xtest_user"
	xtestTenant = "xtest_tenant"
)

// 受测的模型，每个引擎测试前 AutoMigrate。
var xtestModels = []interface{}{
	&model.IPBlockList{}, &model.IPAllowList{},
	&model.URLBlockList{}, &model.URLAllowList{},
	&model.AntiCC{}, &model.LDPUrl{}, &model.LoadBalance{}, &model.Rules{},
}

type xengine struct {
	name  string
	setup func(t *testing.T) (db *gorm.DB, teardown func())
}

func xengines() []xengine {
	return []xengine{
		{"sqlite", setupSQLite},
		{"mysql", setupMySQL},
		{"postgres", setupPostgres},
	}
}

func setupSQLite(t *testing.T) (*gorm.DB, func()) {
	path := filepath.Join(t.TempDir(), "xtest.db")
	dsn := path + "?_db_key=" + url.QueryEscape("xtestkey")
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Logf("sqlite 打开失败: %v", err)
		return nil, nil
	}
	dialect.Register(&dialect.SQLiteDialect{})
	if err := db.AutoMigrate(xtestModels...); err != nil {
		t.Fatalf("sqlite AutoMigrate: %v", err)
	}
	return db, func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
	}
}

func setupMySQL(t *testing.T) (*gorm.DB, func()) {
	base := os.Getenv("SAMWAF_TEST_MYSQL_DSN")
	if base == "" {
		base = "root:canteen1@tcp(127.0.0.1:3306)/"
	}
	// 维护连接：建库
	root, err := gorm.Open(mysqldriver.Open(base+"?parseTime=true"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Logf("mysql 连接失败（跳过）: %v", err)
		return nil, nil
	}
	root.Exec("DROP DATABASE IF EXISTS " + xtestDBName)
	if err := root.Exec("CREATE DATABASE " + xtestDBName + " CHARACTER SET utf8mb4").Error; err != nil {
		t.Logf("mysql 建库失败（跳过）: %v", err)
		return nil, nil
	}
	work, err := gorm.Open(mysqldriver.Open(base+xtestDBName+"?charset=utf8mb4&parseTime=True&loc=Local"),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("mysql 打开工作库: %v", err)
	}
	dialect.Register(&dialect.MySQLDialect{})
	if err := work.AutoMigrate(xtestModels...); err != nil {
		t.Fatalf("mysql AutoMigrate: %v", err)
	}
	return work, func() {
		if s, e := work.DB(); e == nil {
			s.Close()
		}
		root.Exec("DROP DATABASE IF EXISTS " + xtestDBName)
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}

func setupPostgres(t *testing.T) (*gorm.DB, func()) {
	base := os.Getenv("SAMWAF_TEST_PG_DSN")
	if base == "" {
		base = "postgres://postgres:postgres@127.0.0.1:5432/"
	}
	root, err := gorm.Open(pgdriver.Open(base+"postgres?sslmode=disable"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Logf("postgres 连接失败（跳过）: %v", err)
		return nil, nil
	}
	root.Exec("DROP DATABASE IF EXISTS " + xtestDBName)
	if err := root.Exec("CREATE DATABASE " + xtestDBName + " ENCODING 'UTF8'").Error; err != nil {
		t.Logf("postgres 建库失败（跳过）: %v", err)
		return nil, nil
	}
	work, err := gorm.Open(pgdriver.Open(base+xtestDBName+"?sslmode=disable&TimeZone=Asia/Shanghai"),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("postgres 打开工作库: %v", err)
	}
	dialect.Register(&dialect.PostgresDialect{})
	if err := work.AutoMigrate(xtestModels...); err != nil {
		t.Fatalf("postgres AutoMigrate: %v", err)
	}
	return work, func() {
		if s, e := work.DB(); e == nil {
			s.Close() // 先断开工作连接，否则 DROP DATABASE 会被占用
		}
		root.Exec("DROP DATABASE IF EXISTS " + xtestDBName)
		if s, e := root.DB(); e == nil {
			s.Close()
		}
	}
}

func newBase(id string) baseorm.BaseOrm {
	return baseorm.BaseOrm{
		Id:          id,
		USER_CODE:   xtestUser,
		Tenant_ID:   xtestTenant,
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
}

func TestCrossEngine(t *testing.T) {
	global.GWAF_USER_CODE = xtestUser
	global.GWAF_TENANT_ID = xtestTenant

	for _, e := range xengines() {
		e := e
		t.Run(e.name, func(t *testing.T) {
			// 每个引擎前清空全局句柄，避免复用上一个引擎的连接
			global.GWAF_LOCAL_DB = nil
			db, teardown := e.setup(t)
			if db == nil {
				t.Skipf("%s 未就绪，跳过", e.name)
				return
			}
			defer teardown()
			global.GWAF_LOCAL_DB = db

			// —— 修改类接口：走真实 service ModifyApi，内部即 Updates(map) ——

			t.Run("BlockIP", func(t *testing.T) {
				id := uuid.GenUUID()
				must(t, db.Create(&model.IPBlockList{BaseOrm: newBase(id), HostCode: "h1", Ip: "1.1.1.1"}).Error)
				fatalIf(t, WafBlockIpServiceApp.ModifyApi(request.WafBlockIpEditReq{Id: id, HostCode: "h2", Ip: "1.1.1.1", Remarks: "r"}))
				assertHostCode(t, db, &model.IPBlockList{}, id)
			})

			t.Run("AllowIP", func(t *testing.T) {
				id := uuid.GenUUID()
				must(t, db.Create(&model.IPAllowList{BaseOrm: newBase(id), HostCode: "h1", Ip: "2.2.2.2"}).Error)
				fatalIf(t, WafWhiteIpServiceApp.ModifyApi(request.WafAllowIpEditReq{Id: id, HostCode: "h2", Ip: "2.2.2.2", Remarks: "r"}))
				assertHostCode(t, db, &model.IPAllowList{}, id)
			})

			t.Run("AllowUrl", func(t *testing.T) {
				id := uuid.GenUUID()
				must(t, db.Create(&model.URLAllowList{BaseOrm: newBase(id), HostCode: "h1", CompareType: "suffix", Url: "/a"}).Error)
				fatalIf(t, WafWhiteUrlServiceApp.ModifyApi(request.WafAllowUrlEditReq{Id: id, HostCode: "h2", CompareType: "prefix", Url: "/a", Remarks: "r"}))
				assertHostCode(t, db, &model.URLAllowList{}, id)
			})

			t.Run("BlockUrl", func(t *testing.T) {
				id := uuid.GenUUID()
				must(t, db.Create(&model.URLBlockList{BaseOrm: newBase(id), HostCode: "h1", CompareType: "suffix", Url: "/b"}).Error)
				fatalIf(t, WafBlockUrlServiceApp.ModifyApi(request.WafBlockUrlEditReq{Id: id, HostCode: "h2", CompareType: "prefix", Url: "/b", Remarks: "r"}))
				assertHostCode(t, db, &model.URLBlockList{}, id)
			})

			t.Run("AntiCC", func(t *testing.T) {
				id := uuid.GenUUID()
				must(t, db.Create(&model.AntiCC{BaseOrm: newBase(id), HostCode: "h1", Rate: 1, Limit: 1, LimitMode: "window"}).Error)
				fatalIf(t, WafAntiCCServiceApp.ModifyApi(request.WafAntiCCEditReq{
					Id: id, HostCode: "h2", Rate: 5, Limit: 5, LockIPMinutes: 5, LimitMode: "window",
				}))
				assertHostCode(t, db, &model.AntiCC{}, id)
			})

			t.Run("Ldp", func(t *testing.T) {
				id := uuid.GenUUID()
				must(t, db.Create(&model.LDPUrl{BaseOrm: newBase(id), HostCode: "h1", CompareType: "suffix", Url: "/c"}).Error)
				fatalIf(t, WafLdpUrlServiceApp.ModifyApi(request.WafLdpUrlEditReq{Id: id, HostCode: "h2", CompareType: "prefix", Url: "/c", Remarks: "r"}))
				assertHostCode(t, db, &model.LDPUrl{}, id)
			})

			t.Run("LoadBalance", func(t *testing.T) {
				id := uuid.GenUUID()
				must(t, db.Create(&model.LoadBalance{BaseOrm: newBase(id), HostCode: "h1", Remote_ip: "3.3.3.3", Remote_port: 80}).Error)
				fatalIf(t, WafLoadBalanceServiceApp.ModifyApi(request.WafLoadBalanceEditReq{
					Id: id, HostCode: "h2", Remote_ip: "4.4.4.4", Remote_port: 8080, Weight: 2, Remarks: "r",
				}))
				var got model.LoadBalance
				must(t, db.Where("id = ?", id).First(&got).Error)
				if got.HostCode != "h2" || got.Remote_ip != "4.4.4.4" || got.Remote_port != 8080 {
					t.Fatalf("LoadBalance 更新未落库: %+v", got)
				}
			})

			// Rule 的 ModifyApi 签名较重，直接用它内部同款 Updates(map) 验证 user_code 等 key
			t.Run("Rule_UpdateMap", func(t *testing.T) {
				code := uuid.GenUUID()
				must(t, db.Create(&model.Rules{BaseOrm: newBase(uuid.GenUUID()), RuleCode: code, RuleName: "r1"}).Error)
				ruleMap := map[string]interface{}{
					"host_code":   "hh", // 与修复后一致的列名写法
					"RuleName":    "r2",
					"user_code":   xtestUser, // 本次修复点：原为 "User_code"
					"UPDATE_TIME": customtype.JsonTime(time.Now()),
				}
				fatalIf(t, db.Model(model.Rules{}).Where("rule_code = ?", code).Updates(ruleMap).Error)
				var got model.Rules
				must(t, db.Where("rule_code = ?", code).First(&got).Error)
				if got.RuleName != "r2" {
					t.Fatalf("Rule 更新未落库: %+v", got)
				}
			})

			// —— 方言 SQL 在各引擎真实执行 ——
			t.Run("DialectSQL", func(t *testing.T) {
				d := dialect.Get()
				db.Exec("DROP TABLE IF EXISTS xtest_probe")
				fatalIf(t, db.Exec("CREATE TABLE xtest_probe (id varchar(64), tag varchar(64), cnt int)").Error)
				fatalIf(t, db.Exec("INSERT INTO xtest_probe (id,tag,cnt) VALUES ('a','t1',1),('b','t2',20)").Error)

				var s string
				fatalIf(t, db.Raw("SELECT "+d.GroupConcatDistinct("tag")+" FROM xtest_probe").Scan(&s).Error)

				fatalIf(t, db.Exec(d.BatchDeleteSQL("xtest_probe", "cnt < ?", 100), 10).Error)

				db.Exec("DROP TABLE IF EXISTS xtest_probe")
			})
		})
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("前置数据准备失败: %v", err)
	}
}

func fatalIf(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("操作失败（PG 未修复时此处应报 42703）: %v", err)
	}
}

// assertHostCode 读回记录，断言 host_code 已更新为 "h2"。
func assertHostCode(t *testing.T, db *gorm.DB, dst interface{}, id string) {
	t.Helper()
	if err := db.Where("id = ?", id).First(dst).Error; err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	got := fmt.Sprintf("%v", getHostCode(dst))
	if got != "h2" {
		t.Fatalf("host_code 未更新，仍为 %q，模型 %T", got, dst)
	}
}

func getHostCode(v interface{}) string {
	switch x := v.(type) {
	case *model.IPBlockList:
		return x.HostCode
	case *model.IPAllowList:
		return x.HostCode
	case *model.URLBlockList:
		return x.HostCode
	case *model.URLAllowList:
		return x.HostCode
	case *model.AntiCC:
		return x.HostCode
	case *model.LDPUrl:
		return x.HostCode
	default:
		return ""
	}
}
