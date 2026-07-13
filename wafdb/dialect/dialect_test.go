package dialect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SamWaf/customtype"

	sqlite "github.com/samwafgo/sqlitedriver"
	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// tzTestModel 仅供本测试使用的独立表，结构对齐 ip_tags 的时间列（customtype.JsonTime）。
type tzTestModel struct {
	Id          string              `gorm:"primaryKey;size:64"`
	UPDATE_TIME customtype.JsonTime `gorm:"column:update_time"`
}

func (tzTestModel) TableName() string { return "samwaf_dialect_tz_test" }

// MySQL 的 DATETIME 列里存的就是本地墙钟（DSN loc=Local），
// 再做时区换算会二次偏移——这正是风险日志时间快 8 小时的根因。
func TestMySQLFormatLocalTimeHasNoTimezoneConversion(t *testing.T) {
	expr := (&MySQLDialect{}).FormatLocalTime("MAX(update_time)")
	if strings.Contains(strings.ToUpper(expr), "CONVERT_TZ") {
		t.Fatalf("MySQL 不应再做时区换算，实际表达式: %s", expr)
	}
	if !strings.Contains(expr, "MAX(update_time)") {
		t.Fatalf("表达式丢失了列: %s", expr)
	}
}

// 回环校验：写入 JsonTime(本地时间) → 用 FormatLocalTime 查回 → 必须等于本地墙钟。
// SQLite 侧存的是带 +08:00 后缀的文本，SQLite 会先归一到 UTC，所以偏移必须加回来；
// 这个用例守住"SQLite 不能被改坏"这条线。
func TestFormatLocalTimeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		driver string
		d      DBDialect
	}{
		{"sqlite", &SQLiteDialect{}},
		{"mysql", &MySQLDialect{}},
	} {
		t.Run(tc.driver, func(t *testing.T) {
			db := openTZTestDB(t, tc.driver)

			if err := db.AutoMigrate(&tzTestModel{}); err != nil {
				t.Fatalf("建表失败: %v", err)
			}
			t.Cleanup(func() { db.Migrator().DropTable(&tzTestModel{}) })

			now := time.Now()
			if err := db.Create(&tzTestModel{Id: "tz-1", UPDATE_TIME: customtype.JsonTime(now)}).Error; err != nil {
				t.Fatalf("写入失败: %v", err)
			}

			var got string
			query := "SELECT " + tc.d.FormatLocalTime("MAX(update_time)") + " FROM " + tzTestModel{}.TableName()
			if err := db.Raw(query).Scan(&got).Error; err != nil {
				t.Fatalf("查询失败: %v (SQL: %s)", err, query)
			}

			// 与 customtype.JsonTime.MarshalJSON 的语义保持一致
			want := now.Format("2006-01-02 15:04:05")
			if got != want {
				t.Fatalf("时区偏移了: got %q, want %q (SQL: %s)", got, want, query)
			}
		})
	}
}

// openTZTestDB 打开测试 DB。
//   - sqlite：临时文件库，测试结束自动清理
//   - mysql：需设置环境变量 SAMWAF_TEST_MYSQL_DSN（务必指向可丢弃的测试库），否则跳过
func openTZTestDB(t *testing.T, driver string) *gorm.DB {
	t.Helper()
	cfg := &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}
	var (
		db  *gorm.DB
		err error
	)
	switch driver {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "dialect_tz_test.db")), cfg)
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
	// Windows 下不关连接，t.TempDir 清理会因文件被占用而失败
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			sqlDB.Close()
		}
	})
	return db
}
