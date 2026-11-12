//go:build crossdb

// 报告任务表与队列去重的三库兼容回归。
// 复现路径：迁移已建表但旧实例缺 security_report_tasks/security_report_settings，
// 升级迁移必须补列建表，且任务唯一键、租户回调、队列过滤在三种引擎下行为一致。
package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb"
	"SamWaf/wafreport"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func runReportCases(t *testing.T, db *gorm.DB) {
	t.Run("ReportTablesAndUniqueKey", func(t *testing.T) {
		if !db.Migrator().HasTable(&model.SecurityReportSettings{}) {
			t.Fatal("security_report_settings 表不存在")
		}
		if !db.Migrator().HasTable(&model.SecurityReportTask{}) {
			t.Fatal("security_report_tasks 表不存在")
		}

		now := time.Now().Unix()
		cfg, err := encodeReportConfig(wafreport.DefaultConfig())
		if err != nil {
			t.Fatalf("encode config: %v", err)
		}
		row := model.SecurityReportSettings{TenantID: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE, SettingsCipher: cfg, StartedAt: now, Revision: 1}
		must(t, db.Exec("DELETE FROM security_report_settings WHERE tenant_id = ?", global.GWAF_TENANT_ID).Error)
		must(t, db.Create(&row).Error)

		must(t, db.Exec("DELETE FROM security_report_tasks WHERE tenant_id = ?", global.GWAF_TENANT_ID).Error)
		dedup := "dedup-report-0123456789abcdef"
		t1 := model.SecurityReportTask{ID: "report-task-0123456789abcdef", TenantID: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE, DedupKey: dedup,
			Kind: "daily", RangeStart: now - 86400, RangeEnd: now, CreatedAt: now, Status: "queued", Source: "schedule", ConfigCipher: cfg}
		must(t, db.Create(&t1).Error)

		// OnConflict(DoNothing) 与唯一索引配合：重复 dedup 不产生第二行。
		t2 := t1
		t2.ID = "report-task-fedcba9876543210"
		res := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&t2)
		must(t, res.Error)
		var count int64
		must(t, db.Raw("SELECT COUNT(*) FROM security_report_tasks WHERE tenant_id = ? AND dedup_key = ?", global.GWAF_TENANT_ID, dedup).Scan(&count).Error)
		if count != 1 {
			t.Fatalf("唯一键约束未生效，重复行被写入 count=%d", count)
		}

		// 队列过滤：queued/running 计数只统计当前租户。
		must(t, db.Raw("SELECT COUNT(*) FROM security_report_tasks WHERE tenant_id = ? AND status IN ?", global.GWAF_TENANT_ID, []string{"queued", "running"}).Scan(&count).Error)
		if count != 1 {
			t.Fatalf("队列计数=%d want 1", count)
		}
		var ids []string
		must(t, db.Raw("SELECT id FROM security_report_tasks WHERE tenant_id = ? AND status = ? ORDER BY created_at ASC, id ASC", global.GWAF_TENANT_ID, "queued").Scan(&ids).Error)
		if len(ids) != 1 || ids[0] != t1.ID {
			t.Fatalf("队列行数=%d want 1 id=%v", len(ids), ids)
		}
	})

	t.Run("ReportSchemaColumnTypes", func(t *testing.T) {
		for _, col := range []struct{ table, column string }{
			{"security_report_settings", "settings_cipher"},
			{"security_report_tasks", "config_cipher"},
			{"security_report_tasks", "artifact_key"},
			{"security_report_tasks", "error_message"},
			{"security_report_tasks", "size_bytes"},
			{"security_report_tasks", "completed_at"},
		} {
			if !db.Migrator().HasColumn(&model.SecurityReportTask{}, col.column) && !db.Migrator().HasColumn(&model.SecurityReportSettings{}, col.column) {
				t.Fatalf("列不存在: %s.%s", col.table, col.column)
			}
		}
	})
}

// 直接调用迁移的表结构检查，避免依赖具体迁移文件名。
func runReportMigrationCases(t *testing.T, db *gorm.DB) {
	t.Run("ReportMigrationCreatesTables", func(t *testing.T) {
		must(t, wafdb.RunCoreDBMigrations(db))
		if !db.Migrator().HasTable(&model.SecurityReportSettings{}) || !db.Migrator().HasTable(&model.SecurityReportTask{}) {
			t.Fatal("安全报告迁移未创建表")
		}
	})
}
