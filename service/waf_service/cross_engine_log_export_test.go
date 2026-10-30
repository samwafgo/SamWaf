//go:build crossdb

// 日志导出任务表 user_code 列的三库升级回归。
// 复现路径：旧实例已执行建表迁移但表结构缺 user_code，后续查询被租户回调带上该列后报错。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb"
	"testing"
	"time"

	"gorm.io/gorm"
)

func runLogExportCases(t *testing.T, db *gorm.DB) {
	t.Run("LogExportUserCodeColumn", func(t *testing.T) {
		if !db.Migrator().HasColumn(&model.LogExportTask{}, "user_code") {
			t.Fatal("新库迁移后 log_export_task 应包含 user_code 列")
		}
		must(t, db.Migrator().DropColumn(&model.LogExportTask{}, "UserCode"))
		if db.Migrator().HasColumn(&model.LogExportTask{}, "user_code") {
			t.Fatal("模拟旧结构失败：user_code 列仍存在")
		}

		// 再次运行真实 core 迁移，应仅应用追加的补列迁移，不能报「列已存在」。
		// 迁移内部查询不能被租户回调改写，先临时摘除再恢复。
		db.Callback().Query().Before("gorm:query").Remove("tenant_plugin:before_query")
		must(t, db.Exec("DELETE FROM migrations WHERE id = ?", "202610300001_add_log_export_task_user_code").Error)
		must(t, wafdb.RunCoreDBMigrations(db))
		registerTenantScope(db)
		if !db.Migrator().HasColumn(&model.LogExportTask{}, "user_code") {
			t.Fatal("升级迁移未补齐 log_export_task.user_code")
		}

		task := model.LogExportTask{
			Id:        uuid.GenUUID(),
			UserCode:  global.GWAF_USER_CODE,
			TenantID:  global.GWAF_TENANT_ID,
			CreatorID: "creator_" + sfx(),
			RequestID: "req_" + sfx(),
			Status:    "queued",
			CreatedAt: time.Now(),
		}
		must(t, db.Create(&task).Error)

		// 生产查询回调会自动附加 tenant_id/user_code；缺列时这里会复现 no such column。
		var got model.LogExportTask
		must(t, db.Where("id = ?", task.Id).First(&got).Error)
		if got.CreatorID != task.CreatorID {
			t.Fatalf("读回任务不匹配: got=%+v want=%+v", got, task)
		}
		var rows []model.LogExportTask
		must(t, db.Where("status NOT IN ?", []string{"running", "packaging"}).Find(&rows).Error)
	})
}
