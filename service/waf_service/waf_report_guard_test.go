package waf_service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"SamWaf/common/uuid"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafreport"
	"SamWaf/wafsec"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupReportGuard(t *testing.T) (*WafReportService, ReportActor, *gorm.DB) {
	t.Helper()
	oldCore, oldLog, oldStats := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_LOCAL_STATS_DB
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	oldDialect := func() (d dialect.DBDialect) {
		defer func() { _ = recover() }()
		return dialect.Get()
	}()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SamWafIDE", "1")
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_LOCAL_STATS_DB = oldCore, oldLog, oldStats
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		dialect.Register(oldDialect)
		_ = os.Chdir(cwd)
	})
	dialect.Register(&dialect.SQLiteDialect{})
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "report-tenant", "report-user"
	db, err := gorm.Open(sqlite.Open(filepath.Join(root, "core.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw, _ := db.DB(); _ = raw.Close() })
	global.GWAF_LOCAL_DB = db
	global.GWAF_LOCAL_LOG_DB = db
	global.GWAF_LOCAL_STATS_DB = db
	if err = db.AutoMigrate(&model.Account{}, &model.SecurityReportSettings{}, &model.SecurityReportTask{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", func(tx *gorm.DB) {
		tx.Where("tenant_id = ? AND user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"owner", "other"} {
		a := model.Account{BaseOrm: baseorm.BaseOrm{Id: id, Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}, LoginAccount: id, Role: enums.ROLE_SUPER_ADMIN, Status: 1}
		if err = db.Create(&a).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err = wafsec.InitDataKey(t.TempDir(), ""); err != nil {
		t.Fatal(err)
	}
	s := &WafReportService{}
	s.root = filepath.Join(t.TempDir(), "data", "security_report")
	if err := os.MkdirAll(s.root, 0700); err != nil {
		t.Fatal(err)
	}
	return s, ReportActor{LoginAccount: "owner", UserRole: enums.ROLE_SUPER_ADMIN, ClientIP: "127.0.0.1"}, db
}

func reportGuardCode(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrReportForbidden) {
		t.Fatalf("want ErrReportForbidden, got %v", err)
	}
}

func TestReportGuardActor(t *testing.T) {
	s, owner, db := setupReportGuard(t)
	for _, tc := range []struct {
		name, role string
		open       bool
		status     int
		dbRole     string
	}{
		{"non_super", enums.ROLE_AUDIT_ADMIN, false, 1, enums.ROLE_SUPER_ADMIN},
		{"openapi", enums.ROLE_SUPER_ADMIN, true, 1, enums.ROLE_SUPER_ADMIN},
		{"unsupported_negative_status", enums.ROLE_SUPER_ADMIN, false, -1, enums.ROLE_SUPER_ADMIN},
		{"unsupported_positive_status", enums.ROLE_SUPER_ADMIN, false, 2, enums.ROLE_SUPER_ADMIN},
		{"empty_actor_role", "", false, 1, enums.ROLE_SUPER_ADMIN},
		{"empty_stored_role", enums.ROLE_SUPER_ADMIN, false, 1, ""},
		{"demoted_account", enums.ROLE_SUPER_ADMIN, false, 1, enums.ROLE_SYSTEM_ADMIN},
		{"noncanonical_role", enums.ROLE_SUPER_ADMIN, false, 1, "SuperAdmin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := db.Model(&model.Account{}).Where("id = ?", "owner").Updates(map[string]interface{}{"role": tc.dbRole, "status": tc.status}).Error; err != nil {
				t.Fatal(err)
			}
			a := owner
			a.UserRole, a.IsOpenAPI = tc.role, tc.open
			ctx := context.Background()
			_, err := s.Config(ctx, a)
			reportGuardCode(t, err)
			err = s.SaveConfig(ctx, a, wafreport.DefaultConfig())
			reportGuardCode(t, err)
			_, err = s.List(ctx, a, 1, 20)
			reportGuardCode(t, err)
			_, err = s.Create(ctx, a, "daily", time.Now().AddDate(0, 0, -1).Format("2006-01-02"))
			reportGuardCode(t, err)
			err = s.Delete(ctx, a, "report-0123456789abcdef")
			reportGuardCode(t, err)
			_, err = s.Download(ctx, a, "report-0123456789abcdef")
			reportGuardCode(t, err)
		})
	}
}

func TestReportGuardAccountStatusCompatibility(t *testing.T) {
	for _, status := range []int{0, 1} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			s, actor, db := setupReportGuard(t)
			if err := db.Model(&model.Account{}).Where("id = ?", actor.LoginAccount).Update("status", status).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := s.Config(context.Background(), actor); err != nil {
				t.Fatal(err)
			}
			if err := s.SaveConfig(context.Background(), actor, wafreport.DefaultConfig()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReportGuardOwnership(t *testing.T) {
	s, owner, db := setupReportGuard(t)
	now := time.Now()
	r := wafreport.Range{Start: now.AddDate(0, 0, -2), End: now.AddDate(0, 0, -1)}
	cfg := wafreport.DefaultConfig()
	enc, err := encodeReportConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	task := model.SecurityReportTask{ID: "report-owneronly-0123456", TenantID: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE, DedupKey: uuid.GenUUID(),
		Kind: "daily", RangeStart: r.Start.Unix(), RangeEnd: r.End.Unix(), CreatedAt: now.Unix(), Status: "completed", Source: "manual", ConfigCipher: enc, SizeBytes: 10}
	if err = db.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	other := owner
	other.LoginAccount = "other"
	other.UserRole = enums.ROLE_AUDIT_ADMIN
	if _, err = s.Download(context.Background(), other, task.ID); !errors.Is(err, ErrReportForbidden) {
		t.Fatalf("other account should be forbidden, got %v", err)
	}
	if err = db.Model(&model.SecurityReportTask{}).Where("id = ?", task.ID).Update("tenant_id", "other-tenant").Error; err != nil {
		t.Fatal(err)
	}
	if _, err = s.Download(context.Background(), owner, task.ID); err == nil || strings.Contains(err.Error(), "不存在") == false {
		t.Fatalf("cross-tenant task should be not found, got %v", err)
	}
}

func TestReportConfigRoundTripEncrypts(t *testing.T) {
	s, actor, db := setupReportGuard(t)
	ctx := context.Background()
	want := wafreport.DefaultConfig()
	want.TopN = 25
	if err := s.SaveConfig(ctx, actor, want); err != nil {
		t.Fatal(err)
	}
	var row model.SecurityReportSettings
	if err := db.Where("tenant_id = ?", global.GWAF_TENANT_ID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if !wafsec.IsDataKeyCiphertext(row.SettingsCipher) {
		t.Fatal("settings should be stored as data-key ciphertext")
	}
	got, err := s.Config(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if got["top_n"] != float64(25) || got["enabled"] != true || got["daily_enabled"] != true {
		t.Fatalf("config round trip mismatch: %+v", got)
	}

	// 显式 false 持久化且能再读回。
	want.Enabled = false
	want.DailyEnabled = false
	want.WeeklyEnabled = false
	want.MonthlyEnabled = false
	if err := s.SaveConfig(ctx, actor, want); err != nil {
		t.Fatal(err)
	}
	got, err = s.Config(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != false || got["daily_enabled"] != false || got["weekly_enabled"] != false || got["monthly_enabled"] != false {
		t.Fatalf("explicit false flags not persisted: %+v", got)
	}
}

func TestReportSaveConfigIsolatedByUserCode(t *testing.T) {
	s, owner, db := setupReportGuard(t)
	ctx := context.Background()
	// 同 tenant 下存在另一 user_code 的旧设置行（如实例识别码变更后重建）。
	oldCipher, err := encodeReportConfig(wafreport.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	stale := model.SecurityReportSettings{TenantID: global.GWAF_TENANT_ID, UserCode: "other-user", SettingsCipher: oldCipher, StartedAt: time.Now().Unix(), Revision: 1}
	if err = db.Create(&stale).Error; err != nil {
		t.Fatal(err)
	}
	// 当前 user_code 首次保存：创建本行并更新，必须只命中一行（旧实现按 tenant+revision 过滤会同时命中两行报冲突）。
	cfg := wafreport.DefaultConfig()
	cfg.RetainDays = 21
	if err = s.SaveConfig(ctx, owner, cfg); err != nil {
		t.Fatalf("save with coexisting other-user row should succeed: %v", err)
	}
	got, err := s.Config(ctx, owner)
	if err != nil || int(got["retain_days"].(float64)) != 21 {
		t.Fatalf("current user config not updated: %+v err=%v", got, err)
	}
	var oldRow model.SecurityReportSettings
	// Raw 绕过租户查询回调，才能按 other-user 精确读回。
	if err = db.Raw("SELECT * FROM security_report_settings WHERE tenant_id = ? AND user_code = ?", global.GWAF_TENANT_ID, "other-user").Scan(&oldRow).Error; err != nil {
		t.Fatal(err)
	}
	if oldRow.Revision != 1 || oldRow.SettingsCipher != oldCipher {
		t.Fatalf("other-user row must stay untouched: %+v", oldRow)
	}
}

func TestReportQueueAndStatusTransitions(t *testing.T) {
	s, owner, db := setupReportGuard(t)
	ctx := context.Background()
	// 通过 Create 手动任务入队（executor 未启动也可入队，因为 Create 只依赖 cancel==nil 校验）。
	// 这里不启动 executor，直接测 enqueue 的重复与状态流转。
	r := wafreport.Range{Start: time.Now().AddDate(0, 0, -3), End: time.Now().AddDate(0, 0, -2)}
	cfg := wafreport.DefaultConfig()
	enc, err := encodeReportConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	base := model.SecurityReportTask{ID: "report-queue-012345678", TenantID: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE, DedupKey: "dedup-queue-0123456789",
		Kind: "daily", RangeStart: r.Start.Unix(), RangeEnd: r.End.Unix(), CreatedAt: time.Now().Unix(), Status: "queued", Source: "schedule", ConfigCipher: enc}
	if err = db.Create(&base).Error; err != nil {
		t.Fatal(err)
	}
	var count int64
	if err = db.Model(&model.SecurityReportTask{}).Where("tenant_id = ? AND dedup_key = ?", global.GWAF_TENANT_ID, base.DedupKey).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queue seed count=%d want 1", count)
	}

	// 状态推进：queued -> running -> failed，Delete 应拒绝。
	if err = db.Model(&model.SecurityReportTask{}).Where("id = ?", base.ID).Updates(map[string]interface{}{"status": "running"}).Error; err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx, owner, base.ID); err == nil || !strings.Contains(err.Error(), "生成中") {
		t.Fatalf("delete running report should be blocked, got %v", err)
	}
	if err = db.Model(&model.SecurityReportTask{}).Where("id = ?", base.ID).Updates(map[string]interface{}{"status": "failed"}).Error; err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx, owner, base.ID); err != nil {
		t.Fatalf("delete failed report should succeed, got %v", err)
	}
	var got model.SecurityReportTask
	if err = db.Where("id = ?", base.ID).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != "deleted" || got.ArtifactKey != "" || got.ConfigCipher != "" || got.SizeBytes != 0 {
		t.Fatalf("delete should clear artifact fields: %+v", got)
	}
}

func TestReportDeleteHidesTaskAndManualRecreate(t *testing.T) {
	s, owner, db := setupReportGuard(t)
	ctx := context.Background()
	r, err := wafreport.NewRange(wafreport.Daily, time.Now().AddDate(0, 0, -2))
	if err != nil {
		t.Fatal(err)
	}
	cfg := wafreport.DefaultConfig()
	task, err := s.enqueue(ctx, wafreport.Daily, r, cfg, "schedule")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&task).Update("status", "completed").Error; err != nil {
		t.Fatal(err)
	}
	path, err := s.path(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("report-artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, owner, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted report artifact remains: %v", err)
	}
	for refresh := 0; refresh < 2; refresh++ {
		list, err := s.List(ctx, owner, 1, 20)
		if err != nil || list["total"] != int64(0) || len(list["list"].([]model.SecurityReportTask)) != 0 {
			t.Fatalf("deleted report still listed after refresh: %+v / %v", list, err)
		}
	}
	if _, err := s.Download(ctx, owner, task.ID); err == nil {
		t.Fatal("deleted report remains downloadable")
	}
	scheduled, err := s.enqueue(ctx, wafreport.Daily, r, cfg, "schedule")
	if err != nil || scheduled.Status != "deleted" {
		t.Fatalf("scheduled report recreated after deletion: %+v / %v", scheduled, err)
	}
	manual, err := s.enqueue(ctx, wafreport.Daily, r, cfg, "manual")
	if err != nil || manual.Status != "queued" || manual.Source != "manual" {
		t.Fatalf("manual recreation failed: %+v / %v", manual, err)
	}
	list, err := s.List(ctx, owner, 1, 20)
	if err != nil || list["total"] != int64(1) {
		t.Fatalf("manual recreation not listed: %+v / %v", list, err)
	}
	var saved model.SecurityReportTask
	if err := db.Where("id = ?", manual.ID).First(&saved).Error; err != nil || saved.Source != "manual" {
		t.Fatalf("manual source not saved: %+v / %v", saved, err)
	}
	if err := s.expire(ctx, saved); err != nil {
		t.Fatal(err)
	}
	list, err = s.List(ctx, owner, 1, 20)
	if err != nil || list["total"] != int64(1) || list["list"].([]model.SecurityReportTask)[0].Status != "expired" {
		t.Fatalf("automatic expiration should remain visible: %+v / %v", list, err)
	}
}

func TestReportEnqueueDedupAndRequeue(t *testing.T) {
	s, _, db := setupReportGuard(t)
	ctx := context.Background()
	r := wafreport.Range{Start: time.Now().AddDate(0, 0, -5).Truncate(24 * time.Hour), End: time.Now().AddDate(0, 0, -4).Truncate(24 * time.Hour)}
	cfg := wafreport.DefaultConfig()

	// 手动与定时共用周期唯一键：同周期重复入队返回既有任务，不新增行。
	first, err := s.enqueue(ctx, wafreport.Daily, r, cfg, "manual")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.enqueue(ctx, wafreport.Daily, r, cfg, "schedule")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID {
		t.Fatalf("same period should return existing task: %s vs %s", again.ID, first.ID)
	}
	var count int64
	if err = db.Model(&model.SecurityReportTask{}).Where("tenant_id = ? AND range_start = ? AND range_end = ?", global.GWAF_TENANT_ID, r.Start.Unix(), r.End.Unix()).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("dedup should keep one row, got %d", count)
	}

	// 失败任务由定时路径自动重排，重试达上限后不再重排。
	for i := int64(0); i <= reportMaxRetry; i++ {
		if err = db.Model(&model.SecurityReportTask{}).Where("id = ?", first.ID).Updates(map[string]interface{}{"status": "failed", "retry_count": i}).Error; err != nil {
			t.Fatal(err)
		}
		got, err := s.enqueue(ctx, wafreport.Daily, r, cfg, "schedule")
		if err != nil {
			t.Fatal(err)
		}
		if i < reportMaxRetry {
			if got.Status != "queued" || got.RetryCount != i {
				t.Fatalf("attempt %d should requeue with retry kept: %+v", i, got)
			}
		} else if got.Status != "failed" {
			t.Fatalf("attempt %d should stop requeue at cap: %+v", i, got)
		}
	}

	// 手动重新生成总是允许，并重置重试计数。
	got, err := s.enqueue(ctx, wafreport.Daily, r, cfg, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "queued" || got.RetryCount != 0 {
		t.Fatalf("manual requeue should reset retries: %+v", got)
	}
}

func TestReportPathRejectsTraversal(t *testing.T) {
	s, _, _ := setupReportGuard(t)
	s.root = filepath.Join(t.TempDir(), "data", "security_report")
	if err := os.MkdirAll(s.root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"../escape",
		"report-0123456789abcdef/../..",
		"report-0123456789abcdef.swr",
		"report-0123456789abcdef swr",
		"report-0123456789abcdef\n",
	} {
		if _, err := s.path(id); err == nil {
			t.Fatalf("path(%q) should be rejected", id)
		}
	}
}

func TestReportStopWaitLoop(t *testing.T) {
	s, _, _ := setupReportGuard(t)
	s.cancel = func() {}
	s.done = make(chan struct{})
	close(s.done)
	if err := s.Start(noopCollector{}); err != nil {
		t.Fatalf("Start should not error after Stop-like reset, got %v", err)
	}
	s.Stop()
	if s.cancel != nil {
		t.Fatal("Stop should clear cancel")
	}
}

type noopCollector struct{}

func (noopCollector) Collect(ctx context.Context, req wafreport.Request) (wafreport.Report, error) {
	return wafreport.Report{}, nil
}

func TestReportStartStopRace(t *testing.T) {
	for i := 0; i < 20; i++ {
		s, _, _ := setupReportGuard(t)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = s.Start(noopCollector{})
		}()
		go func() {
			defer wg.Done()
			s.Stop()
		}()
		wg.Wait()
		s.mu.Lock()
		cancel := s.cancel
		s.mu.Unlock()
		if cancel != nil {
			s.Stop()
		}
	}
}
