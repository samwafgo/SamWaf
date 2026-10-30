package waf_service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"SamWaf/common/queue"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils/filelease"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/waflogexport"
	"SamWaf/wafsec"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupExportGuard(t *testing.T) (*WafLogExportService, LogExportActor, *gorm.DB) {
	t.Helper()
	oldCore, oldLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	oldTenant, oldUser, oldKey := global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GWAF_PWD_LOGDB
	oldEnabled, oldCfg := global.GWAF_CAN_EXPORT_DOWNLOAD_LOG, global.GLOG_EXPORT_CONFIG
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
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = oldCore, oldLog
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GWAF_PWD_LOGDB = oldTenant, oldUser, oldKey
		global.GWAF_CAN_EXPORT_DOWNLOAD_LOG, global.GLOG_EXPORT_CONFIG = oldEnabled, oldCfg
		dialect.Register(oldDialect)
		_ = os.Chdir(cwd)
	})
	dialect.Register(&dialect.SQLiteDialect{})
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GWAF_PWD_LOGDB = "export-tenant", "export-user", "export-test-key"
	global.GWAF_CAN_EXPORT_DOWNLOAD_LOG, global.GLOG_EXPORT_CONFIG = true, global.DefaultLogExportConfig()
	global.GLOG_EXPORT_CONFIG.MinFreeGiB = 0
	global.GWAF_LOCAL_LOG_DB = nil
	db, err := gorm.Open(sqlite.Open(filepath.Join(root, "core.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw, _ := db.DB(); _ = raw.Close() })
	global.GWAF_LOCAL_DB = db
	if err = db.AutoMigrate(&model.Account{}, &model.LogExportTask{}, &model.ShareDb{}); err != nil {
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
	s := &WafLogExportService{cancel: func() {}, owner: "test-owner", wake: make(chan struct{}, 1), running: map[string]context.CancelFunc{}, tickets: map[string]exportTicket{}, downloads: map[string]int{}}
	return s, LogExportActor{LoginAccount: "owner", UserRole: enums.ROLE_SUPER_ADMIN}, db
}
func exportGuardReq() request.LogExportCreateReq {
	return request.LogExportCreateReq{RequestID: "request-1234567890", Format: "jsonl", Tables: []string{"access_log"}, RangeMode: "recent"}
}
func exportGuardCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *LogExportError
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
func exportGuardTask(t *testing.T, s *WafLogExportService, a LogExportActor) string {
	t.Helper()
	v, err := s.Create(context.Background(), a, exportGuardReq())
	if err != nil {
		t.Fatal(err)
	}
	return v["task_id"].(string)
}
func TestLogExportGuardActor(t *testing.T) {
	s, owner, db := setupExportGuard(t)
	for _, tc := range []struct {
		name, role string
		open       bool
		status     int
		dbRole     string
	}{
		{"non_super", enums.ROLE_AUDIT_ADMIN, false, 1, enums.ROLE_SUPER_ADMIN},
		{"openapi", enums.ROLE_SUPER_ADMIN, true, 1, enums.ROLE_SUPER_ADMIN},
		{"unsupported_status", enums.ROLE_SUPER_ADMIN, false, -1, enums.ROLE_SUPER_ADMIN},
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
			_, err := s.Create(ctx, a, exportGuardReq())
			exportGuardCode(t, err, "EXPORT_FORBIDDEN")
			_, err = s.List(ctx, a, request.LogExportListReq{})
			exportGuardCode(t, err, "EXPORT_FORBIDDEN")
			_, err = s.Get(ctx, a, "task-123456789012")
			exportGuardCode(t, err, "EXPORT_FORBIDDEN")
			_, err = s.Cancel(ctx, a, "task-123456789012")
			exportGuardCode(t, err, "EXPORT_FORBIDDEN")
			err = s.Delete(ctx, a, "task-123456789012")
			exportGuardCode(t, err, "EXPORT_FORBIDDEN")
			_, err = s.IssueDownloadTicket(ctx, a, "task-123456789012")
			exportGuardCode(t, err, "EXPORT_FORBIDDEN")
			caps, err := s.Capabilities(ctx, a)
			if err != nil || caps["allowed"] != false {
				t.Fatalf("capabilities: %v %v", caps, err)
			}
		})
	}
}
func TestLogExportGuardAccountStatusCompatibility(t *testing.T) {
	for _, status := range []int{0, 1} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			s, actor, db := setupExportGuard(t)
			if err := db.Model(&model.Account{}).Where("id = ?", actor.LoginAccount).Update("status", status).Error; err != nil {
				t.Fatal(err)
			}
			caps, err := s.Capabilities(context.Background(), actor)
			if err != nil || caps["allowed"] != true {
				t.Fatalf("capabilities: %v %v", caps, err)
			}
			id := exportGuardTask(t, s, actor)
			if _, err = s.Get(context.Background(), actor, id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLogExportGuardOwnership(t *testing.T) {
	s, owner, db := setupExportGuard(t)
	id := exportGuardTask(t, s, owner)
	other := owner
	other.LoginAccount = "other"
	ctx := context.Background()
	t.Run("get", func(t *testing.T) {
		_, err := s.Get(ctx, other, id)
		exportGuardCode(t, err, "EXPORT_NOT_FOUND")
	})
	t.Run("delete", func(t *testing.T) {
		err := s.Delete(ctx, other, id)
		exportGuardCode(t, err, "EXPORT_NOT_FOUND")
	})
	_, err := s.Cancel(ctx, other, id)
	exportGuardCode(t, err, "EXPORT_NOT_FOUND")
	_, err = s.IssueDownloadTicket(ctx, other, id)
	exportGuardCode(t, err, "EXPORT_NOT_FOUND")
	if err = db.Model(&model.LogExportTask{}).Where("id = ?", id).Update("tenant_id", "other-tenant").Error; err != nil {
		t.Fatal(err)
	}
	_, err = s.Get(ctx, owner, id)
	exportGuardCode(t, err, "EXPORT_NOT_FOUND")
}
func TestLogExportGuardDisabledAndTables(t *testing.T) {
	s, owner, _ := setupExportGuard(t)
	global.GWAF_CAN_EXPORT_DOWNLOAD_LOG = false
	_, err := s.Create(context.Background(), owner, exportGuardReq())
	exportGuardCode(t, err, "EXPORT_DISABLED")
	global.GWAF_CAN_EXPORT_DOWNLOAD_LOG = true
	for _, name := range []string{"event_payload", "web_logs", "accounts", "access_log_202610", "access_log; SELECT 1"} {
		req := exportGuardReq()
		req.Tables = []string{name}
		_, err = s.Create(context.Background(), owner, req)
		exportGuardCode(t, err, "EXPORT_INVALID")
	}
}
func exportGuardArtifact(t *testing.T, s *WafLogExportService, a LogExportActor, db *gorm.DB) string {
	t.Helper()
	id := exportGuardTask(t, s, a)
	dir, err := exportTaskDir(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := waflogexport.NewBuilder(context.Background(), waflogexport.Options{Dir: dir, Format: "jsonl", Tables: []string{"access_log"}, Key: global.GWAF_PWD_LOGDB, TaskID: id})
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.removeArtifact(id) })
	if err = db.Model(&model.LogExportTask{}).Where("id = ?", id).Updates(map[string]interface{}{"status": "ready", "artifact_name": filepath.Base(r.Path), "artifact_key": r.WrappedKey, "bytes_written": r.ZIPBytes, "expires_at": time.Now().Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	return id
}
func exportGuardTicket(t *testing.T, s *WafLogExportService, a LogExportActor, id string) string {
	t.Helper()
	v, err := s.IssueDownloadTicket(context.Background(), a, id)
	if err != nil {
		t.Fatal(err)
	}
	return v["ticket"].(string)
}
func TestLogExportGuardTicket(t *testing.T) {
	s, owner, db := setupExportGuard(t)
	owner.ClientIP = "192.0.2.1"
	id := exportGuardArtifact(t, s, owner, db)
	ctx := context.Background()
	t.Run("wrong_ip", func(t *testing.T) {
		ticket := exportGuardTicket(t, s, owner, id)
		d, err := s.OpenDownload(ctx, id, ticket, "192.0.2.2")
		if d != nil {
			d.Complete(nil)
		}
		exportGuardCode(t, err, "EXPORT_TICKET_INVALID")
	})
	t.Run("reuse", func(t *testing.T) {
		ticket := exportGuardTicket(t, s, owner, id)
		d, err := s.OpenDownload(ctx, id, ticket, owner.ClientIP)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(d.Reader)
		d.Complete(err)
		if err != nil || d.Size == 0 || (d.Size > 0 && int64(len(raw)) != d.Size) {
			t.Fatalf("download length: size=%d bytes=%d err=%v", d.Size, len(raw), err)
		}
		d, err = s.OpenDownload(ctx, id, ticket, owner.ClientIP)
		if d != nil {
			d.Complete(nil)
		}
		exportGuardCode(t, err, "EXPORT_TICKET_INVALID")
	})
	t.Run("concurrent", func(t *testing.T) {
		ticket := exportGuardTicket(t, s, owner, id)
		var wg sync.WaitGroup
		results := make(chan bool, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d, err := s.OpenDownload(ctx, id, ticket, owner.ClientIP)
				if d != nil {
					d.Complete(nil)
				}
				results <- err == nil
			}()
		}
		wg.Wait()
		close(results)
		count := 0
		for ok := range results {
			if ok {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("successful consumers=%d", count)
		}
	})
	t.Run("expired_ticket", func(t *testing.T) {
		ticket := exportGuardTicket(t, s, owner, id)
		for k, v := range s.tickets {
			v.Expires = time.Now().Add(-time.Second)
			s.tickets[k] = v
		}
		_, err := s.OpenDownload(ctx, id, ticket, owner.ClientIP)
		exportGuardCode(t, err, "EXPORT_TICKET_INVALID")
	})
	t.Run("revoked_account", func(t *testing.T) {
		ticket := exportGuardTicket(t, s, owner, id)
		if err := db.Model(&model.Account{}).Where("id = ?", "owner").Update("role", enums.ROLE_AUDIT_ADMIN).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Model(&model.Account{}).Where("id = ?", "owner").Update("role", enums.ROLE_SUPER_ADMIN) })
		d, err := s.OpenDownload(ctx, id, ticket, owner.ClientIP)
		if d != nil {
			d.Complete(nil)
		}
		exportGuardCode(t, err, "EXPORT_FORBIDDEN")
	})
	t.Run("disabled_download", func(t *testing.T) {
		ticket := exportGuardTicket(t, s, owner, id)
		global.GWAF_CAN_EXPORT_DOWNLOAD_LOG = false
		_, err := s.OpenDownload(ctx, id, ticket, owner.ClientIP)
		exportGuardCode(t, err, "EXPORT_DISABLED")
		global.GWAF_CAN_EXPORT_DOWNLOAD_LOG = true
	})
	for _, st := range []string{"failed", "cancelled", "expired", "deleted"} {
		t.Run(st, func(t *testing.T) {
			db.Model(&model.LogExportTask{}).Where("id = ?", id).Update("status", "ready")
			ticket := exportGuardTicket(t, s, owner, id)
			db.Model(&model.LogExportTask{}).Where("id = ?", id).Update("status", st)
			_, err := s.OpenDownload(ctx, id, ticket, owner.ClientIP)
			exportGuardCode(t, err, "EXPORT_NOT_READY")
		})
	}
}
func TestLogExportGuardStartStop(t *testing.T) {
	_, owner, _ := setupExportGuard(t)
	s := &WafLogExportService{}
	s.Start()
	if s.cancel == nil {
		t.Fatal("executor did not start")
	}
	if _, err := s.Create(context.Background(), owner, exportGuardReq()); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	for i := 0; i < 50; i++ {
		if _, err := s.Create(context.Background(), owner, exportGuardReq()); err == nil {
			t.Fatal("create accepted while executor is stopping")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not finish")
	}
	if _, err := s.Create(context.Background(), owner, exportGuardReq()); err == nil {
		t.Fatal("create accepted after stop")
	}
}
func TestLogExportGuardExecutorLock(t *testing.T) {
	setupExportGuard(t)
	path := exportExecutorLockPath()
	first := &WafLogExportService{}
	first.Start()
	if first.cancel == nil {
		t.Fatal("first executor did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var secondLease *filelease.Lease
	secondLease, err := wafdb.AcquireExclusive(ctx, path)
	if err == nil {
		secondLease.Release()
		t.Fatal("second executor lock acquired while executor is running")
	}
	second := &WafLogExportService{}
	second.Start()
	if second.cancel != nil || second.stopping {
		t.Fatal("second executor started without the exclusive lock")
	}
	first.Stop()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	released, err := wafdb.AcquireExclusive(ctx2, path)
	if err != nil {
		t.Fatalf("executor lock not released after stop: %v", err)
	}
	released.Release()
	third := &WafLogExportService{}
	third.Start()
	if third.cancel == nil {
		t.Fatal("executor lock not re-acquirable after stop")
	}
	third.Stop()
}
func TestLogExportGuardMissingTables(t *testing.T) {
	for _, tc := range []struct {
		name          string
		access, event bool
		want          string
	}{
		{"one_missing", true, false, "partial"},
		{"all_missing", false, false, "failed"},
		{"empty_ready", true, true, "ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, owner, core := setupExportGuard(t)
			db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "log.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := db.DB()
			defer raw.Close()
			global.GWAF_LOCAL_LOG_DB = db
			if tc.access {
				if err = db.AutoMigrate(&model.AccessLog{}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.event {
				if err = db.AutoMigrate(&model.SecurityEvent{}); err != nil {
					t.Fatal(err)
				}
			}
			if err = db.AutoMigrate(&model.SecurityAuditLog{}); err != nil {
				t.Fatal(err)
			}
			req := exportGuardReq()
			req.Tables = []string{"access_log", "security_event"}
			v, err := s.Create(context.Background(), owner, req)
			if err != nil {
				t.Fatal(err)
			}
			id := v["task_id"].(string)
			var task model.LogExportTask
			if err = core.Where("id = ?", id).First(&task).Error; err != nil {
				t.Fatal(err)
			}
			core.Model(&task).Updates(map[string]interface{}{"status": "running", "owner": s.owner})
			task.Status = "running"
			task.Owner = s.owner
			s.execute(context.Background(), task)
			if err = core.Where("id = ?", id).First(&task).Error; err != nil {
				t.Fatal(err)
			}
			if task.Status != tc.want {
				t.Fatalf("want %s got %s (%s)", tc.want, task.Status, task.ErrorCode)
			}
			t.Cleanup(func() { _ = s.removeArtifact(id) })
		})
	}
}

func TestLogExportGuardExecuteRetainsArtifact(t *testing.T) {
	s, owner, core := setupExportGuard(t)
	if err := core.Model(&model.Account{}).Where("id = ?", owner.LoginAccount).Update("status", 0).Error; err != nil {
		t.Fatal(err)
	}
	logdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "log.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := logdb.DB()
	defer raw.Close()
	global.GWAF_LOCAL_LOG_DB = logdb
	if err = logdb.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.SecurityAuditLog{}); err != nil {
		t.Fatal(err)
	}
	id := exportGuardTask(t, s, owner)
	var task model.LogExportTask
	if err = core.Where("id = ?", id).First(&task).Error; err != nil {
		t.Fatal(err)
	}
	core.Model(&task).Updates(map[string]interface{}{"status": "running", "owner": s.owner})
	task.Status = "running"
	task.Owner = s.owner
	oldQueue := global.GQEQUE_MESSAGE_DB
	global.GQEQUE_MESSAGE_DB = queue.NewQueue()
	t.Cleanup(func() { global.GQEQUE_MESSAGE_DB = oldQueue })
	s.execute(context.Background(), task)
	msg, ok := global.GQEQUE_MESSAGE_DB.Dequeue()
	ready, typed := msg.(innerbean.LogExportReadyMessageInfo)
	if !ok || !typed || ready.TaskID != id || !strings.Contains(ready.Msg, "条数:0") || !strings.Contains(ready.Msg, "大小:") {
		t.Fatalf("ready notification missing or invalid: %#v", msg)
	}
	if err = core.Where("id = ?", id).First(&task).Error; err != nil {
		t.Fatal(err)
	}
	if task.Status != "ready" {
		t.Fatalf("status=%s error=%s", task.Status, task.ErrorCode)
	}
	dir, err := exportTaskDir(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.removeArtifact(id) })
	if _, err = os.Stat(filepath.Join(dir, task.ArtifactName)); err != nil {
		t.Fatalf("ready artifact missing: %v", err)
	}
	owner.ClientIP = ""
	ticket := exportGuardTicket(t, s, owner, id)
	d, err := s.OpenDownload(context.Background(), id, ticket, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(d.Reader)
	d.Complete(err)
	if err != nil || d.Size == 0 || (d.Size > 0 && d.Size != int64(len(data))) || !strings.HasPrefix(string(data), "PK") {
		t.Fatalf("invalid ZIP: size=%d bytes=%d err=%v", d.Size, len(data), err)
	}
}
