package waf_service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/utils"
	"SamWaf/utils/filelease"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/waflogexport"
	"gorm.io/gorm"
)

type LogExportActor struct {
	LoginAccount, UserRole, ClientIP string
	IsOpenAPI                        bool
}
type LogExportError struct {
	Code, Message string
	HTTPStatus    int
}

func (e *LogExportError) Error() string { return e.Message }
func exportError(code, message string, status int) error {
	return &LogExportError{code, message, status}
}

type LogExportTaskView struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	Phase        string     `json:"phase"`
	Format       string     `json:"format"`
	Tables       []string   `json:"tables"`
	RangeMode    string     `json:"range_mode"`
	StartTime    string     `json:"start_time"`
	EndTime      string     `json:"end_time"`
	RowsWritten  int64      `json:"rows_written"`
	BytesWritten int64      `json:"bytes_written"`
	SourceDone   int        `json:"source_done"`
	SourceTotal  int        `json:"source_total"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
	ErrorCode    string     `json:"error_code"`
	ErrorMessage string     `json:"error_message"`
	Checksum     string     `json:"checksum,omitempty"`
}

func exportTaskView(t model.LogExportTask) LogExportTaskView {
	var tables []string
	_ = json.Unmarshal([]byte(t.TablesJSON), &tables)
	return LogExportTaskView{t.Id, t.Status, t.Phase, t.Format, tables, t.RangeMode, t.StartTime, t.EndTime, t.RowsWritten, t.BytesWritten, t.SourceDone, t.SourceTotal, t.CreatedAt, t.ExpiresAt, t.ErrorCode, t.ErrorMessage, t.Checksum}
}

type exportTicket struct {
	TaskID, AccountID, TenantID, LoginAccount, ClientIP string
	Expires                                             time.Time
}
type LogExportDownload struct {
	Name     string
	Size     int64
	Reader   io.ReadCloser
	Complete func(error)
}
type WafLogExportService struct {
	mu           sync.Mutex
	owner        string
	cancel       context.CancelFunc
	stopping     bool
	executorLock *filelease.Lease
	done         chan struct{}
	wake         chan struct{}
	tickets      map[string]exportTicket
	running      map[string]context.CancelFunc
	downloads    map[string]int
}

var WafLogExportServiceApp = &WafLogExportService{}
var exportIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,64}$`)
var exportActiveStates = []string{"queued", "running", "packaging", "cancelling"}

func logExportAccountAllowed(a model.Account) bool {
	return a.Id != "" && a.Role == enums.ROLE_SUPER_ADMIN && (a.Status == 0 || a.Status == 1)
}

func (s *WafLogExportService) authorize(ctx context.Context, actor LogExportActor) (model.Account, error) {
	var a model.Account
	if actor.IsOpenAPI || actor.LoginAccount == "" || actor.UserRole != enums.ROLE_SUPER_ADMIN {
		return a, exportError("EXPORT_FORBIDDEN", "仅超级管理员可操作日志导出", 403)
	}
	if global.GWAF_LOCAL_DB == nil {
		return a, exportError("EXPORT_UNAVAILABLE", "数据库暂不可用", 503)
	}
	err := global.GWAF_LOCAL_DB.WithContext(ctx).Where("login_account = ? AND tenant_id = ?", actor.LoginAccount, global.GWAF_TENANT_ID).First(&a).Error
	if err != nil || !logExportAccountAllowed(a) {
		return a, exportError("EXPORT_FORBIDDEN", "当前账号无日志导出权限", 403)
	}
	return a, nil
}
func (s *WafLogExportService) Capabilities(ctx context.Context, actor LogExportActor) (map[string]interface{}, error) {
	_, err := s.authorize(ctx, actor)
	if err != nil {
		var e *LogExportError
		if errors.As(err, &e) && e.HTTPStatus == 403 {
			return map[string]interface{}{"allowed": false, "enabled": false}, nil
		}
		return nil, err
	}
	return map[string]interface{}{"allowed": true, "enabled": global.GWAF_CAN_EXPORT_DOWNLOAD_LOG, "formats": []string{"jsonl", "csv", "sqlite"}, "limits": global.GLOG_EXPORT_CONFIG}, nil
}
func normalizeLogExport(req request.LogExportCreateReq, now time.Time) (request.LogExportCreateReq, error) {
	if req.Format == "" {
		req.Format = "jsonl"
	}
	if req.Format != "jsonl" && req.Format != "csv" && req.Format != "sqlite" {
		return req, exportError("EXPORT_INVALID", "导出格式不正确", 400)
	}
	if req.Tables == nil {
		req.Tables = []string{model.AccessLogTableName, model.SecurityEventTableName}
	}
	if len(req.Tables) < 1 || len(req.Tables) > 2 {
		return req, exportError("EXPORT_INVALID", "请选择日志表", 400)
	}
	seen := map[string]bool{}
	for _, t := range req.Tables {
		if (t != model.AccessLogTableName && t != model.SecurityEventTableName) || seen[t] {
			return req, exportError("EXPORT_INVALID", "日志表选择不正确", 400)
		}
		seen[t] = true
	}
	if !exportIDPattern.MatchString(req.RequestID) {
		return req, exportError("EXPORT_INVALID", "请求标识不正确", 400)
	}
	if req.RangeMode == "" {
		req.RangeMode = "recent"
	}
	if req.RangeMode == "all" {
		req.StartTime = ""
		if req.EndTime == "" {
			req.EndTime = now.Format(time.RFC3339)
		}
	}
	if req.RangeMode == "recent" {
		if req.StartTime == "" {
			req.StartTime = now.Add(-4 * time.Hour).Format(time.RFC3339)
		}
		if req.EndTime == "" {
			req.EndTime = now.Format(time.RFC3339)
		}
	}
	if req.RangeMode != "all" && req.RangeMode != "custom" && req.RangeMode != "recent" {
		return req, exportError("EXPORT_INVALID", "时间范围模式不正确", 400)
	}
	hi, err := time.Parse(time.RFC3339Nano, req.EndTime)
	if err != nil {
		return req, exportError("EXPORT_INVALID", "结束时间格式不正确", 400)
	}
	if hi.After(now) {
		hi = now
	}
	hi = hi.Truncate(time.Second)
	req.EndTime = hi.Format(time.RFC3339)
	if req.RangeMode != "all" {
		lo, e := time.Parse(time.RFC3339Nano, req.StartTime)
		if e != nil || !lo.Truncate(time.Second).Before(hi) {
			return req, exportError("EXPORT_INVALID", "开始时间必须早于结束时间", 400)
		}
		req.StartTime = lo.Truncate(time.Second).Format(time.RFC3339)
	}
	return req, nil
}
func (s *WafLogExportService) Create(ctx context.Context, actor LogExportActor, req request.LogExportCreateReq) (map[string]interface{}, error) {
	a, err := s.authorize(ctx, actor)
	if err != nil {
		return nil, err
	}
	if !global.GWAF_CAN_EXPORT_DOWNLOAD_LOG {
		return nil, exportError("EXPORT_DISABLED", "请在 conf/config.yml 中设置 export_download: true 并重启", 403)
	}
	req, err = normalizeLogExport(req, time.Now())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel == nil || s.stopping {
		return nil, exportError("EXPORT_UNAVAILABLE", "导出执行器尚未就绪，请稍后重试", 503)
	}
	var old model.LogExportTask
	db := global.GWAF_LOCAL_DB.WithContext(ctx)
	err = db.Where("tenant_id = ? AND creator_id = ? AND request_id = ?", a.Tenant_ID, a.Id, req.RequestID).First(&old).Error
	if err == nil {
		return map[string]interface{}{"task_id": old.Id, "status": old.Status}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, exportError("EXPORT_UNAVAILABLE", "任务读取失败", 503)
	}
	var count int64
	if err = db.Model(&model.LogExportTask{}).Where("status IN ?", exportActiveStates).Count(&count).Error; err != nil {
		return nil, err
	}
	if count >= int64(global.GLOG_EXPORT_CONFIG.QueueLimit+1) {
		return nil, exportError("EXPORT_BUSY", "导出队列已满，请稍后重试", 409)
	}
	tables, _ := json.Marshal(req.Tables)
	t := model.LogExportTask{Id: uuid.GenUUID(), UserCode: global.GWAF_USER_CODE, TenantID: a.Tenant_ID, CreatorID: a.Id, RequestID: req.RequestID, Format: req.Format, TablesJSON: string(tables), RangeMode: req.RangeMode, StartTime: req.StartTime, EndTime: req.EndTime, Status: "queued", Phase: "queued", CreatedAt: time.Now()}
	if err = db.Create(&t).Error; err != nil {
		return nil, exportError("EXPORT_UNAVAILABLE", "任务创建失败", 503)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	s.audit(actor, t, "create", true)
	return map[string]interface{}{"task_id": t.Id, "status": t.Status}, nil
}
func (s *WafLogExportService) task(ctx context.Context, actor LogExportActor, id string) (model.LogExportTask, error) {
	a, err := s.authorize(ctx, actor)
	if err != nil {
		return model.LogExportTask{}, err
	}
	var t model.LogExportTask
	if !exportIDPattern.MatchString(id) {
		return t, exportError("EXPORT_NOT_FOUND", "任务不存在", 404)
	}
	err = global.GWAF_LOCAL_DB.WithContext(ctx).Where("id = ? AND creator_id = ? AND tenant_id = ?", id, a.Id, a.Tenant_ID).First(&t).Error
	if err != nil {
		return t, exportError("EXPORT_NOT_FOUND", "任务不存在或不可访问", 404)
	}
	return t, nil
}
func (s *WafLogExportService) List(ctx context.Context, actor LogExportActor, req request.LogExportListReq) (map[string]interface{}, error) {
	a, err := s.authorize(ctx, actor)
	if err != nil {
		return nil, err
	}
	if req.PageIndex < 1 {
		req.PageIndex = 1
	}
	if req.PageSize < 1 {
		req.PageSize = 10
	}
	if req.PageSize > 100 {
		req.PageSize = 100
	}
	col := req.SortBy
	if col != "expires_at" && col != "status" {
		col = "created_at"
	}
	dir := "desc"
	if req.SortOrder == "asc" {
		dir = "asc"
	}
	db := global.GWAF_LOCAL_DB.WithContext(ctx).Model(&model.LogExportTask{}).Where("creator_id = ? AND tenant_id = ?", a.Id, a.Tenant_ID)
	var total int64
	if err = db.Count(&total).Error; err != nil {
		return nil, err
	}
	var rows []model.LogExportTask
	if err = db.Order(col + " " + dir).Offset((req.PageIndex - 1) * req.PageSize).Limit(req.PageSize).Find(&rows).Error; err != nil {
		return nil, err
	}
	list := make([]LogExportTaskView, 0, len(rows))
	for _, t := range rows {
		list = append(list, exportTaskView(t))
	}
	return map[string]interface{}{"list": list, "total": total, "page": req.PageIndex, "page_size": req.PageSize}, nil
}
func (s *WafLogExportService) Get(ctx context.Context, a LogExportActor, id string) (LogExportTaskView, error) {
	t, e := s.task(ctx, a, id)
	return exportTaskView(t), e
}
func (s *WafLogExportService) Cancel(ctx context.Context, a LogExportActor, id string) (LogExportTaskView, error) {
	t, e := s.task(ctx, a, id)
	if e != nil {
		return LogExportTaskView{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if t.Status == "queued" {
		e = global.GWAF_LOCAL_DB.WithContext(ctx).Model(&model.LogExportTask{}).Where("id = ? AND status = ?", id, "queued").Updates(map[string]interface{}{"status": "cancelled", "phase": "complete", "finished_at": now}).Error
	} else if t.Status == "running" || t.Status == "packaging" || t.Status == "cancelling" {
		e = global.GWAF_LOCAL_DB.WithContext(ctx).Model(&model.LogExportTask{}).Where("id = ? AND status IN ?", id, []string{"running", "packaging"}).Update("status", "cancelling").Error
		if cancel := s.running[id]; cancel != nil {
			cancel()
		}
	}
	if e != nil {
		return LogExportTaskView{}, e
	}
	s.audit(a, t, "cancel", true)
	var current model.LogExportTask
	e = global.GWAF_LOCAL_DB.WithContext(ctx).Where("id = ?", id).First(&current).Error
	return exportTaskView(current), e
}
func (s *WafLogExportService) Delete(ctx context.Context, a LogExportActor, id string) error {
	t, e := s.task(ctx, a, id)
	if e != nil {
		return e
	}
	if isExportActive(t.Status) {
		_, e = s.Cancel(ctx, a, id)
		if e != nil {
			return e
		}
		return exportError("EXPORT_CANCELLING", "任务正在取消，结束后可删除", 409)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.downloads[id] > 0 {
		return exportError("EXPORT_DOWNLOADING", "文件正在下载，请稍后删除", 409)
	}
	if e = s.removeArtifact(id); e != nil {
		return exportError("EXPORT_FILE_ERROR", "文件回收失败", 500)
	}
	e = global.GWAF_LOCAL_DB.WithContext(ctx).Model(&model.LogExportTask{}).Where("id = ? AND status NOT IN ?", id, exportActiveStates).Updates(map[string]interface{}{"status": "deleted", "artifact_key": "", "artifact_name": ""}).Error
	if e == nil {
		s.audit(a, t, "delete", true)
	}
	return e
}
func isExportActive(st string) bool {
	for _, s := range exportActiveStates {
		if st == s {
			return true
		}
	}
	return false
}
func (s *WafLogExportService) audit(a LogExportActor, t model.LogExportTask, action string, ok bool) {
	result := model.AccessAuditFail
	if ok {
		result = model.AccessAuditOK
	}
	WafSecurityAuditServiceApp.Write(AuditEntry{Event: model.AuditEventConfigLogExport, AccountName: a.LoginAccount, SessionCode: t.Id, ClientIP: a.ClientIP, Result: result, Message: fmt.Sprintf("日志导出 %s format=%s rows=%d bytes=%d", action, t.Format, t.RowsWritten, t.BytesWritten)})
}
func exportRoot() string { return filepath.Join(utils.GetCurrentDir(), "data", "log_exports") }
func exportTaskDir(id string) (string, error) {
	if !exportIDPattern.MatchString(id) {
		return "", errors.New("invalid export identifier")
	}
	root, e := filepath.Abs(filepath.Clean(exportRoot()))
	if e != nil {
		return "", e
	}
	if e := os.MkdirAll(root, 0700); e != nil {
		return "", e
	}
	if st, e := os.Lstat(root); e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("invalid export directory")
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil || !strings.EqualFold(filepath.Clean(real), root) {
		return "", errors.New("invalid export directory anchor")
	}
	path := filepath.Join(root, id)
	if st, e := os.Lstat(path); e == nil && (!st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
		return "", errors.New("invalid task directory")
	} else if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	return path, nil
}
func (s *WafLogExportService) removeArtifact(id string) error {
	p, e := exportTaskDir(id)
	if e != nil {
		return e
	}
	return os.RemoveAll(p)
}

func (s *WafLogExportService) IssueDownloadTicket(ctx context.Context, a LogExportActor, id string) (map[string]interface{}, error) {
	t, e := s.task(ctx, a, id)
	if e != nil {
		return nil, e
	}
	if e = exportDownloadReady(t); e != nil {
		return nil, e
	}
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		return nil, e
	}
	ticket := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(ticket))
	expires := time.Now().Add(time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil {
		s.tickets = map[string]exportTicket{}
	}
	for k, v := range s.tickets {
		if time.Now().After(v.Expires) {
			delete(s.tickets, k)
		}
	}
	if len(s.tickets) >= 1024 {
		return nil, exportError("EXPORT_BUSY", "下载请求过多，请稍后重试", 429)
	}
	s.tickets[hex.EncodeToString(sum[:])] = exportTicket{id, t.CreatorID, t.TenantID, a.LoginAccount, a.ClientIP, expires}
	return map[string]interface{}{"ticket": ticket, "expires_at": expires}, nil
}
func exportDownloadReady(t model.LogExportTask) error {
	if !global.GWAF_CAN_EXPORT_DOWNLOAD_LOG {
		return exportError("EXPORT_DISABLED", "日志导出下载尚未开启", 403)
	}
	if (t.Status != "ready" && t.Status != "partial") || t.ExpiresAt == nil || !time.Now().Before(*t.ExpiresAt) {
		return exportError("EXPORT_NOT_READY", "文件尚未就绪或已过期", 409)
	}
	return nil
}
func (s *WafLogExportService) OpenDownload(ctx context.Context, id, ticket, clientIP string) (*LogExportDownload, error) {
	if len(ticket) != 64 || !exportIDPattern.MatchString(id) {
		return nil, exportError("EXPORT_TICKET_INVALID", "下载链接无效或已过期", 403)
	}
	sum := sha256.Sum256([]byte(ticket))
	hash := hex.EncodeToString(sum[:])
	s.mu.Lock()
	v, ok := s.tickets[hash]
	delete(s.tickets, hash)
	s.mu.Unlock()
	if !ok || v.TaskID != id || v.ClientIP != clientIP || time.Now().After(v.Expires) {
		return nil, exportError("EXPORT_TICKET_INVALID", "下载链接无效或已过期", 403)
	}
	actor := LogExportActor{LoginAccount: v.LoginAccount, UserRole: enums.ROLE_SUPER_ADMIN, ClientIP: clientIP}
	t, e := s.task(ctx, actor, id)
	if e != nil {
		return nil, e
	}
	if t.CreatorID != v.AccountID || t.TenantID != v.TenantID {
		return nil, exportError("EXPORT_FORBIDDEN", "任务不可访问", 403)
	}
	if e = exportDownloadReady(t); e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The state is reloaded while holding the file lease mutex.
	if e = global.GWAF_LOCAL_DB.WithContext(ctx).Where("id = ?", id).First(&t).Error; e != nil {
		return nil, e
	}
	if e = exportDownloadReady(t); e != nil {
		return nil, e
	}
	dir, e := exportTaskDir(id)
	if e != nil {
		return nil, exportError("EXPORT_FILE_ERROR", "文件不可访问", 500)
	}
	if t.ArtifactName == "" || filepath.Base(t.ArtifactName) != t.ArtifactName {
		return nil, exportError("EXPORT_FILE_ERROR", "文件不可访问", 500)
	}
	path := filepath.Join(dir, t.ArtifactName)
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return nil, exportError("EXPORT_FILE_ERROR", "文件不存在或已回收", 404)
	}
	reader, e := waflogexport.OpenArchive(path, t.ArtifactKey, id)
	if e != nil {
		return nil, exportError("EXPORT_FILE_ERROR", "文件读取失败", 500)
	}
	if s.downloads == nil {
		s.downloads = map[string]int{}
	}
	s.downloads[id]++
	s.audit(actor, t, "download_start", true)
	var once sync.Once
	complete := func(err error) {
		once.Do(func() {
			reader.Close()
			s.mu.Lock()
			s.downloads[id]--
			s.mu.Unlock()
			s.audit(actor, t, "download_finish", err == nil)
		})
	}
	return &LogExportDownload{Name: "samwaf_logs_" + id + ".zip", Size: t.BytesWritten, Reader: reader, Complete: complete}, nil
}

func exportExecutorLockPath() string {
	return filepath.Join(utils.GetCurrentDir(), "data", ".samwaf_log_export_executor.lock")
}
func (s *WafLogExportService) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil || global.GWAF_LOCAL_DB == nil {
		return
	}
	lockCtx, lockCancel := context.WithTimeout(context.Background(), 5*time.Second)
	executorLock, err := wafdb.AcquireExclusive(lockCtx, exportExecutorLockPath())
	lockCancel()
	if err != nil {
		zlog.Warn("日志导出执行器锁被其他进程持有，本进程保持未启动", "error", err.Error())
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.stopping = false
	s.executorLock = executorLock
	s.done = make(chan struct{})
	s.wake = make(chan struct{}, 1)
	s.owner = uuid.GenUUID()
	s.running = map[string]context.CancelFunc{}
	s.downloads = map[string]int{}
	s.tickets = map[string]exportTicket{}
	go s.loop(ctx, s.done)
}
func (s *WafLogExportService) Stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	executorLock := s.executorLock
	if cancel != nil {
		s.stopping = true
		cancel()
	}
	for _, c := range s.running {
		c()
	}
	s.mu.Unlock()
	exited := true
	if done != nil {
		select {
		case <-done:
		case <-time.After(35 * time.Second):
			exited = false
		}
	}
	s.mu.Lock()
	if executorLock != nil {
		executorLock.Release()
		if err := executorLock.Err(); err != nil {
			zlog.Warn("释放日志导出执行器锁失败", "error", err.Error())
		}
		s.executorLock = nil
	}
	if cancel != nil && exited {
		s.cancel = nil
		s.stopping = false
	}
	s.mu.Unlock()
}
func (s *WafLogExportService) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	now := time.Now()
	global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("status IN ?", []string{"running", "packaging", "cancelling"}).Updates(map[string]interface{}{"status": "failed", "phase": "complete", "error_code": "EXPORT_INTERRUPTED", "error_message": "执行器已重启，请重新导出", "finished_at": now})
	s.reap()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if !s.runNext(ctx) {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				s.reap()
			case <-s.wake:
			}
		}
	}
}
func (s *WafLogExportService) runNext(ctx context.Context) bool {
	var t model.LogExportTask
	if e := global.GWAF_LOCAL_DB.WithContext(ctx).Where("status = ?", "queued").Order("created_at asc").First(&t).Error; e != nil {
		return false
	}
	now := time.Now()
	if now.Sub(t.CreatedAt) > 10*time.Minute {
		s.finish(t, "failed", "EXPORT_QUEUE_TIMEOUT", "排队等待超时")
		return true
	}
	r := global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND status = ?", t.Id, "queued").Updates(map[string]interface{}{"status": "running", "phase": "resolving", "owner": s.owner, "started_at": now, "heartbeat_at": now})
	if r.Error != nil || r.RowsAffected != 1 {
		return false
	}
	t.Owner = s.owner
	t.Status = "running"
	taskCtx, cancel := context.WithTimeout(ctx, time.Duration(global.GLOG_EXPORT_CONFIG.TimeoutMinutes)*time.Minute)
	s.mu.Lock()
	s.running[t.Id] = cancel
	s.mu.Unlock()
	heartDone := make(chan struct{})
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-heartDone:
				return
			case <-taskCtx.Done():
				return
			case <-tick.C:
				var current model.LogExportTask
				if global.GWAF_LOCAL_DB.Where("id = ? AND owner = ?", t.Id, s.owner).First(&current).Error != nil || current.Status == "cancelling" {
					cancel()
					continue
				}
				global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND owner = ? AND status IN ?", t.Id, s.owner, []string{"running", "packaging"}).Update("heartbeat_at", time.Now())
			}
		}
	}()
	s.execute(taskCtx, t)
	close(heartDone)
	cancel()
	s.mu.Lock()
	delete(s.running, t.Id)
	s.mu.Unlock()
	return true
}
func exportServerName() string {
	if global.GWAF_CUSTOM_SERVER_NAME != "" {
		return global.GWAF_CUSTOM_SERVER_NAME
	}
	return "未命名服务器"
}

func (s *WafLogExportService) finish(t model.LogExportTask, status, code, message string) {
	now := time.Now()
	global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND status IN ?", t.Id, exportActiveStates).Updates(map[string]interface{}{"status": status, "phase": "complete", "error_code": code, "error_message": message, "finished_at": now})
	s.audit(LogExportActor{}, t, status, status == "ready")
}

func (s *WafLogExportService) notifyReady(t model.LogExportTask, status string) {
	if status == "ready" || status == "partial" {
		msg := fmt.Sprintf("日志导出已完成，任务:%s 条数:%d 大小:%d字节", t.Id, t.RowsWritten, t.BytesWritten)
		if status == "partial" {
			msg = fmt.Sprintf("日志导出部分完成，任务:%s 条数:%d 大小:%d字节，请在任务详情核对缺失来源", t.Id, t.RowsWritten, t.BytesWritten)
		}
		if global.GQEQUE_MESSAGE_DB != nil {
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.LogExportReadyMessageInfo{BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "日志导出任务", Server: exportServerName()}, TaskID: t.Id, Msg: msg})
		}
	}
}
func (s *WafLogExportService) execute(ctx context.Context, t model.LogExportTask) {
	defer func() {
		if r := recover(); r != nil {
			s.finish(t, "failed", "EXPORT_INTERNAL", "导出未完成，请重新发起")
			_ = s.removeArtifact(t.Id)
		}
	}()
	failure := func(code, message string) {
		st := "failed"
		if ctx.Err() != nil {
			st = "cancelled"
			code = "EXPORT_CANCELLED"
			message = "导出已取消"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				st = "failed"
				code = "EXPORT_TIMEOUT"
				message = "导出超时，请缩小范围"
			}
		}
		s.finish(t, st, code, message)
		_ = s.removeArtifact(t.Id)
	}
	if !global.GWAF_CAN_EXPORT_DOWNLOAD_LOG {
		failure("EXPORT_DISABLED", "日志导出尚未开启")
		return
	}
	var account model.Account
	if global.GWAF_LOCAL_DB.WithContext(ctx).Where("id = ? AND tenant_id = ?", t.CreatorID, t.TenantID).First(&account).Error != nil || !logExportAccountAllowed(account) {
		failure("EXPORT_FORBIDDEN", "当前账号无导出权限")
		return
	}
	dir, e := exportTaskDir(t.Id)
	if e != nil {
		failure("EXPORT_FILE_ERROR", "导出目录不可用")
		return
	}
	var tables []string
	if json.Unmarshal([]byte(t.TablesJSON), &tables) != nil {
		failure("EXPORT_INVALID", "任务参数不可用")
		return
	}
	hi, e := time.Parse(time.RFC3339, t.EndTime)
	if e != nil {
		failure("EXPORT_INVALID", "任务时间不可用")
		return
	}
	start := ""
	var lo time.Time
	if t.StartTime != "" {
		lo, e = time.Parse(time.RFC3339, t.StartTime)
		if e != nil {
			failure("EXPORT_INVALID", "任务时间不可用")
			return
		}
		start = lo.In(time.Local).Format("2006-01-02 15:04:05")
	}
	release, releaseErr := wafdb.AcquireLogRead(ctx)
	if releaseErr != nil {
		failure("EXPORT_BUSY", "日志分区正在调整")
		return
	}
	defer release()
	sources, e := s.sources(ctx, t.TenantID, lo, hi)
	if e != nil {
		failure("EXPORT_SOURCE_LIST", "读取日志分区登记失败")
		return
	}
	cfg := global.GLOG_EXPORT_CONFIG
	gib := int64(1 << 30)
	builder, e := waflogexport.NewBuilder(ctx, waflogexport.Options{Dir: dir, Format: t.Format, Tables: tables, Key: global.GWAF_PWD_LOGDB, TaskID: t.Id, MaxBytes: int64(cfg.MaxUncompressedGiB) * gib, TempQuotaBytes: int64(cfg.TempQuotaGiB) * gib, MinFreeBytes: uint64(cfg.MinFreeGiB) * uint64(gib), Manifest: waflogexport.Manifest{ApplicationVersion: global.GWAF_RELEASE_VERSION, TaskID: t.Id, Format: t.Format, Tables: tables, RequestedStart: t.StartTime, RequestedEnd: t.EndTime, ActualStart: t.StartTime, ActualEnd: t.EndTime, Timezone: time.Local.String(), SourceDriver: dialect.Get().Name(), Consistency: "per-source read-only repeatable snapshot; sources are captured at different times"}})
	if e != nil {
		failure("EXPORT_FILE_ERROR", "无法创建导出文件，请检查配额与磁盘空间")
		return
	}
	defer func() {
		if builder != nil {
			_ = builder.Abort()
		}
	}()
	global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND status = ?", t.Id, "running").Updates(map[string]interface{}{"phase": "reading", "source_total": len(sources)})
	statuses := []waflogexport.SourceStatus{}
	success, failed := 0, 0
	for i, source := range sources {
		if ctx.Err() != nil {
			failure("EXPORT_CANCELLED", "导出已取消")
			return
		}
		var writeErr error
		st, readErr := wafdb.ReadExportSourceWithOptions(ctx, source, t.TenantID, start, hi.In(time.Local).Format("2006-01-02 15:04:05"), tables, func(batch wafdb.ExportRowBatch) error {
			if e := builder.AddBatch(batch.Table, batch.Rows); e != nil {
				writeErr = e
				return e
			}
			stats := builder.Stats()
			var rows int64
			for _, count := range stats.Counts {
				rows += count.Written
			}
			return global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND owner = ? AND status = ?", t.Id, s.owner, "running").Updates(map[string]interface{}{"rows_written": rows, "bytes_written": stats.Bytes}).Error
		}, wafdb.ExportReadOptions{MaxSQLiteWALBytes: int64(cfg.SQLiteWALMaxGiB) * gib})
		if writeErr != nil {
			failure("EXPORT_OUTPUT_FAILED", "导出文件写入失败，请检查配额和磁盘空间")
			return
		}
		if ctx.Err() != nil {
			failure("EXPORT_CANCELLED", "导出已取消")
			return
		}
		sourceID := fmt.Sprintf("source-%04d", i+1)
		if readErr != nil {
			failed++
			statuses = append(statuses, waflogexport.SourceStatus{ID: sourceID, Driver: st.Driver, Status: "failed", ErrorCode: "EXPORT_SOURCE_FAILED"})
		} else {
			for _, table := range tables {
				if ts, ok := st.Tables[table]; ok && ts.State == "ready" {
					success++
				} else {
					failed++
				}
			}
		}
		for table, ts := range st.Tables {
			statuses = append(statuses, waflogexport.SourceStatus{ID: sourceID, Driver: st.Driver, Table: table, Status: ts.State, SnapshotTime: st.SnapshotTime.Format(time.RFC3339), MissingColumns: ts.MissingColumns})
		}
		global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND owner = ? AND status = ?", t.Id, s.owner, "running").Update("source_done", i+1)
	}
	if success == 0 {
		failure("EXPORT_SOURCES_FAILED", "所有日志来源均未能完成读取")
		return
	}
	release()
	builder.SetSources(statuses)
	changed := global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND owner = ? AND status = ?", t.Id, s.owner, "running").Updates(map[string]interface{}{"status": "packaging", "phase": "packaging"})
	if changed.Error != nil || changed.RowsAffected != 1 {
		failure("EXPORT_CANCELLED", "任务状态已变化")
		return
	}
	result, e := builder.Close()
	if e != nil {
		failure("EXPORT_OUTPUT_FAILED", "导出文件打包失败，请检查配额和磁盘空间")
		return
	}
	now := time.Now()
	expires := now.Add(time.Duration(cfg.RetentionHours) * time.Hour)
	state, code, msg := "ready", "", ""
	if failed > 0 {
		state, code, msg = "partial", "EXPORT_PARTIAL", "部分日志分区读取失败，下载清单含缺失说明"
	}
	var rows int64
	for _, count := range result.Manifest.Counts {
		rows += count.Written
	}
	r := global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND owner = ? AND status = ?", t.Id, s.owner, "packaging").Updates(map[string]interface{}{"status": state, "phase": "complete", "rows_written": rows, "bytes_written": result.ZIPBytes, "artifact_key": result.WrappedKey, "artifact_name": filepath.Base(result.Path), "checksum": result.SHA256, "finished_at": now, "expires_at": expires, "error_code": code, "error_message": msg})
	if r.Error != nil || r.RowsAffected != 1 {
		failure("EXPORT_STATE_CHANGED", "任务状态已变化")
		return
	}
	builder = nil
	t.RowsWritten = rows
	t.BytesWritten = result.ZIPBytes
	s.audit(LogExportActor{LoginAccount: account.LoginAccount}, t, state, state == "ready")
	s.notifyReady(t, state)
}
func (s *WafLogExportService) sources(ctx context.Context, tenant string, lo, hi time.Time) ([]string, error) {
	var rows []model.ShareDb
	if e := global.GWAF_LOCAL_DB.WithContext(ctx).Where("tenant_id = ? AND (db_logic_type = ? OR db_logic_type = ?)", tenant, "log", "").Order("end_time desc").Find(&rows).Error; e != nil {
		return nil, e
	}
	result := []string{wafdb.LiveLogName()}
	seen := map[string]bool{wafdb.LiveLogName(): true}
	sort.SliceStable(rows, func(i, j int) bool { return time.Time(rows[i].EndTime).After(time.Time(rows[j].EndTime)) })
	for _, sh := range rows {
		if sh.FileName == "" || seen[sh.FileName] {
			continue
		}
		a, b := time.Time(sh.StartTime), time.Time(sh.EndTime)
		if !a.IsZero() && !a.Before(hi) {
			continue
		}
		if !lo.IsZero() && !b.IsZero() && b.Before(lo) {
			continue
		}
		seen[sh.FileName] = true
		result = append(result, sh.FileName)
	}
	return result, nil
}
func (s *WafLogExportService) reap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var rows []model.LogExportTask
	if global.GWAF_LOCAL_DB.Where("status NOT IN ?", exportActiveStates).Find(&rows).Error != nil {
		return
	}
	for _, t := range rows {
		if s.downloads[t.Id] > 0 {
			continue
		}
		expired := t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
		if t.Status == "failed" || t.Status == "cancelled" || t.Status == "deleted" || t.Status == "expired" || expired {
			if s.removeArtifact(t.Id) != nil {
				continue
			}
			if expired && (t.Status == "ready" || t.Status == "partial") {
				global.GWAF_LOCAL_DB.Model(&model.LogExportTask{}).Where("id = ? AND status = ?", t.Id, t.Status).Updates(map[string]interface{}{"status": "expired", "artifact_key": "", "artifact_name": ""})
			}
			if now.Sub(t.CreatedAt) > 7*24*time.Hour {
				global.GWAF_LOCAL_DB.Where("id = ? AND status NOT IN ?", t.Id, exportActiveStates).Delete(&model.LogExportTask{})
			}
		}
	}
	for k, v := range s.tickets {
		if now.After(v.Expires) {
			delete(s.tickets, k)
		}
	}
}
