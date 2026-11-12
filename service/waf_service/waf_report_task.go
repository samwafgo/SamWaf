package waf_service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/utils/filelease"
	"SamWaf/wafreport"
	"SamWaf/wafsec"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const reportMaxBytes = 8 << 20
const reportMaxRetry = 3

var reportIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,64}$`)
var ErrReportForbidden = errors.New("仅超级管理员可操作全实例报告")

type ReportActor struct {
	LoginAccount, UserRole, ClientIP string
	IsOpenAPI                        bool
}
type WafReportService struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	wake      chan struct{}
	lease     *filelease.Lease
	collector wafreport.Collector
	renderer  wafreport.Renderer
	root      string
}

var WafReportServiceApp = &WafReportService{}

func (s *WafReportService) authorize(ctx context.Context, a ReportActor) error {
	if a.IsOpenAPI || a.UserRole != enums.ROLE_SUPER_ADMIN || a.LoginAccount == "" {
		return ErrReportForbidden
	}
	if global.GWAF_LOCAL_DB == nil {
		return errors.New("数据库暂不可用")
	}
	var account model.Account
	err := global.GWAF_LOCAL_DB.WithContext(ctx).Where("tenant_id = ? AND login_account = ?", global.GWAF_TENANT_ID, a.LoginAccount).First(&account).Error
	if err != nil || account.Id == "" || account.Role != enums.ROLE_SUPER_ADMIN || (account.Status != 0 && account.Status != 1) {
		return ErrReportForbidden
	}
	return nil
}
func reportDB(ctx context.Context) *gorm.DB { return global.GWAF_LOCAL_DB.WithContext(ctx) }
func encodeReportConfig(c wafreport.Config) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return wafsec.DataEncrypt(string(b))
}
func decodeReportConfig(cipher string) (wafreport.Config, error) {
	var c wafreport.Config
	if !wafsec.IsDataKeyCiphertext(cipher) {
		return c, errors.New("报告配置格式不正确")
	}
	plain, err := wafsec.DataDecrypt(cipher, nil)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal([]byte(plain), &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func (s *WafReportService) settings(ctx context.Context) (model.SecurityReportSettings, wafreport.Config, error) {
	var row model.SecurityReportSettings
	err := reportDB(ctx).Where("tenant_id = ?", global.GWAF_TENANT_ID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c := wafreport.DefaultConfig()
		enc, e := encodeReportConfig(c)
		if e != nil {
			return row, c, e
		}
		row = model.SecurityReportSettings{TenantID: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE, SettingsCipher: enc, StartedAt: time.Now().Unix(), Revision: 1}
		if e = reportDB(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; e != nil {
			return row, c, e
		}
		if e = reportDB(ctx).Where("tenant_id = ?", global.GWAF_TENANT_ID).First(&row).Error; e != nil {
			return row, c, e
		}
	} else if err != nil {
		return row, wafreport.Config{}, err
	}
	c, err := decodeReportConfig(row.SettingsCipher)
	return row, c, err
}
func (s *WafReportService) Config(ctx context.Context, a ReportActor) (map[string]interface{}, error) {
	if err := s.authorize(ctx, a); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, c, err := s.settings(ctx)
	if err != nil {
		return nil, errors.New("报告配置读取失败")
	}
	b, _ := json.Marshal(c)
	out := map[string]interface{}{}
	_ = json.Unmarshal(b, &out)
	now := time.Now()
	zone, offset := now.Zone()
	out["timezone"] = zone
	out["timezone_offset"] = offset
	out["server_time"] = now.Unix()
	return out, nil
}
func (s *WafReportService) SaveConfig(ctx context.Context, a ReportActor, c wafreport.Config) error {
	if err := s.authorize(ctx, a); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, old, err := s.settings(ctx)
	if err != nil {
		return errors.New("报告配置读取失败")
	}
	enc, err := encodeReportConfig(c)
	if err != nil {
		return errors.New("报告配置加密失败")
	}
	started := row.StartedAt
	if !old.Enabled && c.Enabled {
		started = time.Now().Unix()
	}
	res := reportDB(ctx).Model(&model.SecurityReportSettings{}).Where("tenant_id = ? AND user_code = ? AND revision = ?", row.TenantID, global.GWAF_USER_CODE, row.Revision).Updates(map[string]interface{}{"settings_cipher": enc, "started_at": started, "revision": row.Revision + 1})
	if res.Error != nil {
		return errors.New("报告配置保存失败")
	}
	if res.RowsAffected != 1 {
		return errors.New("报告配置已更新，请刷新后重试")
	}
	s.audit(a, "settings", "")
	s.signal()
	return nil
}
func (s *WafReportService) List(ctx context.Context, a ReportActor, page, size int) (map[string]interface{}, error) {
	if err := s.authorize(ctx, a); err != nil {
		return nil, err
	}
	if page < 1 || page > 1000000 || size < 1 || size > 100 {
		return nil, errors.New("分页参数超出范围")
	}
	var total int64
	var rows []model.SecurityReportTask
	countDB := reportDB(ctx).Model(&model.SecurityReportTask{}).Where("tenant_id = ? AND status <> ?", global.GWAF_TENANT_ID, "deleted")
	if err := countDB.Count(&total).Error; err != nil {
		return nil, errors.New("任务读取失败")
	}
	findDB := reportDB(ctx).Model(&model.SecurityReportTask{}).Where("tenant_id = ? AND status <> ?", global.GWAF_TENANT_ID, "deleted")
	if err := findDB.Order("created_at DESC, id DESC").Offset((page - 1) * size).Limit(size).Find(&rows).Error; err != nil {
		return nil, errors.New("任务读取失败")
	}
	return map[string]interface{}{"list": rows, "total": total}, nil
}
func (s *WafReportService) Create(ctx context.Context, a ReportActor, kind, date string) (model.SecurityReportTask, error) {
	var task model.SecurityReportTask
	if err := s.authorize(ctx, a); err != nil {
		return task, err
	}
	anchor, err := time.ParseInLocation("2006-01-02", date, time.Local)
	if err != nil {
		return task, errors.New("日期须为 YYYY-MM-DD")
	}
	r, err := wafreport.NewRange(wafreport.Kind(kind), anchor)
	if err != nil {
		return task, errors.New("报告周期不正确")
	}
	if r.End.After(time.Now()) || r.Start.Year() < 2000 {
		return task, errors.New("请选择已结束的自然日、周或月")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel == nil {
		return task, errors.New("报告执行器尚未就绪")
	}
	_, c, err := s.settings(ctx)
	if err != nil {
		return task, errors.New("报告配置读取失败")
	}
	task, err = s.enqueue(ctx, wafreport.Kind(kind), r, c, "manual")
	if err == nil {
		s.audit(a, "create", task.ID)
		s.signal()
	}
	return task, err
}
func (s *WafReportService) enqueue(ctx context.Context, kind wafreport.Kind, r wafreport.Range, c wafreport.Config, source string) (model.SecurityReportTask, error) {
	t := model.SecurityReportTask{}
	var count int64
	if err := reportDB(ctx).Model(&t).Where("tenant_id = ? AND status IN ?", global.GWAF_TENANT_ID, []string{"queued", "running"}).Count(&count).Error; err != nil {
		return t, errors.New("任务队列不可用")
	}
	if count >= 8 {
		return t, errors.New("报告队列已满，请稍后重试")
	}
	enc, err := encodeReportConfig(c)
	if err != nil {
		return t, errors.New("报告配置加密失败")
	}
	// 同一周期全局唯一：手动与定时共用周期哈希，重复创建返回既有任务；失败/过期任务按来源决定是否重排。
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d:%d:v1", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, kind, r.Start.Unix(), r.End.Unix())))
	dedup := hex.EncodeToString(sum[:])
	t = model.SecurityReportTask{ID: uuid.GenUUID(), TenantID: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE, DedupKey: dedup, Kind: string(kind), RangeStart: r.Start.Unix(), RangeEnd: r.End.Unix(), CreatedAt: time.Now().Unix(), Status: "queued", Source: source, ConfigCipher: enc}
	res := reportDB(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&t)
	if res.Error != nil {
		return t, errors.New("任务创建失败")
	}
	if res.RowsAffected == 0 {
		var old model.SecurityReportTask
		if err := reportDB(ctx).Where("dedup_key = ?", dedup).First(&old).Error; err != nil {
			return t, errors.New("任务创建失败")
		}
		if old.Status != "failed" && old.Status != "expired" && old.Status != "deleted" {
			return old, nil
		}
		if old.Status == "deleted" && source != "manual" {
			return old, nil
		}
		if source != "manual" && old.RetryCount >= reportMaxRetry {
			return old, nil
		}
		retry := old.RetryCount
		if source == "manual" {
			retry = 0
		}
		res = reportDB(ctx).Model(&model.SecurityReportTask{}).Where("id = ? AND tenant_id = ? AND user_code = ? AND status IN ?", old.ID, old.TenantID, old.UserCode, []string{"failed", "expired", "deleted"}).Updates(map[string]interface{}{"status": "queued", "source": source, "error_message": "", "config_cipher": enc, "created_at": time.Now().Unix(), "completed_at": int64(0), "retry_count": retry, "size_bytes": int64(0), "artifact_key": ""})
		if res.Error != nil {
			return old, errors.New("任务重排失败")
		}
		if res.RowsAffected == 0 {
			return old, nil
		}
		old.Status = "queued"
		old.Source = source
		old.ErrorMessage = ""
		old.ConfigCipher = enc
		old.CreatedAt = time.Now().Unix()
		old.CompletedAt = 0
		old.RetryCount = retry
		old.SizeBytes = 0
		old.ArtifactKey = ""
		return old, nil
	}
	return t, nil
}
func (s *WafReportService) audit(a ReportActor, action, id string) {
	WafSecurityAuditServiceApp.Write(AuditEntry{Event: model.AuditEventConfigReport, AccountName: a.LoginAccount, ClientIP: a.ClientIP, Result: model.AccessAuditOK, Message: "action=" + action + " report=" + id})
}
func (s *WafReportService) signal() {
	if s.wake != nil {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

func (s *WafReportService) Start(collector wafreport.Collector) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return nil
	}
	if global.GWAF_LOCAL_DB == nil {
		return errors.New("报告数据库暂不可用")
	}
	root, err := filepath.Abs(filepath.Join(utils.GetCurrentDir(), "data", "security_report"))
	if err != nil {
		return err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	actual, err := filepath.EvalSymlinks(root)
	if err != nil || filepath.Clean(actual) != filepath.Clean(root) {
		return errors.New("报告目录须为本地固定目录")
	}
	lockctx, cancelLock := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelLock()
	lease, err := filelease.AcquireExclusive(lockctx, filepath.Join(filepath.Dir(root), ".samwaf_report_executor.lock"))
	if err != nil {
		return err
	}
	if _, _, err = s.settings(context.Background()); err != nil {
		lease.Release()
		return err
	}
	// 独占执行锁后，接续排队任务并结束上次中断的生成。
	if err = global.GWAF_LOCAL_DB.Model(&model.SecurityReportTask{}).Where("tenant_id = ? AND user_code = ? AND status = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, "running").Updates(map[string]interface{}{"status": "failed", "error_message": "生成已中断，可手动重新生成", "completed_at": time.Now().Unix()}).Error; err != nil {
		lease.Release()
		return err
	}
	s.root = root
	s.lease = lease
	s.collector = collector
	s.renderer = wafreport.NewHTMLRenderer()
	s.wake = make(chan struct{}, 1)
	s.done = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go s.loop(ctx)
	return nil
}
func (s *WafReportService) Stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
	s.mu.Lock()
	s.cancel = nil
	s.mu.Unlock()
}
func (s *WafReportService) loop(ctx context.Context) {
	defer close(s.done)
	defer s.lease.Release()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		s.maintain(ctx)
		s.schedule(ctx, time.Now())
		s.mu.Unlock()
		for ctx.Err() == nil {
			var t model.SecurityReportTask
			err := reportDB(ctx).Where("tenant_id = ? AND status = ?", global.GWAF_TENANT_ID, "queued").Order("created_at ASC, id ASC").First(&t).Error
			if err != nil {
				break
			}
			s.run(ctx, t)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
	}
}
func (s *WafReportService) schedule(ctx context.Context, now time.Time) {
	row, c, err := s.settings(ctx)
	if err != nil {
		zlog.Error("报告设置读取失败")
		return
	}
	for _, kind := range []wafreport.Kind{"daily", "weekly", "monthly"} {
		if r, due := wafreport.DueRange(kind, now, time.Unix(row.StartedAt, 0), c); due {
			if _, err = s.enqueue(ctx, kind, r, c, "schedule"); err != nil {
				zlog.Error("报告任务排队失败")
			}
		}
	}
}
func (s *WafReportService) path(id string) (string, error) {
	if !reportIDPattern.MatchString(id) {
		return "", errors.New("报告编号不正确")
	}
	root := filepath.Clean(s.root)
	if root == "." || !filepath.IsAbs(root) {
		return "", errors.New("报告目录未就绪")
	}
	actual, err := filepath.EvalSymlinks(root)
	if err != nil || filepath.Clean(actual) != root {
		return "", errors.New("报告目录不可用")
	}
	path := filepath.Clean(filepath.Join(root, id+".swr"))
	if filepath.Dir(path) != root {
		return "", errors.New("报告路径不正确")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("报告文件类型不正确")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return path, nil
}

type reportBuffer struct{ bytes.Buffer }

func (b *reportBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > reportMaxBytes {
		return 0, errors.New("报告超过大小上限")
	}
	return b.Buffer.Write(p)
}
func (s *WafReportService) run(parent context.Context, t model.SecurityReportTask) {
	res := reportDB(parent).Model(&t).Where("status = ?", "queued").Update("status", "running")
	if res.Error != nil || res.RowsAffected != 1 {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	var failure error
	defer func() {
		if r := recover(); r != nil {
			failure = errors.New("报告生成未完成")
		}
		if failure != nil {
			retries := t.RetryCount + 1
			msg := "报告生成未完成，请重试或检查数据源"
			if retries >= reportMaxRetry {
				msg = "报告生成多次未完成，已停止自动重试，可在报告中心手动重新生成"
			}
			_ = global.GWAF_LOCAL_DB.Model(&model.SecurityReportTask{}).Where("id = ? AND status = ?", t.ID, "running").Updates(map[string]interface{}{"status": "failed", "error_message": msg, "completed_at": time.Now().Unix(), "retry_count": retries}).Error
			zlog.Error("报告生成未完成", "report", t.ID)
			if retries >= reportMaxRetry {
				s.notifyFailure(t)
			}
		}
	}()
	c, err := decodeReportConfig(t.ConfigCipher)
	if err != nil {
		failure = err
		return
	}
	req := wafreport.Request{Kind: wafreport.Kind(t.Kind), Range: wafreport.Range{Start: time.Unix(t.RangeStart, 0).In(time.Local), End: time.Unix(t.RangeEnd, 0).In(time.Local)}, Locale: c.Language, GeneratedAt: time.Now(), TopN: c.TopN, ID: t.ID}
	report, err := s.collector.Collect(ctx, req)
	if err != nil {
		failure = err
		return
	}
	var content reportBuffer
	if err = s.renderer.Render(ctx, &content, report); err != nil {
		failure = err
		return
	}
	if err = ctx.Err(); err != nil {
		failure = err
		return
	}
	s.mu.Lock()
	path, err := s.path(t.ID)
	if err == nil {
		err = s.writeArtifact(path, t.ID, content.Bytes(), &t.ArtifactKey)
	}
	if err == nil {
		status := "completed"
		if string(report.Status) != "ok" {
			status = "partial"
		}
		err = reportDB(ctx).Model(&model.SecurityReportTask{}).Where("id = ? AND status = ?", t.ID, "running").Updates(map[string]interface{}{"status": status, "completed_at": time.Now().Unix(), "size_bytes": int64(content.Len()), "artifact_key": t.ArtifactKey}).Error
		if err != nil {
			_ = os.Remove(path)
		}
	}
	s.mu.Unlock()
	if err != nil {
		failure = err
		return
	}
	s.audit(ReportActor{LoginAccount: "system"}, "generated", t.ID)
	s.notify(t, report)
}
func (s *WafReportService) writeArtifact(path, id string, plain []byte, wrapped *string) error {
	key, envelope, err := wafsec.NewStreamKey()
	if err != nil {
		return err
	}
	defer clear(key)
	f, err := os.CreateTemp(s.root, ".report-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	writer, err := wafsec.NewStreamWriter(f, key, id)
	if err == nil {
		_, err = writer.Write(plain)
	}
	if err == nil {
		err = writer.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	*wrapped = envelope
	return nil
}
func (s *WafReportService) Download(ctx context.Context, a ReportActor, id string) ([]byte, error) {
	if err := s.authorize(ctx, a); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.Status != "completed" && t.Status != "partial" {
		return nil, errors.New("报告尚未就绪或已过期")
	}
	path, err := s.path(id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("报告产物不可用")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > reportMaxBytes+(1<<20) {
		return nil, errors.New("报告产物大小不正确")
	}
	key, err := wafsec.UnwrapStreamKey(t.ArtifactKey)
	if err != nil {
		return nil, errors.New("报告解密失败")
	}
	defer clear(key)
	reader, err := wafsec.NewStreamReader(f, key, id)
	if err != nil {
		return nil, errors.New("报告解密失败")
	}
	b, err := io.ReadAll(io.LimitReader(reader, reportMaxBytes+1))
	if err != nil || len(b) > reportMaxBytes {
		return nil, errors.New("报告完整性校验失败")
	}
	s.audit(a, "download", id)
	return b, nil
}
func (s *WafReportService) find(ctx context.Context, id string) (model.SecurityReportTask, error) {
	var t model.SecurityReportTask
	if !reportIDPattern.MatchString(id) {
		return t, errors.New("报告编号不正确")
	}
	if err := reportDB(ctx).Where("id = ? AND tenant_id = ?", id, global.GWAF_TENANT_ID).First(&t).Error; err != nil {
		return t, errors.New("报告任务不存在")
	}
	return t, nil
}
func (s *WafReportService) Delete(ctx context.Context, a ReportActor, id string) error {
	if err := s.authorize(ctx, a); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.find(ctx, id)
	if err != nil {
		return err
	}
	if t.Status == "running" || t.Status == "queued" {
		return errors.New("生成中的报告暂不能删除")
	}
	if err = s.clearArtifact(ctx, t, "deleted"); err != nil {
		return errors.New("报告删除未完成")
	}
	s.audit(a, "delete", id)
	return nil
}
func (s *WafReportService) expire(ctx context.Context, t model.SecurityReportTask) error {
	return s.clearArtifact(ctx, t, "expired")
}

func (s *WafReportService) clearArtifact(ctx context.Context, t model.SecurityReportTask, status string) error {
	path, err := s.path(t.ID)
	if err != nil {
		return err
	}
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return reportDB(ctx).Model(&model.SecurityReportTask{}).Where("id = ? AND tenant_id = ? AND user_code = ?", t.ID, t.TenantID, t.UserCode).Updates(map[string]interface{}{"status": status, "size_bytes": 0, "artifact_key": "", "config_cipher": ""}).Error
}
func (s *WafReportService) maintain(ctx context.Context) {
	_, c, err := s.settings(ctx)
	if err != nil {
		return
	}
	var rows []model.SecurityReportTask
	if err = reportDB(ctx).Where("tenant_id = ? AND status IN ?", global.GWAF_TENANT_ID, []string{"completed", "partial", "failed"}).Order("created_at ASC, id ASC").Find(&rows).Error; err != nil {
		return
	}
	var size int64
	for _, t := range rows {
		size += t.SizeBytes
	}
	cutoff := time.Now().AddDate(0, 0, -c.RetainDays).Unix()
	for _, t := range rows {
		if t.CreatedAt < cutoff || size > int64(c.QuotaMB)*(1<<20) {
			if s.expire(ctx, t) == nil {
				size -= t.SizeBytes
			}
		}
	}
}
