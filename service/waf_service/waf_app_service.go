package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/model/wafappmodel"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type WafAppService struct{}

var WafAppServiceApp = new(WafAppService)

// envBlacklist 禁止用户注入的环境变量键（可劫持进程/动态链接库行为）
var envBlacklist = map[string]struct{}{
	"LD_PRELOAD":            {},
	"LD_LIBRARY_PATH":       {},
	"LD_AUDIT":              {},
	"DYLD_INSERT_LIBRARIES": {},
	"DYLD_LIBRARY_PATH":     {},
	"LD_PRELOAD_ONCE":       {},
}

// parseAllowedDirs 解析逗号分隔的允许目录列表
func parseAllowedDirs(dirStr string) []string {
	var result []string
	for _, p := range strings.Split(dirStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		result = []string{"data/applications"}
	}
	return result
}

// resolveSafeAppDir 将用户提供的 appDir 解析并校验必须落在允许目录之一下
func resolveSafeAppDir(code, appDir string) (string, error) {
	allowedDirs := parseAllowedDirs(global.GWAF_APP_ALLOW_DIRS)
	if appDir == "" {
		return filepath.Join(allowedDirs[0], code), nil
	}
	absPath, err := filepath.Abs(filepath.Clean(appDir))
	if err != nil {
		return "", fmt.Errorf("无法解析应用目录路径: %w", err)
	}
	for _, allowed := range allowedDirs {
		allowedAbs, err2 := filepath.Abs(filepath.Clean(allowed))
		if err2 != nil {
			continue
		}
		rel, err3 := filepath.Rel(allowedAbs, absPath)
		if err3 == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			return absPath, nil
		}
	}
	return "", fmt.Errorf("应用目录必须在允许范围内（%s）", global.GWAF_APP_ALLOW_DIRS)
}

// validateEnv 校验用户提供的环境变量格式并拦截黑名单键
func validateEnv(env string) error {
	if env == "" {
		return nil
	}
	for _, part := range strings.Split(env, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eqIdx := strings.IndexByte(part, '=')
		if eqIdx <= 0 {
			return fmt.Errorf("环境变量格式错误（需为 KEY=VALUE）: %s", part)
		}
		key := strings.ToUpper(part[:eqIdx])
		if _, blocked := envBlacklist[key]; blocked {
			return fmt.Errorf("不允许设置环境变量 %s（存在安全风险）", part[:eqIdx])
		}
	}
	return nil
}

func (s *WafAppService) AddApi(req request.WafAppAddReq) (*model.WafApp, error) {
	if req.Name == "" {
		return nil, errors.New("应用名称不能为空")
	}
	if req.StartCmd == "" {
		return nil, errors.New("启动命令不能为空")
	}
	if err := validateEnv(req.Env); err != nil {
		return nil, err
	}

	bean := &model.WafApp{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Code:            req.Code,
		Name:            req.Name,
		AppDir:          req.AppDir,
		StartCmd:        req.StartCmd,
		Env:             req.Env,
		AutoStart:       req.AutoStart,
		StartStatus:     req.StartStatus,
		StopMode:        req.StopMode,
		StopCmd:         req.StopCmd,
		StopTimeout:     req.StopTimeout,
		RestartPolicy:   req.RestartPolicy,
		RestartDelay:    req.RestartDelay,
		MaxRestartCount: req.MaxRestartCount,
		LogMaxLines:     req.LogMaxLines,
		Remarks:         req.Remarks,
	}
	if bean.Code == "" {
		bean.Code = bean.Id
	}
	if bean.StopMode == "" {
		bean.StopMode = "signal"
	}
	if bean.RestartPolicy == "" {
		bean.RestartPolicy = "no"
	}
	if bean.StopTimeout == 0 {
		bean.StopTimeout = 30
	}
	if bean.LogMaxLines == 0 {
		bean.LogMaxLines = 1000
	}

	safeDir, err := resolveSafeAppDir(bean.Code, bean.AppDir)
	if err != nil {
		return nil, err
	}
	bean.AppDir = safeDir

	if err := os.MkdirAll(bean.AppDir, 0755); err != nil {
		zlog.Warn("创建应用目录失败", "dir", bean.AppDir, "err", err.Error())
	}

	if err := global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
		return nil, err
	}
	return bean, nil
}

func (s *WafAppService) CheckIsExist(name string) int {
	var total int64
	global.GWAF_LOCAL_DB.Model(&model.WafApp{}).Where("name = ?", name).Count(&total)
	return int(total)
}

func (s *WafAppService) ModifyApi(req request.WafAppEditReq) error {
	var total int64
	global.GWAF_LOCAL_DB.Model(&model.WafApp{}).Where("name = ? AND id != ?", req.Name, req.Id).Count(&total)
	if total > 0 {
		return errors.New("应用名称已存在")
	}
	if err := validateEnv(req.Env); err != nil {
		return err
	}

	var existing model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&existing).Error; err != nil {
		return errors.New("应用不存在")
	}
	safeDir, err := resolveSafeAppDir(existing.Code, req.AppDir)
	if err != nil {
		return err
	}

	updates := map[string]interface{}{
		"name":              req.Name,
		"app_dir":           safeDir,
		"start_cmd":         req.StartCmd,
		"env":               req.Env,
		"auto_start":        req.AutoStart,
		"start_status":      req.StartStatus,
		"stop_mode":         req.StopMode,
		"stop_cmd":          req.StopCmd,
		"stop_timeout":      req.StopTimeout,
		"restart_policy":    req.RestartPolicy,
		"restart_delay":     req.RestartDelay,
		"max_restart_count": req.MaxRestartCount,
		"log_max_lines":     req.LogMaxLines,
		"remarks":           req.Remarks,
		"update_time":       customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(&model.WafApp{}).Where("id = ?", req.Id).Updates(updates).Error
}

func (s *WafAppService) DelApi(req request.WafAppDelReq) error {
	return global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(&model.WafApp{}).Error
}

func (s *WafAppService) GetDetailApi(req request.WafAppDetailReq) *model.WafApp {
	var bean model.WafApp
	global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean)
	return &bean
}

func (s *WafAppService) GetDetailByCodeApi(code string) *model.WafApp {
	var bean model.WafApp
	global.GWAF_LOCAL_DB.Where("code = ?", code).First(&bean)
	return &bean
}

func (s *WafAppService) GetListApi(req request.WafAppSearchReq) ([]model.WafApp, int64) {
	var list []model.WafApp
	var total int64
	global.GWAF_LOCAL_DB.Model(&model.WafApp{}).Count(&total)
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	pageIndex := req.PageIndex
	if pageIndex <= 0 {
		pageIndex = 1
	}
	global.GWAF_LOCAL_DB.Limit(pageSize).Offset((pageIndex - 1) * pageSize).Find(&list)
	return list, total
}

// UploadFile 上传文件并校验 SHA256
func (s *WafAppService) UploadFile(code string, filename string, src io.Reader, expectedHash string) error {
	var app model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("code = ?", code).First(&app).Error; err != nil {
		return fmt.Errorf("应用不存在: %s", code)
	}
	appDir, err := resolveSafeAppDir(app.Code, app.AppDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return err
	}

	// 安全文件名，防止路径穿越
	safeFilename := filepath.Base(filename)
	destPath := filepath.Join(appDir, safeFilename)

	tmpPath := destPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer func() { os.Remove(tmpPath) }()

	h := sha256.New()
	writer := io.MultiWriter(f, h)
	if _, err := io.Copy(writer, src); err != nil {
		f.Close()
		return fmt.Errorf("写入文件失败: %w", err)
	}
	f.Close()

	actualHash := hex.EncodeToString(h.Sum(nil))
	if expectedHash != "" && !equalIgnoreCase(actualHash, expectedHash) {
		return fmt.Errorf("文件哈希校验失败，期望: %s，实际: %s", expectedHash, actualHash)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("保存文件失败: %w", err)
	}
	return nil
}

// UpgradeApp 升级应用：备份当前文件后替换
func (s *WafAppService) UpgradeApp(code string, filename string, src io.Reader, expectedHash string) error {
	var app model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("code = ?", code).First(&app).Error; err != nil {
		return fmt.Errorf("应用不存在: %s", code)
	}
	appDir, err := resolveSafeAppDir(app.Code, app.AppDir)
	if err != nil {
		return err
	}
	safeFilename := filepath.Base(filename)
	destPath := filepath.Join(appDir, safeFilename)

	// 备份已有文件
	if _, err := os.Stat(destPath); err == nil {
		backupDir := filepath.Join(appDir, "backup")
		if err2 := os.MkdirAll(backupDir, 0755); err2 == nil {
			backupName := safeFilename + "." + time.Now().Format("20060102150405")
			backupPath := filepath.Join(backupDir, backupName)
			if copyErr := copyFile(destPath, backupPath); copyErr != nil {
				// 备份失败时移除不完整的空文件，不阻断升级
				os.Remove(backupPath)
				zlog.Warn("备份文件失败，继续升级", "file", destPath, "error", copyErr.Error())
			}
		}
	}

	return s.UploadFile(code, filename, src, expectedHash)
}

// RollbackApp 回滚到备份文件
func (s *WafAppService) RollbackApp(code string, backupFilename string) error {
	var app model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("code = ?", code).First(&app).Error; err != nil {
		return fmt.Errorf("应用不存在: %s", code)
	}
	appDir, err := resolveSafeAppDir(app.Code, app.AppDir)
	if err != nil {
		return err
	}
	safeBackup := filepath.Base(backupFilename)
	backupPath := filepath.Join(appDir, "backup", safeBackup)

	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("备份文件不存在: %s", safeBackup)
	}

	// 从备份文件名推断原文件名（去掉时间戳后缀 .20060102150405）
	origName := safeBackup
	if len(safeBackup) > 15 {
		origName = safeBackup[:len(safeBackup)-15]
	}
	destPath := filepath.Join(appDir, origName)

	return copyFile(backupPath, destPath)
}

// ListBackups 列出备份文件
func (s *WafAppService) ListBackups(code string) ([]wafappmodel.BackupInfo, error) {
	var app model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("code = ?", code).First(&app).Error; err != nil {
		return nil, fmt.Errorf("应用不存在: %s", code)
	}
	appDir, err := resolveSafeAppDir(app.Code, app.AppDir)
	if err != nil {
		return nil, err
	}
	backupDir := filepath.Join(appDir, "backup")
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []wafappmodel.BackupInfo{}, nil
		}
		return nil, err
	}

	var result []wafappmodel.BackupInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(backupDir, entry.Name())
		info, err2 := os.Stat(fullPath)
		if err2 != nil {
			continue
		}
		result = append(result, wafappmodel.BackupInfo{
			Filename:  entry.Name(),
			Size:      info.Size(),
			CreatedAt: info.ModTime().Format("2006-01-02 15:04:05"),
		})
	}
	return result, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func equalIgnoreCase(a, b string) bool {
	return strings.EqualFold(a, b)
}
