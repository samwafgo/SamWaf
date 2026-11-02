package wafapppath

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultAllowedDir 配置为空时使用的默认应用根目录
const DefaultAllowedDir = "data/applications"

// codePattern 应用 code 的合法字符集：UUID 与常规安全格式，天然排除路径分隔符与 ..
var codePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Preview 目录解析预览结果（API 固定契约，也供引擎复用）
type Preview struct {
	DefaultDir  string   `json:"default_dir"`
	ResolvedDir string   `json:"resolved_dir"`
	AllowedDirs []string `json:"allowed_dirs"`
	PathBase    string   `json:"path_base"`
	Valid       bool     `json:"valid"`
	Error       string   `json:"error"`
}

// IsSafeCode 校验应用 code 是否为 UUID 或已有安全格式（无目录穿越风险）
func IsSafeCode(code string) bool {
	return codePattern.MatchString(code)
}

// ParseAllowedDirs 解析逗号分隔的允许目录列表，空配置回退默认目录
func ParseAllowedDirs(dirStr string) []string {
	var result []string
	for _, p := range strings.Split(dirStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		result = []string{DefaultAllowedDir}
	}
	return result
}

// absAllowed 将允许目录条目转为绝对路径（以进程 cwd 为基准）
func absAllowed(p string) (string, error) {
	return filepath.Abs(filepath.Clean(p))
}

// DefaultDir 计算空 app_dir 时按「允许根首项 + code」派生的默认目录（绝对路径）
func DefaultDir(code, allowedDirs string) (string, error) {
	if !IsSafeCode(code) {
		return "", fmt.Errorf("应用编号格式不合法")
	}
	abs, err := absAllowed(ParseAllowedDirs(allowedDirs)[0])
	if err != nil {
		return "", err
	}
	return filepath.Join(abs, code), nil
}

// Resolve 统一解析应用目录（预检与保存共用，不做任何磁盘写入）：
// app_dir 为空取允许根首项+code；显式路径按进程 cwd 取绝对路径后必须在允许根之内。
// 结果非法时 Valid=false 并给出 Error，ResolvedDir 仍回显实际解析路径便于前端展示。
func Resolve(code, appDir, allowedDirs string) Preview {
	p := Preview{Valid: true}

	allowed := ParseAllowedDirs(allowedDirs)
	p.AllowedDirs = allowed

	defDir, err := DefaultDir(code, allowedDirs)
	if err != nil {
		p.Valid = false
		p.Error = "无法解析默认应用目录: " + err.Error()
		return p
	}
	p.DefaultDir = defDir

	if !IsSafeCode(code) {
		p.Valid = false
		p.Error = "应用编号格式不合法"
		return p
	}

	if appDir == "" {
		p.ResolvedDir = defDir
		if base, err2 := absAllowed(allowed[0]); err2 == nil {
			p.PathBase = base
		}
		return p
	}

	absPath, err := filepath.Abs(filepath.Clean(appDir))
	if err != nil {
		p.Valid = false
		p.Error = "无法解析应用目录路径: " + err.Error()
		return p
	}
	p.ResolvedDir = absPath

	for _, allowedDir := range allowed {
		allowedAbs, err2 := absAllowed(allowedDir)
		if err2 != nil {
			continue
		}
		rel, err3 := filepath.Rel(allowedAbs, absPath)
		if err3 == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			p.PathBase = allowedAbs
			return p
		}
	}
	p.Valid = false
	p.Error = fmt.Sprintf("应用目录必须在允许范围内（%s）", strings.Join(allowed, ","))
	return p
}
