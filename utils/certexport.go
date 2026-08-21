package utils

import (
	"SamWaf/global"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// 证书导出（落盘）相关的路径校验与原子写入。
//
// 场景：SamWaf 申请/续期或手工更新证书后，把证书和私钥同步写成实体文件，
// 供 nginx 等 SamWaf 之外的程序使用（issue #929）。
//
// 这里只做「纯粹的路径判断」和「安全的文件写入」两件事，不碰数据库、不打日志，
// 方便单测覆盖；编排逻辑在 service 层。设计原则是宁可不导出也不能写坏东西：
// 任何一条校验不过就返回错误，由调用方记录后继续走原有证书流程。

// certExportBaseDir 取 SamWaf 程序所在目录，单测里可替换。
var certExportBaseDir = GetCurrentDir

// CertExportKind 区分导出的是证书还是私钥，决定文件名扩展白名单。
type CertExportKind int

const (
	CertExportCert CertExportKind = iota // 证书文件，允许 .crt/.pem
	CertExportKey                        // 私钥文件，允许 .key/.pem
)

// certExportDefaultSubDir 内置默认导出目录（相对程序目录），恒允许，SamWaf 自管可自建。
const certExportDefaultSubDir = "data/ssl_export"

// 文件名扩展白名单（小写）。刻意保持很短：够 nginx 等常见用法即可，不给攻击面留花样。
var (
	certExportCertExts = []string{".crt", ".pem"}
	certExportKeyExts  = []string{".key", ".pem"}
)

// cleanAbsFilePath 只做「与文件系统状态无关」的路径规范化与基本合法性判断：
// 非空、无控制字符、非目录结尾、必须绝对、base 是具体文件名。返回 Clean 后的绝对路径。
// 不含允许目录/扩展名这类策略判断——策略在 ValidateCertExportPath。
func cleanAbsFilePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", errors.New("导出路径为空")
	}
	// 控制字符：换行会把路径截断成两段，NUL 在部分系统调用里会截断，一律拒绝
	if strings.ContainsAny(p, "\r\n\x00") {
		return "", errors.New("导出路径包含非法字符(换行或空字符)")
	}
	// 以分隔符结尾说明填的是目录，必须在 Clean 之前判断——Clean 会把尾部分隔符抹掉
	if os.IsPathSeparator(p[len(p)-1]) {
		return "", fmt.Errorf("导出路径必须指向具体文件，不能以路径分隔符结尾: %s", raw)
	}
	cleaned := filepath.Clean(p)
	// 必须是绝对路径：相对路径的基准目录取决于进程工作目录（服务方式启动时不可控）
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("导出路径必须是绝对路径: %s", raw)
	}
	base := filepath.Base(cleaned)
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) {
		return "", fmt.Errorf("导出路径必须指向具体文件: %s", raw)
	}
	return cleaned, nil
}

// certExportAllowedRoots 返回当前允许的导出根目录（已 Clean 的绝对路径）：
// 内置默认 <程序目录>/data/ssl_export（恒允许）+ config.yml security.ssl_export_allowed_dirs 声明的目录。
// 只从 config 读，不涉及 DB/API——攻击者/OpenAPI Key/普通 systemAdmin 都改不了这份清单。
func certExportAllowedRoots() []string {
	roots := make([]string, 0, 4)
	// base 可能是 "."（IDE/开发模式，GetCurrentDir 见 SamWafIDE 环境变量）或可执行文件所在目录。
	// 两种都用 filepath.Abs 归一到绝对路径：Abs(".") = 当前工作目录，与其它模块
	// filepath.Join(GetCurrentDir(), ...) 的落盘基准一致。绝不能因为 base=="." 就跳过内置根，
	// 否则开发模式下默认目录失效、空清单时一切导出被拒。
	if base := certExportBaseDir(); base != "" {
		if absBase, err := filepath.Abs(base); err == nil {
			roots = append(roots, filepath.Clean(filepath.Join(absBase, certExportDefaultSubDir)))
		}
	}
	for _, d := range strings.Split(global.GCONFIG_SSL_EXPORT_ALLOWED_DIRS, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		cleaned := filepath.Clean(d)
		if !filepath.IsAbs(cleaned) {
			continue // 只接受绝对目录，相对目录基准不可控，忽略
		}
		roots = append(roots, cleaned)
	}
	return roots
}

// hasAllowedExt 判断文件名扩展是否命中白名单（大小写不敏感）。
func hasAllowedExt(path string, exts []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range exts {
		if ext == e {
			return true
		}
	}
	return false
}

// ValidateCertExportPath 校验并规范化证书/私钥导出路径。三道关（纵深）：
//  1. 基本合法性（cleanAbsFilePath）；
//  2. 文件名扩展白名单（按 kind：证书 .crt/.pem，私钥 .key/.pem）；
//  3. 必须落在允许根目录之下（内置 data/ssl_export + config.yml 声明的目录）。
//
// 任意一关不过即拒绝，把「向宿主机任意路径写文件」收敛为「只能写进运营方声明的目录」。
func ValidateCertExportPath(raw string, kind CertExportKind) (string, error) {
	cleaned, err := cleanAbsFilePath(raw)
	if err != nil {
		return "", err
	}

	exts, kindName := certExportCertExts, "证书"
	if kind == CertExportKey {
		exts, kindName = certExportKeyExts, "私钥"
	}
	if !hasAllowedExt(cleaned, exts) {
		return "", fmt.Errorf("%s导出文件名扩展名不合法，仅允许 %s: %s", kindName, strings.Join(exts, "/"), cleaned)
	}

	for _, root := range certExportAllowedRoots() {
		if pathEqual(root, cleaned) || pathUnder(root, cleaned) {
			return cleaned, nil
		}
	}
	return "", fmt.Errorf("导出路径不在允许目录内（请使用内置 %s 目录，或在 config.yml 的 security.ssl_export_allowed_dirs 声明目标目录）: %s", certExportDefaultSubDir, cleaned)
}

// IsSameFilePath 判断两个路径是否指向同一个文件，Windows 下大小写不敏感。
// 只做字符串层面的比较，不解析软链接（软链接在写入阶段直接拒绝）。
func IsSameFilePath(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	return pathEqual(filepath.Clean(a), filepath.Clean(b))
}

// pathEqual 比较两个已 Clean 的路径是否相同，Windows 下大小写不敏感。
func pathEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// pathUnder 判断 child 是否在 parent 目录之下（parent 自身不算）。
func pathUnder(parent, child string) bool {
	prefix := parent
	if !os.IsPathSeparator(prefix[len(prefix)-1]) {
		prefix += string(filepath.Separator)
	}
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(strings.ToLower(child), strings.ToLower(prefix))
	}
	return strings.HasPrefix(child, prefix)
}

// WriteCertFileAtomic 把内容原子写入目标路径。
//   - 内容与现有文件完全一致时不重写（返回 false），避免每次任务都改动 mtime，
//     触发用户侧 inotify/reload 脚本空转。
//   - 目标已存在但不是普通文件（目录、软链接、设备）时拒绝写入：软链接会把写操作
//     引到别的文件上，是最容易误伤的一种情况。
//   - 先写同目录临时文件再 rename，外部程序不会读到写了一半的证书。
func WriteCertFileAtomic(path string, content []byte, perm os.FileMode) (bool, error) {
	if fi, err := os.Lstat(path); err == nil {
		switch {
		case fi.IsDir():
			return false, fmt.Errorf("目标已存在且是目录: %s", path)
		case fi.Mode()&os.ModeSymlink != 0:
			return false, fmt.Errorf("目标是软链接，出于安全考虑不覆盖: %s", path)
		case !fi.Mode().IsRegular():
			return false, fmt.Errorf("目标不是普通文件: %s", path)
		}
		if old, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(old, content) {
			return false, nil
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("目标文件不可访问: %s, %v", path, err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("创建导出目录失败: %s, %v", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, ".samwaf-cert-*.tmp")
	if err != nil {
		return false, fmt.Errorf("创建临时文件失败(检查目录写权限): %s, %v", dir, err)
	}
	tmpPath := tmpFile.Name()
	// 只要没走到最后的 rename 成功，临时文件都要清掉，不给用户目录留垃圾
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err = tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return false, fmt.Errorf("写入临时文件失败: %v", err)
	}
	// 私钥必须先收权限再落位，否则 rename 后会有一瞬间是 0600 之外的权限
	if err = tmpFile.Chmod(perm); err != nil {
		// Windows 上 Chmod 只影响只读位，失败不阻断
		if runtime.GOOS != "windows" {
			tmpFile.Close()
			return false, fmt.Errorf("设置文件权限失败: %v", err)
		}
	}
	if err = tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return false, fmt.Errorf("刷盘失败: %v", err)
	}
	if err = tmpFile.Close(); err != nil {
		return false, fmt.Errorf("关闭临时文件失败: %v", err)
	}

	if err = os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("写入目标文件失败(可能被占用或无权限): %s, %v", path, err)
	}
	renamed = true
	return true, nil
}
