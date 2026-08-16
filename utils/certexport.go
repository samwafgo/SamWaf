package utils

import (
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

// certExportReservedDirs SamWaf 自身的运行目录，禁止把证书导出到这些目录下，
// 避免用户误填路径把数据库、配置、日志覆盖掉。
var certExportReservedDirs = []string{"conf", "data", "logs", "cache", "plugins", "plugin", "exedata", "download"}

// certExportBaseDir 取 SamWaf 程序所在目录，单测里可替换。
var certExportBaseDir = GetCurrentDir

// ValidateCertExportPath 校验并规范化证书导出路径。
// 只做与文件系统状态无关的判断（是否为空、非法字符、是否绝对路径、是否落在保留目录），
// 返回规范化后的路径。路径为空返回错误，由调用方自行判空决定是否跳过。
func ValidateCertExportPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", errors.New("导出路径为空")
	}
	// 控制字符：换行会把路径截断成两段，NUL 在部分系统调用里会截断，一律拒绝
	if strings.ContainsAny(p, "\r\n\x00") {
		return "", errors.New("导出路径包含非法字符(换行或空字符)")
	}

	// 以分隔符结尾说明用户填的是目录，必须在 Clean 之前判断——Clean 会把尾部分隔符抹掉
	if os.IsPathSeparator(p[len(p)-1]) {
		return "", fmt.Errorf("导出路径必须指向具体文件，不能以路径分隔符结尾: %s", raw)
	}

	cleaned := filepath.Clean(p)

	// 必须是绝对路径：相对路径的基准目录取决于进程工作目录（服务方式启动时不可控），
	// 用户会以为写到了自己想的位置，实际落到别处。
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("导出路径必须是绝对路径: %s", raw)
	}

	// 必须以文件名结尾，不能是目录或盘符根
	base := filepath.Base(cleaned)
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) {
		return "", fmt.Errorf("导出路径必须指向具体文件: %s", raw)
	}

	// 不能写进 SamWaf 自己的运行目录
	if reserved, err := isUnderSamWafReservedDir(cleaned); err != nil {
		return "", err
	} else if reserved != "" {
		return "", fmt.Errorf("导出路径不能位于 SamWaf 自身的 %s 目录下: %s", reserved, cleaned)
	}

	return cleaned, nil
}

// isUnderSamWafReservedDir 判断路径是否落在 SamWaf 保留目录内或就是程序自身，
// 命中时返回命中的目录名（或 "程序文件"），未命中返回空串。
func isUnderSamWafReservedDir(cleaned string) (string, error) {
	baseDir := certExportBaseDir()
	if baseDir == "" || baseDir == "." {
		// IDE 调试模式下取不到有效的程序目录，不做该项判断
		return "", nil
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", nil
	}

	// 程序自身可执行文件：覆盖它等于把 SamWaf 自己写坏
	if exe, err := os.Executable(); err == nil && exe != "" {
		if pathEqual(filepath.Clean(exe), cleaned) {
			return "程序文件", nil
		}
	}

	for _, dir := range certExportReservedDirs {
		reserved := filepath.Join(absBase, dir)
		if pathEqual(reserved, cleaned) || pathUnder(reserved, cleaned) {
			return dir, nil
		}
	}
	return "", nil
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
