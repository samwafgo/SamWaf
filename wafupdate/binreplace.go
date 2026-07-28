package wafupdate

import (
	"SamWaf/common/zlog"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 二进制原地替换底座。
//
// Windows 语义前提：正在运行的 exe 允许被 rename(只改目录项)，但不允许被删除/覆盖
// ——映像段仍挂着文件对象，DeleteFile 返回 ERROR_ACCESS_DENIED。
//
// SamWaf 是 Supervisor + Worker 双进程，且 Supervisor 按设计"永不为升级退出"，
// 于是升级后 Supervisor 的映像文件就是被换下来的那个 .old、永远删不掉。
// 旧实现用固定名 ".SamWaf64.exe.old" 做 rename 目标：
//
//	升级#1 rename 成功 → .old 删不掉 → 隐藏残留
//	升级#2 rename 目标已存在且是运行中映像 → MoveFileEx 无法删除目标 → ACCESS_DENIED
//
// 所以 .old 必须"每次唯一"，rename 的目标才永不预先存在。
//
// Linux 不受影响：unlink 只摘目录项(inode 等最后一个引用释放才回收)，
// 且 rename(2) 对已存在目标是原子替换——两道关都过得去。但代码统一走这里。
//
// fromStream() 与 RollbackExecutable() 共用本文件，不要再各写一套 rename 技巧。

const (
	stageNewSuffix      = ".new"
	stageOldSuffix      = ".old"
	stageRollbackSuffix = ".rollback"

	// rename 失败多为永久性(目标被占用/权限)，少试几次尽快回错；
	// remove 失败常见于杀软/EDR/索引器对刚落盘文件的瞬时占用，可以多试。
	renameAttempts  = 3
	removeAttempts  = 5
	retryBackoff    = 120 * time.Millisecond
	retryBackoffMax = 800 * time.Millisecond

	// 清扫时跳过刚创建的 .old，避开"另一个进程正在进行替换"的竞争窗口
	// (例如服务运行中同时执行 samwaf rollback)。
	sweepSkipRecent = 60 * time.Second
	// 残留数量超过该值时告警，提示运维在维护窗口重启服务。
	sweepKeepWarn = 5
)

// stagePath 返回可执行文件同目录下的临时文件路径，形如 .SamWaf64.exe.new
func stagePath(dir, exeName, suffix string) string {
	return filepath.Join(dir, "."+exeName+suffix)
}

// oldPrefix 返回所有 .old 变体的公共前缀，形如 .SamWaf64.exe.old
func oldPrefix(exeName string) string {
	return "." + exeName + stageOldSuffix
}

// uniqueOldPath 生成一个当前目录中一定不存在的 .old 路径，形如
//
//	.SamWaf64.exe.old.20260728153012.4712
//
// 这是本模块的核心：rename 的目标永不预先存在 ⇒ MoveFileEx 无需删除目标 ⇒ 不会 ACCESS_DENIED。
func uniqueOldPath(dir, exeName string) string {
	base := filepath.Join(dir, oldPrefix(exeName))
	pid := os.Getpid()
	for i := 0; i < 50; i++ {
		p := fmt.Sprintf("%s.%s.%d", base, time.Now().Format("20060102150405"), pid)
		if i > 0 {
			p = fmt.Sprintf("%s.%d", p, i)
		}
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return p
		}
		// 同一秒内的冲突由上面的 .i 序号消解，无需等待下一秒。
	}
	// 理论上到不了这里；兜底加纳秒，保证调用方总能拿到一个路径。
	return fmt.Sprintf("%s.%d.%d", base, time.Now().UnixNano(), pid)
}

// retryFileOp 有限次重试 + 退避执行文件操作，用于对抗杀软/EDR 对刚落盘文件的瞬时占用。
// 文件不存在视为成功(删除幂等)；确定性错误立即返回，不做无谓等待。
func retryFileOp(desc string, attempts int, op func() error) error {
	backoff := retryBackoff
	var err error
	for i := 0; i < attempts; i++ {
		err = op()
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		if !isTransientFileError(err) {
			return err
		}
		if i == attempts-1 {
			break
		}
		zlog.Debug("[升级] " + desc + " 第 " + fmt.Sprint(i+1) + " 次失败，重试: " + err.Error())
		time.Sleep(backoff)
		if backoff < retryBackoffMax {
			backoff *= 2
		}
	}
	return err
}

// removeFileForce 尽力删除：先清 READONLY/HIDDEN/SYSTEM 属性(否则 Windows 上删除会被拒)，再带重试删。
func removeFileForce(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	_ = clearFileAttrs(path)
	return retryFileOp("删除 "+filepath.Base(path), removeAttempts, func() error {
		return os.Remove(path)
	})
}

// disposeOldBinary 处置被替换下来的旧二进制。
//
// 优先删除；删不掉的绝大多数情况是"仍在运行的 Supervisor 自身映像"，
// 此时隐藏它并登记重启时删除。全过程记日志——旧实现在这里丢弃了错误，
// 导致 .old 悄悄堆积、第二次升级才以 ACCESS_DENIED 的形式爆出来。
func disposeOldBinary(oldPath string) {
	err := removeFileForce(oldPath)
	if err == nil {
		zlog.Info("[升级] 旧二进制已删除: " + oldPath)
		return
	}
	zlog.Info("[升级] 旧二进制暂时删不掉(通常是常驻 Supervisor 仍映射着它): " +
		oldPath + " -> " + err.Error())

	if err := hideFile(oldPath); err != nil {
		zlog.Warn("[升级] 隐藏旧二进制失败: " + err.Error())
	}
	if err := markDeleteOnReboot(oldPath); err != nil {
		zlog.Info("[升级] 登记重启时删除失败(不影响升级): " + err.Error())
	} else {
		zlog.Info("[升级] 已登记重启时删除: " + oldPath)
	}
}

// sweepLeftovers 清扫可执行文件目录下的历史残留临时文件。
//
// includeStaging 为 true 时连 .new/.rollback 一起清(仅用于进程启动)。
// 删不掉的一律忽略，只计数，绝不阻塞调用方。
func sweepLeftovers(dir, exeName string, includeStaging bool) (removed, kept int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	// 用前缀匹配而不是 filepath.Glob——exe 名可能含 '[' 等 glob 元字符。
	oldPre := oldPrefix(exeName)
	newPath := stagePath(dir, exeName, stageNewSuffix)
	rollbackPath := stagePath(dir, exeName, stageRollbackSuffix)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(dir, e.Name())
		isOld := strings.HasPrefix(e.Name(), oldPre)
		isStaging := includeStaging && (full == newPath || full == rollbackPath)
		if !isOld && !isStaging {
			continue
		}
		// 跳过刚创建的 .old：可能是另一个进程正在进行中的替换。
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) < sweepSkipRecent {
			kept++
			continue
		}
		if err := removeFileForce(full); err != nil {
			kept++
			continue
		}
		removed++
	}
	if removed > 0 || kept > 0 {
		zlog.Info("[升级] 清扫遗留临时二进制: 删除 " + fmt.Sprint(removed) + " 个, 保留 " + fmt.Sprint(kept) + " 个")
	}
	if kept > sweepKeepWarn {
		zlog.Warn("[升级] " + dir + " 下有 " + fmt.Sprint(kept) +
			" 个删不掉的旧二进制残留，建议在维护窗口重启一次 SamWaf 服务以释放并清理")
	}
	return removed, kept
}

// CleanupLegacyLeftovers 供进程启动时调用：清扫上一轮升级/回退遗留的临时二进制。
// 幂等、不返回错误、不阻塞启动。
func CleanupLegacyLeftovers() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, e := filepath.EvalSymlinks(exePath); e == nil {
		exePath = resolved
	}
	sweepLeftovers(filepath.Dir(exePath), filepath.Base(exePath), true)
}

// replaceExecutable 用 stagedPath 处已就绪的新二进制原地替换 exePath。
// 这是升级(fromStream)与回退(RollbackExecutable)唯一共用的替换实现。
//
// 返回 (err, errRecover)：err 非空表示替换失败；errRecover 非空表示连回滚原程序都失败了(需人工介入)。
func replaceExecutable(exePath, stagedPath string) (err error, errRecover error) {
	updateDir := filepath.Dir(exePath)
	filename := filepath.Base(exePath)

	// 顺手清历史残留(不碰本次的 .new/.rollback)。删不掉的忽略。
	sweepLeftovers(updateDir, filename, false)

	// 新文件不能带 HIDDEN/READONLY，否则换上去之后主程序是隐藏/只读的。
	_ = clearFileAttrs(stagedPath)
	// 源的 READONLY 会让 rename 失败。
	_ = clearFileAttrs(exePath)

	oldPath := uniqueOldPath(updateDir, filename)

	// 把当前程序挪开。目标唯一 ⇒ 不存在"目标被占用无法覆盖"的问题。
	if e := retryFileOp("重命名当前程序", renameAttempts, func() error {
		return os.Rename(exePath, oldPath)
	}); e != nil {
		err = fmt.Errorf("%s", diagnoseFileOp("rename", exePath, oldPath, e))
		return
	}

	// 新程序就位。
	if e := retryFileOp("放置新程序", renameAttempts, func() error {
		return os.Rename(stagedPath, exePath)
	}); e != nil {
		err = fmt.Errorf("%s", diagnoseFileOp("rename", stagedPath, exePath, e))
		// 把原程序挪回来
		errRecover = os.Rename(oldPath, exePath)
		return
	}

	disposeOldBinary(oldPath)
	return nil, nil
}

// diagnoseFileOp 组装可诊断的错误说明：errno、源/目标状态、当前角色。
// 这条串最终会经 api 层拼成"升级错误:..."推给前端，故截断到 400 字符内保证可读。
func diagnoseFileOp(op, src, dst string, err error) string {
	var b strings.Builder
	b.WriteString(op)
	b.WriteString(" ")
	b.WriteString(src)
	if dst != "" {
		b.WriteString(" -> ")
		b.WriteString(dst)
	}
	b.WriteString(" 失败: ")
	b.WriteString(err.Error())
	b.WriteString(" [")
	b.WriteString(errnoName(err))
	b.WriteString(" role=")
	b.WriteString(currentRole())
	b.WriteString(" pid=")
	b.WriteString(fmt.Sprint(os.Getpid()))
	b.WriteString(" src=")
	b.WriteString(platformFileDiag(src))
	if dst != "" {
		b.WriteString(" dst=")
		b.WriteString(platformFileDiag(dst))
	}
	b.WriteString("]")

	s := b.String()
	// 完整信息进日志，前端只拿截断版。
	zlog.Error("[升级] " + s)
	// 按 rune 截断——诊断串含中文，按字节切会截出半个字符。
	if r := []rune(s); len(r) > 400 {
		s = string(r[:400]) + "..."
	}
	return s
}

// currentRole 返回当前进程角色，仅用于日志与错误诊断。
// 与 cmd/samwaf/main.go 的 parseWorkerRole 保持同一判据(扫 os.Args 找 --worker)。
func currentRole() string {
	for _, a := range os.Args[1:] {
		if a == "--worker" {
			return "Worker"
		}
	}
	return "Supervisor"
}
