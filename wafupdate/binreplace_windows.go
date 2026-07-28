package wafupdate

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

// clearFileAttrs 清除 READONLY / HIDDEN / SYSTEM，保留其余属性。
//
// 必要性(两条都会以 ACCESS_DENIED 的形式咬人)：
//  1. os.Remove 对 READONLY 文件返回 ACCESS_DENIED；
//  2. os.OpenFile(O_CREATE|O_TRUNC) 底层是 CreateFile(CREATE_ALWAYS)，
//     目标已存在且带 HIDDEN/SYSTEM 时直接返回 ACCESS_DENIED。
//     旧实现给删不掉的 .old 打 HIDDEN，正好踩中这条。
func clearFileAttrs(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		return err
	}
	cleared := attrs &^ (windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM)
	if cleared == attrs {
		return nil
	}
	if cleared == 0 {
		cleared = windows.FILE_ATTRIBUTE_NORMAL
	}
	return windows.SetFileAttributes(p, cleared)
}

// pendingDeleteOnReboot 按路径去重，防止同一进程反复往
// HKLM\...\PendingFileRenameOperations 里塞同一条记录。
var pendingDeleteOnReboot sync.Map

// markDeleteOnReboot 用 MoveFileEx(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)
// 登记"下次重启时删除"。需要管理员/SYSTEM 权限(服务模式满足)，
// 交互式非管理员会失败——只记日志，不影响升级结果。
func markDeleteOnReboot(path string) error {
	if _, loaded := pendingDeleteOnReboot.LoadOrStore(path, true); loaded {
		return nil
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		pendingDeleteOnReboot.Delete(path)
		return err
	}
	if err := windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		pendingDeleteOnReboot.Delete(path)
		return err
	}
	return nil
}

// isTransientFileError 判断是否为"重试有意义"的瞬时错误。
// ACCESS_DENIED 也纳入：杀软扫描期确实会短暂返回它。
// 重试次数很少(rename 3 次 / remove 5 次)，确定性失败也不会明显拖慢报错。
func isTransientFileError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.Errno(windows.ERROR_ACCESS_DENIED),
		syscall.Errno(windows.ERROR_SHARING_VIOLATION),
		syscall.Errno(windows.ERROR_LOCK_VIOLATION),
		syscall.Errno(windows.ERROR_USER_MAPPED_FILE):
		return true
	}
	return false
}

// errnoName 把底层 Windows 错误码翻成可读名，供诊断串使用。
func errnoName(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "errno=?"
	}
	name := ""
	switch errno {
	case syscall.Errno(windows.ERROR_ACCESS_DENIED):
		name = "ERROR_ACCESS_DENIED"
	case syscall.Errno(windows.ERROR_SHARING_VIOLATION):
		name = "ERROR_SHARING_VIOLATION"
	case syscall.Errno(windows.ERROR_LOCK_VIOLATION):
		name = "ERROR_LOCK_VIOLATION"
	case syscall.Errno(windows.ERROR_USER_MAPPED_FILE):
		name = "ERROR_USER_MAPPED_FILE"
	case syscall.Errno(windows.ERROR_FILE_NOT_FOUND):
		name = "ERROR_FILE_NOT_FOUND"
	case syscall.Errno(windows.ERROR_PATH_NOT_FOUND):
		name = "ERROR_PATH_NOT_FOUND"
	}
	if name == "" {
		return fmt.Sprintf("errno=%d", uintptr(errno))
	}
	return fmt.Sprintf("errno=%d(%s)", uintptr(errno), name)
}

// platformFileDiag 返回路径的诊断细节：是否存在、属性位、是否疑似被占用。
func platformFileDiag(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "路径无效"
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return "不存在"
	}
	s := fmt.Sprintf("存在/attrs=0x%x", attrs)
	// 以"允许删除"的共享模式试开一次：打不开基本可判定被别的进程(或映像段)占着。
	h, err := windows.CreateFile(p, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return s + "/被占用(" + err.Error() + ")"
	}
	_ = windows.CloseHandle(h)
	return s
}
