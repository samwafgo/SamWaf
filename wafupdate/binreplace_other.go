//go:build !windows
// +build !windows

package wafupdate

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// 非 Windows 平台不需要属性清理：POSIX 下 unlink 只摘目录项，
// rename(2) 对已存在目标是原子替换，都不会因"文件在用"而失败。
func clearFileAttrs(path string) error { return nil }

// markDeleteOnReboot 是 Windows 专有能力(PendingFileRenameOperations)。
// 其他平台用不到——旧二进制在这里本来就能立刻删掉。
func markDeleteOnReboot(path string) error {
	return errors.New("当前平台不支持重启时删除")
}

// isTransientFileError 判断是否为"重试有意义"的瞬时错误。
func isTransientFileError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EBUSY, syscall.ETXTBSY, syscall.EAGAIN, syscall.EINTR:
		return true
	}
	return false
}

func errnoName(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "errno=?"
	}
	return fmt.Sprintf("errno=%d(%s)", int(errno), errno.Error())
}

func platformFileDiag(path string) string {
	fi, err := os.Lstat(path)
	if err != nil {
		return "不存在"
	}
	return fmt.Sprintf("存在/mode=%s/size=%d", fi.Mode().String(), fi.Size())
}
