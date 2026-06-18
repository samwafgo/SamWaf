//go:build !windows

package supervisor

import "syscall"

// isProcessAlive 判断指定 PID 的进程是否仍在运行（Unix）。
// 用途仅限：判断 Supervisor 自身重启后是否有遗留的存活 Worker、以及等待其退出；
// 不用于决定"是否杀进程"——退出一律走控制通道 DRAIN，绝不按 PID 硬杀。
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// signal 0 不真正发信号，只做存在性/权限探测：nil=存在；EPERM=存在但无权限。
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return err == syscall.EPERM
}
