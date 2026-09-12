//go:build !windows

package supervisor

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

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

// isWorkerProcessAlive 在"存活"之上再确认该 PID 确实是本系统的 Worker。
//
// PID 号会被复用：容器重启后 PID 从 1 重新分配，且线程也占用 PID 号段
// （kill(pid,0) 对线程同样返回成功）。只凭存活判断，上一代 Worker 的号码很容易
// 落在新进程或其线程身上，于是把毫不相干的东西当成遗留孤儿收编，
// 白白走一遍 takeover（跳过端口占用探测、延迟接管独占单例）。
func isWorkerProcessAlive(pid int) bool {
	if !isProcessAlive(pid) {
		return false
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		// 读不到(非 Linux 或权限不足)时退回存活判断，保持既有行为
		return true
	}
	for _, arg := range strings.FieldsFunc(string(cmdline), func(r rune) bool { return r == 0 }) {
		if strings.HasPrefix(arg, "--worker") {
			return true
		}
	}
	return false
}
