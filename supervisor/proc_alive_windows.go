//go:build windows

package supervisor

import "golang.org/x/sys/windows"

// stillActive 对应 Windows STILL_ACTIVE(259)：GetExitCodeProcess 返回该值表示进程仍在运行。
const stillActive = 259

// isProcessAlive 判断指定 PID 的进程是否仍在运行（Windows）。
// 用途仅限：判断 Supervisor 自身重启后是否有遗留的存活 Worker、以及等待其退出；
// 不用于决定"是否杀进程"——退出一律走控制通道 DRAIN，绝不按 PID 硬杀。
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
