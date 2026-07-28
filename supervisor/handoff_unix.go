//go:build !windows
// +build !windows

package supervisor

import (
	"SamWaf/common/zlog"
	"os"
	"syscall"
)

// handoffToNewBinary 让 Supervisor 自身换到磁盘上的新二进制（设计文档 §4.6）。
//
// Unix 上直接 execve 原地替换进程映像：
//   - PID 不变 ⇒ systemd 完全无感，不会走 Restart= 逻辑，也不会因为
//     默认的 KillMode=control-group 把整个 cgroup（含 Worker）连带杀掉；
//   - 子进程(Worker)不受 exec 影响，继续转发业务；
//   - 新映像重新 Run()，从 supervisor.state 复用 ctrl 端口 + token，
//     Worker 断线后每 2s 重连即可连回来（adoptOrphans 同版本原地认领）。
//
// serviceManaged 在 Unix 上不影响决策：前台跑也能安全 re-exec。
//
// 成功时本函数不返回（进程映像已被替换）。
func handoffToNewBinary(exePath string, serviceManaged bool) error {
	zlog.Info("[Supervisor] 自升级交接：re-exec 到新二进制 " + exePath + "（PID 不变，Worker 不受影响）")
	// 监听 fd 带 CLOEXEC，exec 时自动关闭；新映像会用同一端口重新监听。
	return syscall.Exec(exePath, os.Args, os.Environ())
}
