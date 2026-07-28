package supervisor

import (
	"SamWaf/common/wafexec"
	"SamWaf/common/zlog"
	"errors"
	"os"
	"os/exec"
	"strconv"
)

// handoffToNewBinary 让 Supervisor 自身换到磁盘上的新二进制（设计文档 §4.6）。
//
// Windows 没有 execve，只能"退出 + 由外部把服务重新拉起来"。这里不依赖 SCM 的
// 失败恢复动作(OnFailure=restart)——那是服务**安装时**写入的，2026-01 之前装的
// 服务可能根本没配，一旦退出就再也起不来。改为先起一个脱离的助手进程去 start，
// 确定性更高。
//
// Worker 不受影响：Windows 没有 Job Object，Supervisor 退出后 Worker 变成孤儿
// 继续转发业务；新 Supervisor 起来后靠 supervisor.state 里的 ctrl 端口 + token
// 把它们收编回来（adoptOrphans，已实测过的路径）。
//
// 成功时本函数不返回（进程退出）。
func handoffToNewBinary(exePath string, serviceManaged bool) error {
	if !serviceManaged {
		// 前台运行时没有服务管理器兜底，退出就等于把 WAF 停了。
		return errors.New("前台(交互式)运行，无服务管理器兜底")
	}

	cmd := exec.Command(exePath, HandoffRestartArg)
	// 助手不接管任何标准流，三个都是 nil —— 精简版 Windows 缺失 NUL 空设备时
	// os/exec 会在 Start() 前就报 "open NUL"，所以三个流都要兜底(FixStdio 而非 FixStdin)。
	wafexec.FixStdio(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	// 助手已就位，不等它（它的活儿要等本进程退出后才能干成）。
	_ = cmd.Process.Release()

	zlog.Info("[Supervisor] 自升级交接：重启助手 pid=" + strconv.Itoa(cmd.Process.Pid) +
		" 已启动，本进程即将退出，Worker 继续服务；助手会把服务以新二进制重新拉起")
	// 干净退出(0)：不触发 SCM 的失败恢复动作，完全交给助手，行为可预期。
	// 注意这里必须绕过 Shutdown()——绝不能让 Worker 跟着退出，否则业务就断了。
	os.Exit(0)
	return nil
}
