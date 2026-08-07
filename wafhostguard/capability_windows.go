//go:build windows

package wafhostguard

import (
	"SamWaf/common/wafexec"
	"context"
	"os/exec"
	"strings"
	"time"
)

// probeTimeout 探测命令超时。wevtutil 在事件日志服务异常时可能挂住，
// 不能让能力探测把调用方的锁一起焊死。
const probeTimeout = 8 * time.Second

// checkLogCapability Windows：能否读取安全事件日志(4625 所在的 Security 频道)。
//
// 读 Security 频道需要管理员或 SYSTEM 权限。SamWaf 装成服务时默认是 LocalSystem，
// 有权限；但用户以普通身份双击 exe 调试时会读不到，这时要给出能直接照做的提示。
func checkLogCapability() (bool, string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	// 只取 1 条，纯粹验证"打得开"
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:text")
	out, err := wafexec.FixStdin(cmd).CombinedOutput()
	if err == nil {
		return true, "", false
	}

	detail := strings.TrimSpace(string(out))
	msg := "无法读取 Windows 安全事件日志（4625 登录失败事件所在的 Security 频道）"
	switch {
	case ctx.Err() != nil:
		msg += "：探测超时，可能是 Windows Event Log 服务异常，请检查该服务是否正在运行"
	case strings.Contains(detail, "5") && strings.Contains(strings.ToLower(detail), "access"),
		strings.Contains(detail, "拒绝访问"):
		msg += "：权限不足。请以管理员身份运行，或把 SamWaf 安装为系统服务（服务默认以 LocalSystem 运行，有读取权限）"
	default:
		msg += "：" + detail
		if detail == "" {
			msg += err.Error()
		}
	}
	return false, msg, false
}
