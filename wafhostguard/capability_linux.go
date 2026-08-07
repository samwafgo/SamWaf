//go:build linux

package wafhostguard

import (
	"os"
	"os/exec"
	"strings"
)

// 容器提示。与 firewall/firewall.go 的 containerHint 同源，但内容不同：
// 那边讲的是"封不了"，这边讲的是"看不见"——容器里的 /var/log 是容器自己的视图，
// 宿主机上谁在爆破 SSH，容器内一无所知。
const containerLogHint = "。当前运行在容器中：容器内的 /var/log 是容器自己的视图，看不到宿主机的 SSH 登录日志。" +
	"请以 `-v /var/log:/host/var/log:ro` 把宿主机日志只读挂载进来，并在【自定义日志路径】里填 /host/var/log/secure（Debian/Ubuntu 填 auth.log）；" +
	"若还要真正封禁，容器另需 `--cap-add=NET_ADMIN --network host`"

// checkLogCapability Linux：按 探测顺序 检查是否有可用的事件源
func checkLogCapability() (bool, string, bool) {
	inContainer := isInContainer()

	// 1. 用户显式指定了路径就只认这个——这是容器场景唯一的逃生口，
	//    指错了要明确报错，不能悄悄回落到自动探测让用户以为配好了
	if paths := splitList(globalLogPaths()); len(paths) > 0 {
		for _, p := range paths {
			if readable(p) {
				return true, "", inContainer
			}
		}
		msg := "已配置的自定义日志路径都不可读：" + strings.Join(paths, ", ") + "，请检查路径是否正确、当前进程是否有读权限（通常需要 root）"
		if inContainer {
			msg += containerLogHint
		}
		return false, msg, inContainer
	}

	// 2. 自动探测常见路径
	for _, p := range defaultAuthLogPaths {
		if readable(p) {
			return true, "", inContainer
		}
	}

	// 3. journald-only 的发行版(如较新的 Fedora/Arch，或裁掉了 rsyslog 的最小化镜像)
	if _, err := exec.LookPath("journalctl"); err == nil {
		return true, "", inContainer
	}

	msg := "未找到可读的系统认证日志：/var/log/secure、/var/log/auth.log 均不存在或无权读取，且系统里没有 journalctl。" +
		"若 SamWaf 不是以 root 运行，请改为 root 后重试；若日志在非标准路径，请在【自定义日志路径】里指定"
	if inContainer {
		msg += containerLogHint
	}
	return false, msg, inContainer
}

// readable 文件存在且当前进程能打开读
func readable(path string) bool {
	if path == "" {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// isInContainer 复刻 firewall/firewall.go 的判定：/.dockerenv 或 cgroup 里带容器标记
func isInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") ||
		strings.Contains(content, "kubepods") ||
		strings.Contains(content, "containerd") ||
		strings.Contains(content, "lxc")
}
