//go:build linux

package wafhostguard

import (
	"SamWaf/common/zlog"
	"errors"
	"os/exec"
)

// defaultAuthLogPaths 常见发行版的认证日志位置，按探测优先级排列
var defaultAuthLogPaths = []string{
	"/var/log/secure",   // RHEL / CentOS / Rocky / Alma / openEuler
	"/var/log/auth.log", // Debian / Ubuntu
	"/var/log/messages", // 部分老系统把认证日志也写在这
}

var errJournalTooManyRestarts = errors.New("journalctl 反复异常退出，已停止重启")

// newSources Linux 事件源装配。
//
// 探测顺序刻意如此：
//  1. 用户显式配的路径 —— 容器场景唯一的逃生口，配了就只认它，
//     不能悄悄回落到自动探测，否则用户以为配好了实际读的是别的文件。
//  2. 自动探测常见路径。
//  3. journalctl 兜底。
func newSources() ([]Source, string) {
	if paths := splitList(globalLogPaths()); len(paths) > 0 {
		var srcs []Source
		for _, p := range paths {
			if readable(p) {
				srcs = append(srcs, &fileTailSource{path: p})
			} else {
				zlog.Warn("[主机登录防护] 自定义日志路径不可读，已跳过", "path", p)
			}
		}
		if len(srcs) > 0 {
			return srcs, ""
		}
		ok, reason, _ := checkLogCapability()
		if !ok {
			return nil, reason
		}
	}

	var srcs []Source
	for _, p := range defaultAuthLogPaths {
		if readable(p) {
			srcs = append(srcs, &fileTailSource{path: p})
			// 只取第一个命中的：RHEL 系同时存在 secure 和 messages 时，
			// 两个文件里是同一批认证日志，都读会让每次失败被计两次，阈值直接腰斩
			break
		}
	}
	if len(srcs) > 0 {
		return srcs, ""
	}

	if _, err := exec.LookPath("journalctl"); err == nil {
		return []Source{&journalSource{}}, ""
	}

	_, reason, _ := checkLogCapability()
	return nil, reason
}
