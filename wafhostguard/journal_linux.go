//go:build linux

package wafhostguard

import (
	"SamWaf/common/wafexec"
	"SamWaf/common/zlog"
	"bufio"
	"context"
	"os/exec"
	"time"
)

// journald 事件源：给那些没有 /var/log/secure、/var/log/auth.log 的发行版用
// (较新的 Fedora/Arch、裁掉 rsyslog 的最小化镜像)。
//
// **三个 identifier 都要订**：OpenSSH 9.8+(Ubuntu 24.10 / Fedora 41 起)把认证阶段
// 拆到了独立的 sshd-session 进程里，syslog identifier 随之变化。只订 sshd 的话，
// 在新发行版上一条失败日志都收不到，而且完全没有报错——功能静默失效是最糟的失效方式。
var journalIdentifiers = []string{"sshd", "sshd-session", "sshd-auth"}

// journalRestartMax 重启保护：5 分钟内超过这个次数就放弃，避免疯狂 fork
const (
	journalRestartMax    = 10
	journalRestartWindow = 5 * time.Minute
	journalRestartDelay  = 3 * time.Second
)

type journalSource struct{}

func (s *journalSource) Name() string { return "journalctl" }

func (s *journalSource) Run(ctx context.Context, out chan<- LoginFailEvent) error {
	restarts := 0
	windowStart := time.Now()

	for {
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(windowStart) > journalRestartWindow {
			restarts = 0
			windowStart = time.Now()
		}
		if restarts >= journalRestartMax {
			return errJournalTooManyRestarts
		}

		if err := s.runOnce(ctx, out); err != nil && ctx.Err() == nil {
			zlog.Warn("[主机登录防护] journalctl 异常退出，稍后重启", "error", err.Error())
		}
		if ctx.Err() != nil {
			return nil
		}
		restarts++

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(journalRestartDelay):
		}
	}
}

// runOnce 拉起一次 journalctl -f 并读到它退出
func (s *journalSource) runOnce(ctx context.Context, out chan<- LoginFailEvent) error {
	// -n 0：只要新产生的，不回放历史(理由同 tail 的 Seek 到末尾)
	// -o cat：只输出消息正文，不带行首——解析器本来就不看行首时间戳
	args := []string{"-f", "-n", "0", "-o", "cat"}
	for _, id := range journalIdentifiers {
		args = append(args, "-t", id)
	}

	cmd := wafexec.FixStdin(exec.Command("journalctl", args...))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	// ctx 取消时杀掉子进程，否则 SamWaf 退出后会留下孤儿 journalctl 一直跑着
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-done:
		}
	}()
	defer close(done)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		if ev, ok := ParseSSHDLine(scanner.Text(), time.Now()); ok {
			select {
			case out <- ev:
			case <-ctx.Done():
				break
			default:
				dropEvent()
			}
		}
	}

	_ = cmd.Wait()
	return scanner.Err()
}
