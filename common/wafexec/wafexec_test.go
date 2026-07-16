package wafexec

import (
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"
)

// resetProbe 重置空设备探测缓存，让下一次调用重新探测。
func resetProbe() {
	nullOnce = sync.Once{}
	nullOK = false
}

// trueCmd 返回一个立刻成功退出的短命命令。
func trueCmd() *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/c", "exit 0")
	}
	return exec.Command("true")
}

// echoCmd 返回一个会向 stdout 打印内容的命令。
func echoCmd(s string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/c", "echo "+s)
	}
	return exec.Command("echo", s)
}

// TestNoopWhenNullAvailable 空设备可用时必须原样返回，三个流保持 nil。
// 这是"正常机器零回归"的核心保证：os/exec 依旧走它原本的空设备路径。
func TestNoopWhenNullAvailable(t *testing.T) {
	resetProbe()
	if !NullDeviceAvailable() {
		t.Skipf("本机 %s 不可用，跳过", os.DevNull)
	}

	cmd := trueCmd()
	FixStdio(cmd)
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatalf("空设备可用时不应改动标准流，实际 Stdin=%v Stdout=%v Stderr=%v",
			cmd.Stdin, cmd.Stdout, cmd.Stderr)
	}
}

// TestFixStdinWhenDegraded 降级时只补 Stdin，不碰 Stdout/Stderr（否则 Output/Pipe 路径会报 Stdout already set）。
func TestFixStdinWhenDegraded(t *testing.T) {
	t.Setenv(forceNoNullEnv, "1")
	resetProbe()
	defer resetProbe()

	cmd := trueCmd()
	FixStdin(cmd)
	if cmd.Stdin == nil {
		t.Fatal("降级时 Stdin 应被补上")
	}
	if cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("FixStdin 不应改动 Stdout/Stderr")
	}
}

// TestOutputStillWorksWhenDegraded 降级后 Output() 仍能正常取到输出（防止误伤采集类命令）。
func TestOutputStillWorksWhenDegraded(t *testing.T) {
	t.Setenv(forceNoNullEnv, "1")
	resetProbe()
	defer resetProbe()

	out, err := FixStdin(echoCmd("samwaf")).Output()
	if err != nil {
		t.Fatalf("Output() 失败: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("Output() 未取到内容")
	}
}

// TestStdoutIsFileWhenDegraded 降级时 Stdout/Stderr 必须是 *os.File。
//
// 回归断言：不能改成 io.Discard —— 非 *os.File 会让 os/exec 建匿名管道 + 拷贝 goroutine，
// 而 cmd.Run()/Wait() 要等管道 EOF 才返回；`cmd /C` 的孙进程会继承管道写端，
// 孙进程不退出则 Run() 永久阻塞（wafappengine 的 StopCmd/taskkill 会因此卡死优雅停止）。
func TestStdoutIsFileWhenDegraded(t *testing.T) {
	t.Setenv(forceNoNullEnv, "1")
	resetProbe()
	defer resetProbe()

	cmd := trueCmd()
	FixStdio(cmd)
	if _, ok := cmd.Stdout.(*os.File); !ok {
		t.Fatalf("降级时 Stdout 必须是 *os.File(直传句柄，零管道)，实际为 %T", cmd.Stdout)
	}
	if _, ok := cmd.Stderr.(*os.File); !ok {
		t.Fatalf("降级时 Stderr 必须是 *os.File，实际为 %T", cmd.Stderr)
	}
}

// TestStartWithoutCmdWait 降级后只调 os.Process.Wait()、不调 cmd.Wait() 也能正常收尾。
// 对齐 supervisor.spawn 的实际用法（它保存 cmd.Process，用 proc.Wait() 监护）。
func TestStartWithoutCmdWait(t *testing.T) {
	t.Setenv(forceNoNullEnv, "1")
	resetProbe()
	defer resetProbe()

	cmd := trueCmd()
	FixStdio(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start() 失败: %v", err)
	}
	state, err := cmd.Process.Wait()
	if err != nil {
		t.Fatalf("proc.Wait() 失败: %v", err)
	}
	if state.ExitCode() != 0 {
		t.Fatalf("子进程退出码应为 0，实际 %d", state.ExitCode())
	}
}

// TestRunNotBlockedByGrandchild 降级后，即使子进程派生了长命孙进程，Run() 也必须立即返回。
//
// 这是 io.Discard 方案会踩的坑：非 *os.File 的 Stdout 会让 os/exec 建匿名管道，孙进程继承写端，
// Run()/Wait() 要等管道 EOF 才返回 → 孙进程活多久就阻塞多久。wafappengine 的 StopCmd/taskkill
// 正是 `cmd /C` 起的，一旦阻塞会直接卡死应用的优雅停止。用 *os.File 则零管道、不阻塞。
func TestRunNotBlockedByGrandchild(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅在 Windows 上验证 cmd /C 的孙进程场景")
	}
	t.Setenv(forceNoNullEnv, "1")
	resetProbe()
	defer resetProbe()

	// cmd /C start /b 派生一个脱离 cmd.exe 自身生命周期的孙进程(存活约 8s)。
	// 孙进程必须继承 Stdout —— 这正是 io.Discard 方案里"管道迟迟不 EOF"的成因，不能重定向掉。
	cmd := FixStdio(exec.Command("cmd", "/C", "start /b ping -n 8 127.0.0.1"))

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-done: // 期望：cmd.exe 一退出 Run() 立刻返回，不等孙进程
	case <-time.After(3 * time.Second):
		t.Fatal("Run() 被孙进程阻塞超过 3s —— Stdout 很可能被改成了非 *os.File(如 io.Discard)，会卡死应用优雅停止")
	}
}

// TestNeverOverrideExisting 已显式赋值的流一律不覆盖。
func TestNeverOverrideExisting(t *testing.T) {
	t.Setenv(forceNoNullEnv, "1")
	resetProbe()
	defer resetProbe()

	cmd := trueCmd()
	cmd.Stdout = os.Stderr // 故意用 Stderr 占位，确认不被改写
	FixStdio(cmd)
	if cmd.Stdout != os.Stderr {
		t.Fatal("已设置的 Stdout 不应被覆盖")
	}
}

// TestNilCmdSafe 传 nil 不 panic。
func TestNilCmdSafe(t *testing.T) {
	t.Setenv(forceNoNullEnv, "1")
	resetProbe()
	defer resetProbe()

	if FixStdin(nil) != nil || FixStdio(nil) != nil {
		t.Fatal("传 nil 应原样返回 nil")
	}
}
