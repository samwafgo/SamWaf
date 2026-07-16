// Package wafexec 统一子进程标准流的兜底处理。
//
// Go 的 os/exec 在 Cmd.Stdin/Stdout/Stderr 为 nil 时，会去打开系统空设备
// (os.DevNull：Windows 为 NUL，类 Unix 为 /dev/null)，见 os/exec/exec.go 的
// childStdin / writerDescriptor。某些精简版 Windows(如 LTSC 纯净版)裁掉或禁用了
// Null 内核驱动，open NUL 直接失败，cmd.Start() 在创建进程前就报
// "open NUL: The system cannot find the file specified." —— 所有子进程全起不来
// (Supervisor 连首个 Worker 都拉不起来，SamWaf 完全无法启动)。
//
// 本包采用"探测降级"：
//   - 空设备可用(绝大多数机器) → 原样返回，行为与改造前完全一致，零回归；
//   - 空设备不可用(精简系统)   → 注入等价的替代流，让子进程照常启动。
//
// 约定：本项目内所有 exec.Cmd 在 Start/Run/Output/CombinedOutput 之前，
// 必须先经 FixStdin 或 FixStdio 处理，不得直接依赖空设备。
package wafexec

import (
	"bytes"
	"os"
	"os/exec"
	"sync"
)

// forceNoNullEnv 强制走"无空设备"降级分支的隐藏开关，仅用于在正常机器上验证降级路径。
// 该变量随 os.Environ() 自动继承给 spawn 出来的 Worker 子进程，无需额外传递。
const forceNoNullEnv = "SAMWAF_FORCE_NO_NULLDEV"

var (
	nullOnce sync.Once
	nullOK   bool
)

// nullAvailable 惰性探测一次系统空设备是否可读可写，结果进程内缓存。
// 读写都要探：os/exec 对 Stdin 用 os.Open，对 Stdout/Stderr 用 os.OpenFile(O_WRONLY)。
func nullAvailable() bool {
	nullOnce.Do(func() {
		if os.Getenv(forceNoNullEnv) == "1" {
			return // nullOK 保持 false
		}
		r, err := os.Open(os.DevNull)
		if err != nil {
			return
		}
		_ = r.Close()
		w, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_ = w.Close()
		nullOK = true
	})
	return nullOK
}

// NullDeviceAvailable 返回系统空设备是否可用，供启动自检使用。
func NullDeviceAvailable() bool { return nullAvailable() }

// FixStdin 仅在"空设备不可用"时，为 nil 的 Stdin 补一个立即 EOF 的读端；不动 Stdout/Stderr。
//
// 适用于随后要调 Output()/CombinedOutput()/StdoutPipe()/StderrPipe() 的场景 ——
// 这些方法要求 Stdout/Stderr 保持 nil 或由其自行接管，被提前占用会报 "exec: Stdout already set"。
//
// 替代流用 bytes.Reader 而非 os.Stdin：os.Stdin 在 Windows 服务模式下句柄可能无效，
// 前台模式下又会把真实控制台输入交给子进程(可能吞掉用户按键)。非 *os.File 的 Reader 会让
// os/exec 自建匿名管道，读端由 Start() 收尾关闭、写端由其拷贝 goroutine 拷完 0 字节后主动关闭，
// 因此即使调用方只调 os.Process.Wait() 而不调 cmd.Wait()(supervisor 就是如此)也不会泄漏句柄，
// 子进程读 stdin 立即 EOF，与 NUL 语义等价。
func FixStdin(cmd *exec.Cmd) *exec.Cmd {
	if cmd == nil || nullAvailable() {
		return cmd
	}
	if cmd.Stdin == nil {
		cmd.Stdin = bytes.NewReader(nil)
	}
	return cmd
}

// FixStdio 在"空设备不可用"时补齐三个标准流。
// 仅用于"直接 Run()/Start() 且确定不会再取 Pipe/Output"的 Cmd。
//
// Stdout/Stderr 必须填 *os.File(os.Stdout/os.Stderr)，不能填 io.Discard：
// io.Discard 不是 *os.File，os/exec 会为它新建匿名管道 + 拷贝 goroutine，而 cmd.Run()/Wait()
// 要等管道 EOF 才返回。像 `cmd /C xxx` 这类命令的孙进程会继承管道写端，孙进程不退出则管道
// 永不 EOF，Run() 将永久阻塞。*os.File 是直传句柄、零管道零 goroutine，与 NUL 行为等价；
// 服务模式下 os.Stdout 句柄为 0(子进程等于没有 stdout，天然丢弃)，前台模式下输出到控制台。
func FixStdio(cmd *exec.Cmd) *exec.Cmd {
	if cmd == nil || nullAvailable() {
		return cmd
	}
	FixStdin(cmd)
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	return cmd
}
