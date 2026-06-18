//go:build windows

package wafnet

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// reusePortControl 在 socket 绑定前设置 SO_REUSEADDR。
// Windows 没有 SO_REUSEPORT，SO_REUSEADDR 允许新旧 Worker 绑定同一端口，
// 但分流语义较弱（不保证均衡），需配合 Supervisor 调度的"快速交接"兜底（见设计文档 §4.7）。
func reusePortControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if e := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); e != nil {
			serr = e
			return
		}
	}); err != nil {
		return err
	}
	return serr
}
