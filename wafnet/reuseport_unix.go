//go:build !windows

package wafnet

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortControl 在 socket 绑定前设置 SO_REUSEADDR + SO_REUSEPORT，
// 允许升级重叠期新旧 Worker 同端口并行监听，由内核做连接分流。
func reusePortControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
			serr = e
			return
		}
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
			serr = e
			return
		}
	}); err != nil {
		return err
	}
	return serr
}
