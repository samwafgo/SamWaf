// Package wafnet 提供端口复用监听等底层网络工具。
//
// 端口复用让升级重叠期新旧 Worker 能同时绑定同一端口，内核分流新连接，避免端口空窗：
//   - Linux/BSD/macOS：SO_REUSEPORT（+ SO_REUSEADDR）
//   - Windows：SO_REUSEADDR（无 SO_REUSEPORT，语义较弱，配合 Supervisor 快速交接兜底）
//
// 该包仅依赖标准库与 golang.org/x/sys，可被 wafenginecore / wafhttpserver / wafmangeweb
// 等任意上层包引用而不产生导入环。平台相关的 reusePortControl 见 reuseport_unix.go / reuseport_windows.go。
package wafnet

import (
	"context"
	"net"
)

// ReusePortTCPListen 创建开启端口复用的 TCP 监听（双栈，等价 network="tcp"）。
func ReusePortTCPListen(addr string) (net.Listener, error) {
	return ReusePortTCPListenNetwork("tcp", addr)
}

// ReusePortTCPListenNetwork 创建开启端口复用的 TCP 监听，network 取 tcp/tcp4/tcp6，
// 供站点端口按 IP 版本（both/ipv4/ipv6）选择监听族。
func ReusePortTCPListenNetwork(network, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: reusePortControl}
	return lc.Listen(context.Background(), network, addr)
}

// ReusePortPacketConn 创建开启端口复用的 UDP PacketConn，供 HTTP/3(QUIC) 使用。
func ReusePortPacketConn(addr string) (net.PacketConn, error) {
	return ReusePortPacketConnNetwork("udp", addr)
}

// ReusePortPacketConnNetwork 同上，network 取 udp/udp4/udp6，与 TCP 侧保持同一 IP 版本。
func ReusePortPacketConnNetwork(network, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: reusePortControl}
	return lc.ListenPacket(context.Background(), network, addr)
}
