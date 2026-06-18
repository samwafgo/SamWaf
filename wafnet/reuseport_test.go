package wafnet

import (
	"net"
	"strconv"
	"testing"
)

// TestReusePortTCPDualBind 验证端口复用的核心能力：两个监听器能同时绑定同一个 TCP 端口。
// 这是升级重叠期"新旧 Worker 同端口并存"的基础。Linux 走 SO_REUSEPORT，Windows 走 SO_REUSEADDR。
func TestReusePortTCPDualBind(t *testing.T) {
	// 先用 :0 让系统分配一个空闲端口
	ln1, err := ReusePortTCPListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("第一个 REUSEPORT 监听失败: %v", err)
	}
	defer ln1.Close()

	port := ln1.Addr().(*net.TCPAddr).Port
	addr := "127.0.0.1:" + strconv.Itoa(port)

	// 第二个监听器绑定同一端口，应当成功（端口复用生效）
	ln2, err := ReusePortTCPListen(addr)
	if err != nil {
		t.Fatalf("第二个 REUSEPORT 监听绑定同端口 %d 失败（端口复用未生效）: %v", port, err)
	}
	defer ln2.Close()

	t.Logf("两个监听器成功同时绑定 TCP 端口 %d（端口复用生效）", port)
}

// TestReusePortPacketConnDualBind 验证 UDP（HTTP/3 用）端口复用双绑定。
func TestReusePortPacketConnDualBind(t *testing.T) {
	pc1, err := ReusePortPacketConn("127.0.0.1:0")
	if err != nil {
		t.Fatalf("第一个 REUSEPORT UDP 监听失败: %v", err)
	}
	defer pc1.Close()

	port := pc1.LocalAddr().(*net.UDPAddr).Port
	addr := "127.0.0.1:" + strconv.Itoa(port)

	pc2, err := ReusePortPacketConn(addr)
	if err != nil {
		t.Fatalf("第二个 REUSEPORT UDP 监听绑定同端口 %d 失败: %v", port, err)
	}
	defer pc2.Close()

	t.Logf("两个 PacketConn 成功同时绑定 UDP 端口 %d（端口复用生效）", port)
}
