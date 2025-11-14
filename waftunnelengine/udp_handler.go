package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/model/waftunnelmodel"
	"fmt"
	"net"
	"strconv"
	"time"
)

// startUDPServer 启动UDP服务器
func (waf *WafTunnelEngine) startUDPServer(netRuntime waftunnelmodel.NetRunTime) {
	addr := ":" + strconv.Itoa(netRuntime.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		serverPort := strconv.Itoa(netRuntime.Port)
		zlog.Error(fmt.Sprintf("UDP地址解析失败 [服务端口:%s 错误:%s]", serverPort, err.Error()))
		return
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		serverPort := strconv.Itoa(netRuntime.Port)
		zlog.Error(fmt.Sprintf("UDP服务器启动失败 [服务端口:%s 错误:%s]", serverPort, err.Error()))
		return
	}

	// 将服务器连接添加到活动连接列表，标记为来源连接
	waf.UDPConnections.AddConn(netRuntime.Port, conn, waftunnelmodel.ConnTypeSource)

	key := "udp" + strconv.Itoa(netRuntime.Port)
	// 更新状态
	netClone, _ := waf.NetListerOnline.Get(key)
	netClone.Status = 0
	netClone.Svr = conn
	waf.NetListerOnline.Set(key, netClone)

	serverPort := strconv.Itoa(netRuntime.Port)
	zlog.Info(fmt.Sprintf("启动UDP服务器 [服务端口:%s]", serverPort))

	// 处理UDP数据
	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			zlog.Error(fmt.Sprintf("UDP读取失败 [服务端口:%s 错误:%s]", serverPort, err.Error()))
			break
		}

		// 获取客户端信息用于日志
		clientIP := remoteAddr.IP.String()
		clientPort := strconv.Itoa(remoteAddr.Port)

		// 获取隧道配置
		tunnelInfo, ok := waf.TunnelTarget.Get("udp" + strconv.Itoa(netRuntime.Port))
		if !ok {
			zlog.Error(fmt.Sprintf("未找到端口对应的隧道配置 [客户端IP:%s 客户端端口:%s 服务端口:%s]",
				clientIP, clientPort, serverPort))
			continue
		}

		// 检查入站连接数限制
		if tunnelInfo.Tunnel.MaxInConnect > 0 {
			inConnCount := waf.UDPConnections.GetPortConnsCountByType(netRuntime.Port, waftunnelmodel.ConnTypeSource)
			if inConnCount >= tunnelInfo.Tunnel.MaxInConnect {
				zlog.Warn(fmt.Sprintf("UDP入站连接数超过限制 [客户端IP:%s 客户端端口:%s 服务端口:%s 当前连接数:%d 最大限制:%d]",
					clientIP, clientPort, serverPort, inConnCount, tunnelInfo.Tunnel.MaxInConnect))
				continue
			}
		}

		// 处理UDP数据
		go waf.handleUDPData(conn, remoteAddr, buffer[:n], netRuntime.Port)
	}

	zlog.Info(fmt.Sprintf("UDP服务器关闭 [服务端口:%s]", serverPort))
	waf.UDPConnections.RemoveConn(netRuntime.Port, conn)
}

// handleUDPData 处理UDP数据
func (waf *WafTunnelEngine) handleUDPData(serverConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, port int) {
	// 获取客户端IP和端口
	clientIP := clientAddr.IP.String()
	clientPort := strconv.Itoa(clientAddr.Port)
	serverPort := strconv.Itoa(port)

	// 获取隧道配置
	tunnelInfo, ok := waf.TunnelTarget.Get("udp" + strconv.Itoa(port))
	if !ok {
		zlog.Error(fmt.Sprintf("未找到端口对应的隧道配置 [客户端IP:%s 客户端端口:%s 服务端口:%s]",
			clientIP, clientPort, serverPort))
		return
	}

	// 检查IP访问权限
	if !CheckIPAccess("UDP", clientIP, clientPort, serverPort, tunnelInfo.Tunnel) {
		zlog.Warn(fmt.Sprintf("UDP数据被拒绝 [客户端IP:%s 客户端端口:%s 服务端口:%s]",
			clientIP, clientPort, serverPort))
		return
	}

	// 检查出站连接数限制
	if tunnelInfo.Tunnel.MaxOutConnect > 0 {
		outConnCount := waf.UDPConnections.GetPortConnsCountByType(port, waftunnelmodel.ConnTypeTarget)
		if outConnCount >= tunnelInfo.Tunnel.MaxOutConnect {
			zlog.Warn(fmt.Sprintf("UDP出站连接数超过限制 [客户端IP:%s 客户端端口:%s 服务端口:%s 当前连接数:%d 最大限制:%d]",
				clientIP, clientPort, serverPort, outConnCount, tunnelInfo.Tunnel.MaxOutConnect))
			return
		}
	}

	// 连接到目标服务器
	targetAddr := tunnelInfo.Tunnel.RemoteIp + ":" + strconv.Itoa(tunnelInfo.Tunnel.RemotePort)
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		zlog.Error(fmt.Sprintf("解析目标地址失败 [客户端IP:%s 客户端端口:%s 服务端口:%s 目标地址:%s 错误:%s]",
			clientIP, clientPort, serverPort, targetAddr, err.Error()))
		return
	}

	// 创建到目标的连接
	targetConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		zlog.Error(fmt.Sprintf("连接目标服务器失败 [客户端IP:%s 客户端端口:%s 服务端口:%s 目标地址:%s 错误:%s]",
			clientIP, clientPort, serverPort, targetAddr, err.Error()))
		return
	}

	// 将目标连接添加到活动连接列表，标记为目标连接
	waf.UDPConnections.AddConn(port, targetConn, waftunnelmodel.ConnTypeTarget)
	defer func() {
		targetConn.Close()
		waf.UDPConnections.RemoveConn(port, targetConn)
	}()

	// 设置超时
	if tunnelInfo.Tunnel.ConnTimeout > 0 {
		targetConn.SetDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.ConnTimeout) * time.Second))
	}

	// 设置读取超时
	if tunnelInfo.Tunnel.ReadTimeout > 0 {
		targetConn.SetReadDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.ReadTimeout) * time.Second))
	}

	// 设置写入超时
	if tunnelInfo.Tunnel.WriteTimeout > 0 {
		targetConn.SetWriteDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.WriteTimeout) * time.Second))
	}

	// 发送数据到目标
	_, err = targetConn.Write(data)
	if err != nil {
		zlog.Error(fmt.Sprintf("发送数据到目标失败 [客户端IP:%s 客户端端口:%s 服务端口:%s 错误:%s]",
			clientIP, clientPort, serverPort, err.Error()))
		return
	}

	// 接收目标响应
	buffer := make([]byte, 4096)
	n, _, err := targetConn.ReadFromUDP(buffer)
	if err != nil {
		zlog.Error(fmt.Sprintf("从目标接收数据失败 [客户端IP:%s 客户端端口:%s 服务端口:%s 错误:%s]",
			clientIP, clientPort, serverPort, err.Error()))
		return
	}

	// 发送响应回客户端
	_, err = serverConn.WriteToUDP(buffer[:n], clientAddr)
	if err != nil {
		zlog.Error(fmt.Sprintf("发送响应到客户端失败 [客户端IP:%s 客户端端口:%s 服务端口:%s 错误:%s]",
			clientIP, clientPort, serverPort, err.Error()))
		return
	}
}
