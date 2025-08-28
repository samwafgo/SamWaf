package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/model/waftunnelmodel"
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// startTCPServer 启动TCP服务器
func (waf *WafTunnelEngine) startTCPServer(netRuntime waftunnelmodel.NetRunTime) {
	addr := ":" + strconv.Itoa(netRuntime.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		zlog.Error("TCP服务器启动失败，端口: " + strconv.Itoa(netRuntime.Port) + ", 错误: " + err.Error())
		return
	}

	key := "tcp" + strconv.Itoa(netRuntime.Port)
	// 更新状态
	netClone, _ := waf.NetListerOnline.Get(key)
	netClone.Status = 0
	netClone.Svr = listener
	waf.NetListerOnline.Set(key, netClone)

	zlog.Info("启动TCP服务器，端口: " + strconv.Itoa(netRuntime.Port))

	for {
		conn, err := listener.Accept()
		if err != nil {
			zlog.Error("TCP连接接收失败: " + err.Error())
			break
		}

		// 获取隧道配置
		tunnelInfo, ok := waf.TunnelTarget.Get("tcp" + strconv.Itoa(netRuntime.Port))
		if !ok {
			zlog.Error("未找到端口对应的隧道配置: " + "tcp" + strconv.Itoa(netRuntime.Port))
			conn.Close()
			continue
		}

		// 检查入站连接数限制
		if tunnelInfo.Tunnel.MaxInConnect > 0 {
			inConnCount := waf.TCPConnections.GetPortConnsCountByType(netRuntime.Port, waftunnelmodel.ConnTypeSource)
			if inConnCount >= tunnelInfo.Tunnel.MaxInConnect {
				zlog.Warn("TCP入站连接数超过限制，当前连接数: " + strconv.Itoa(inConnCount) +
					", 最大限制: " + strconv.Itoa(tunnelInfo.Tunnel.MaxInConnect) +
					", 端口: " + strconv.Itoa(netRuntime.Port))
				conn.Close()
				continue
			}
		}

		// 处理连接
		go waf.handleTCPConnection(conn, netRuntime.Port)
	}

	zlog.Info("TCP服务器关闭，端口: " + strconv.Itoa(netRuntime.Port))
}

// handleTCPConnection 处理TCP连接
func (waf *WafTunnelEngine) handleTCPConnection(clientConn net.Conn, port int) {
	// 获取客户端IP
	clientIP := clientConn.RemoteAddr().String()

	// 获取隧道配置
	tunnelInfo, ok := waf.TunnelTarget.Get("tcp" + strconv.Itoa(port))
	if !ok {
		zlog.Error("未找到端口对应的隧道配置: " + "tcp" + strconv.Itoa(port))
		clientConn.Close()
		return
	}

	// 检查IP访问权限
	if !CheckIPAccess(clientIP, tunnelInfo.Tunnel) {
		zlog.Warn("TCP连接被拒绝，客户端IP: " + clientIP + ", 端口: " + strconv.Itoa(port))
		clientConn.Close()
		return
	}

	// 将客户端连接添加到活动连接列表，标记为来源连接
	waf.TCPConnections.AddConn(port, clientConn, waftunnelmodel.ConnTypeSource)
	defer func() {
		clientConn.Close()
		waf.TCPConnections.RemoveConn(port, clientConn)
	}()

	// 检查出站连接数限制
	if tunnelInfo.Tunnel.MaxOutConnect > 0 {
		outConnCount := waf.TCPConnections.GetPortConnsCountByType(port, waftunnelmodel.ConnTypeTarget)
		if outConnCount >= tunnelInfo.Tunnel.MaxOutConnect {
			zlog.Warn("TCP出站连接数超过限制，当前连接数: " + strconv.Itoa(outConnCount) +
				", 最大限制: " + strconv.Itoa(tunnelInfo.Tunnel.MaxOutConnect) +
				", 端口: " + strconv.Itoa(port))
			return
		}
	}

	// 连接到目标服务器
	targetAddr := tunnelInfo.Tunnel.RemoteIp + ":" + strconv.Itoa(tunnelInfo.Tunnel.RemotePort)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		zlog.Error("连接目标服务器失败: " + targetAddr + ", 错误: " + err.Error())
		return
	}

	// 将目标连接也添加到活动连接列表，标记为目标连接
	waf.TCPConnections.AddConn(port, targetConn, waftunnelmodel.ConnTypeTarget)
	defer func() {
		targetConn.Close()
		waf.TCPConnections.RemoveConn(port, targetConn)
	}()

	// 设置超时
	if tunnelInfo.Tunnel.ConnTimeout > 0 {
		clientConn.SetDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.ConnTimeout) * time.Second))
		targetConn.SetDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.ConnTimeout) * time.Second))
	}

	// 设置读取超时
	if tunnelInfo.Tunnel.ReadTimeout > 0 {
		clientConn.SetReadDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.ReadTimeout) * time.Second))
		targetConn.SetReadDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.ReadTimeout) * time.Second))
	}

	// 设置写入超时
	if tunnelInfo.Tunnel.WriteTimeout > 0 {
		clientConn.SetWriteDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.WriteTimeout) * time.Second))
		targetConn.SetWriteDeadline(time.Now().Add(time.Duration(tunnelInfo.Tunnel.WriteTimeout) * time.Second))
	}

	// 使用context和WaitGroup管理连接生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端到目标服务器的数据转发
	go func() {
		defer wg.Done()
		defer cancel() // 任一方向断开时取消context

		// 使用io.Copy，当连接断开时会自动返回
		_, err := io.Copy(targetConn, clientConn)
		if err != nil {
			zlog.Error("客户端->目标 数据转发结束: " + err.Error())
		} else {
			zlog.Debug("客户端->目标 数据转发正常结束")
		}
	}()

	// 目标服务器到客户端的数据转发
	go func() {
		defer wg.Done()
		defer cancel() // 任一方向断开时取消context

		// 使用io.Copy，当连接断开时会自动返回
		_, err := io.Copy(clientConn, targetConn)
		if err != nil {
			zlog.Error("目标->客户端 数据转发结束: " + err.Error())
		} else {
			zlog.Debug("目标->客户端 数据转发正常结束")
		}
	}()

	// 监控context取消，主动关闭连接
	go func() {
		<-ctx.Done()
		// context被取消时，主动关闭两个连接
		clientConn.Close()
		targetConn.Close()
		zlog.Debug("Context取消，主动关闭连接")
	}()

	// 等待任一方向的连接断开
	wg.Wait()
	zlog.Info("TCP连接处理完成，端口: " + strconv.Itoa(port))
}
