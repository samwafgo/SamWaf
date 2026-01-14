package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/waftunnelmodel"
	"net"
	"strconv"
	"strings"
)

type WafTunnelEngine struct {
	//隧道情况（key:协议+端口 : tunnelSafe信息里面详细等）
	TunnelTarget *waftunnelmodel.SafeTunnelMap
	//服务在线情况（key：协议+端口，value :连接接入控制器）
	NetListerOnline *waftunnelmodel.SafeNetMap
	//TCP连接管理
	TCPConnections *waftunnelmodel.SafeTCPConnMap
	//UDP连接管理
	UDPConnections *waftunnelmodel.SafeUDPConnMap
}

func NewWafTunnelEngine() *WafTunnelEngine {
	return &WafTunnelEngine{
		TunnelTarget:    waftunnelmodel.NewSafeTunnelMap(),
		NetListerOnline: waftunnelmodel.NewSafeNetMap(),
		TCPConnections:  waftunnelmodel.NewSafeTCPConnMap(),
		UDPConnections:  waftunnelmodel.NewSafeUDPConnMap(),
	}
}

// StartTunnel 启动tunnel
func (waf *WafTunnelEngine) StartTunnel() {
	// 启动tunnel
	waf.LoadAllTunnel()
	waf.StartAllTunnelServer()
}

// CloseTunnel 关闭tunnel
func (waf *WafTunnelEngine) CloseTunnel() {
	// 关闭tunnel
	zlog.Info("开始关闭所有隧道服务...")
	waf.StopAllTunnelServer()
	// 清理隧道目标信息
	waf.TunnelTarget.Clear()

	// 清理服务在线情况
	waf.NetListerOnline.Clear()
	zlog.Info("所有隧道服务已关闭")
}

// LoadAllTunnel 加载全部tunnel
func (waf *WafTunnelEngine) LoadAllTunnel() {
	//重新查询
	var tunnels []model.Tunnel
	global.GWAF_LOCAL_DB.Find(&tunnels)
	for i := 0; i < len(tunnels); i++ {
		waf.LoadTunnel(tunnels[i])
	}
}

// LoadTunnel 加载指定tunnel
func (waf *WafTunnelEngine) LoadTunnel(inTunnel model.Tunnel) []waftunnelmodel.NetRunTime {

	netRunTimes := make([]waftunnelmodel.NetRunTime, 0)

	// 先处理端口
	portStr := inTunnel.Port
	portStrArray := strings.Split(portStr, ",")
	portArray := make([]int, 0, len(portStrArray))
	for _, portItem := range portStrArray {
		portItem = strings.TrimSpace(portItem)
		if portItem == "" {
			continue
		}
		port, err := strconv.Atoi(portItem)
		if err != nil {
			continue
		}
		portArray = append(portArray, port)

		key := inTunnel.Protocol + portItem //唯一识别 协议+端口
		_, ok := waf.NetListerOnline.Get(key)
		if ok == false {
			//不存在，创建一个
			netRuntime := waftunnelmodel.NetRunTime{
				ServerType: inTunnel.Protocol,
				Port:       port,
				Status:     inTunnel.StartStatus,
				Svr:        nil,
			}
			waf.NetListerOnline.Set(key, netRuntime)
			netRunTimes = append(netRunTimes, netRuntime)
		}
		//设置或者重新更新引用隧道的基本信息
		waf.TunnelTarget.Set(key, &waftunnelmodel.TunnelSafe{
			Tunnel: inTunnel,
		})
	}

	return netRunTimes
}

// EditTunnel 编辑隧道配置
func (waf *WafTunnelEngine) EditTunnel(oldTunnel model.Tunnel, newTunnel model.Tunnel) []waftunnelmodel.NetRunTime {
	// 返回值：新增的端口运行时, 移除的端口运行时
	addedRunTimes := make([]waftunnelmodel.NetRunTime, 0)

	// 解析旧端口列表
	oldPortMap := make(map[string]bool)
	oldPortStrArray := strings.Split(oldTunnel.Port, ",")
	for _, portItem := range oldPortStrArray {
		portItem = strings.TrimSpace(portItem)
		if portItem == "" {
			continue
		}
		oldPortMap[portItem] = true
	}

	// 解析新端口列表
	newPortMap := make(map[string]bool)
	newPortStrArray := strings.Split(newTunnel.Port, ",")
	for _, portItem := range newPortStrArray {
		portItem = strings.TrimSpace(portItem)
		if portItem == "" {
			continue
		}
		newPortMap[portItem] = true
	}

	// 情况1：端口完全没变，只修改了其他信息
	if len(oldPortMap) == len(newPortMap) {
		allSame := true
		for port := range oldPortMap {
			if !newPortMap[port] {
				allSame = false
				break
			}
		}

		//如果是端口相同，也存在是否存在切换状态或IP版本变化
		if allSame {
			// 端口完全相同，检查是否需要重启服务
			// 获取旧的IP版本（如果为空则默认为both）
			oldIpVersion := oldTunnel.IpVersion
			if oldIpVersion == "" {
				oldIpVersion = "both"
			}
			// 获取新的IP版本（如果为空则默认为both）
			newIpVersion := newTunnel.IpVersion
			if newIpVersion == "" {
				newIpVersion = "both"
			}

			// 检查是否需要重启服务：状态变化或IP版本变化
			needRestart := oldTunnel.StartStatus != newTunnel.StartStatus || oldIpVersion != newIpVersion

			// 更新隧道信息
			for port := range oldPortMap {
				key := oldTunnel.Protocol + port
				// 更新隧道目标信息
				if tunnelSafe, ok := waf.TunnelTarget.Get(key); ok {
					tunnelSafe.Tunnel = newTunnel
					waf.TunnelTarget.Set(key, tunnelSafe)
				}
			}

			// 如果需要重启服务
			if needRestart {
				// 先移除旧的服务
				waf.RemoveTunnel(oldTunnel)
				// 如果新状态是启动的，重新加载
				if newTunnel.StartStatus != 0 {
					netRunTimes := waf.LoadTunnel(newTunnel)
					addedRunTimes = append(addedRunTimes, netRunTimes...)
				}
			}
			return addedRunTimes
		}
	}

	// 情况2和3：端口有变化

	// 处理减少的端口 - 需要移除
	for port := range oldPortMap {
		if !newPortMap[port] {
			// 这个端口在新配置中不存在，需要移除
			key := oldTunnel.Protocol + port
			if netRuntime, ok := waf.NetListerOnline.Get(key); ok {
				// 停止服务
				waf.StopTunnelServer(netRuntime)
				// 从在线列表中移除
				waf.NetListerOnline.Delete(key)
				// 从隧道目标中移除
				waf.TunnelTarget.Delete(key)
				zlog.Info("已移除隧道服务: " + oldTunnel.Protocol + " 端口: " + port)
			}
		}
	}

	// 处理新增的端口 - 需要添加
	for port := range newPortMap {
		if !oldPortMap[port] {
			// 这个端口在旧配置中不存在，需要添加
			portInt, err := strconv.Atoi(port)
			if err != nil {
				continue
			}

			key := newTunnel.Protocol + port
			_, ok := waf.NetListerOnline.Get(key)
			if !ok {
				// 不存在，创建一个
				netRuntime := waftunnelmodel.NetRunTime{
					ServerType: newTunnel.Protocol,
					Port:       portInt,
					Status:     newTunnel.StartStatus,
					Svr:        nil,
				}
				waf.NetListerOnline.Set(key, netRuntime)
				addedRunTimes = append(addedRunTimes, netRuntime)
			}
			// 设置或更新隧道基本信息
			waf.TunnelTarget.Set(key, &waftunnelmodel.TunnelSafe{
				Tunnel: newTunnel,
			})
		} else {
			// 端口相同但其他信息可能变了，检查是否需要重启服务
			key := newTunnel.Protocol + port
			if tunnelSafe, ok := waf.TunnelTarget.Get(key); ok {
				// 获取旧的IP版本（如果为空则默认为both）
				oldIpVersion := tunnelSafe.Tunnel.IpVersion
				if oldIpVersion == "" {
					oldIpVersion = "both"
				}
				// 获取新的IP版本（如果为空则默认为both）
				newIpVersion := newTunnel.IpVersion
				if newIpVersion == "" {
					newIpVersion = "both"
				}

				// 检查是否需要重启服务：状态变化或IP版本变化
				needRestart := tunnelSafe.Tunnel.StartStatus != newTunnel.StartStatus || oldIpVersion != newIpVersion

				// 更新隧道信息
				tunnelSafe.Tunnel = newTunnel
				waf.TunnelTarget.Set(key, tunnelSafe)

				// 如果需要重启服务
				if needRestart {
					// 获取当前的运行时信息
					if netRuntime, ok := waf.NetListerOnline.Get(key); ok {
						// 停止旧服务
						waf.StopTunnelServer(netRuntime)
						// 从在线列表中移除
						waf.NetListerOnline.Delete(key)
					}

					// 如果新状态是启动的，重新加载
					if newTunnel.StartStatus != 0 {
						portInt, err := strconv.Atoi(port)
						if err == nil {
							netRuntime := waftunnelmodel.NetRunTime{
								ServerType: newTunnel.Protocol,
								Port:       portInt,
								Status:     newTunnel.StartStatus,
								Svr:        nil,
							}
							waf.NetListerOnline.Set(key, netRuntime)
							addedRunTimes = append(addedRunTimes, netRuntime)
						}
					}
				}
			}
		}
	}

	return addedRunTimes
}

// RemoveTunnel 移除指定tunnel
func (waf *WafTunnelEngine) RemoveTunnel(inTunnel model.Tunnel) []waftunnelmodel.NetRunTime {
	removedRunTimes := make([]waftunnelmodel.NetRunTime, 0)

	// 处理端口
	portStr := inTunnel.Port
	portStrArray := strings.Split(portStr, ",")
	for _, portItem := range portStrArray {
		portItem = strings.TrimSpace(portItem)
		if portItem == "" {
			continue
		}
		_, err := strconv.Atoi(portItem)
		if err != nil {
			continue
		}

		key := inTunnel.Protocol + portItem // 唯一识别 协议+端口
		netRuntime, ok := waf.NetListerOnline.Get(key)
		if ok {
			// 存在，需要移除
			removedRunTimes = append(removedRunTimes, netRuntime)
			// 停止服务
			waf.StopTunnelServer(netRuntime)
			// 从在线列表中移除
			waf.NetListerOnline.Delete(key)
			// 从隧道目标中移除
			waf.TunnelTarget.Delete(key)
			zlog.Info("已移除隧道服务: " + inTunnel.Protocol + " 端口: " + portItem)
		}
	}

	return removedRunTimes
}

// StartAllTunnelServer 开启所有隧道服务
func (waf *WafTunnelEngine) StartAllTunnelServer() {
	netMap := waf.NetListerOnline.GetAll()
	for _, v := range netMap {
		waf.StartTunnelServer(v)
	}
	waf.EnumAllPortTunnelServer()
}

// EnumAllPortTunnelServer 罗列所有隧道端口
func (waf *WafTunnelEngine) EnumAllPortTunnelServer() {
	onlinePorts := ""
	netMap := waf.NetListerOnline.GetAll()
	for _, v := range netMap {
		onlinePorts = strconv.Itoa(v.Port) + "," + onlinePorts
	}
	// 可以将端口信息存储到全局变量中
	global.GWAF_RUNTIME_CURRENT_TUNNELPORT = onlinePorts
}

// StartTunnelServer 启动指定隧道服务
func (waf *WafTunnelEngine) StartTunnelServer(netRuntime waftunnelmodel.NetRunTime) {
	if netRuntime.Status == 0 {
		// 已启动完成的就不处理
		return
	}
	if netRuntime.ServerType == "" {
		// 如果协议类型为空就不处理
		return
	}

	go func(netRuntime waftunnelmodel.NetRunTime) {
		defer func() {
			e := recover()
			if e != nil {
				zlog.Warn("tunnel server recover ", e)
			}
		}()

		// 根据协议类型启动不同的服务
		switch strings.ToLower(netRuntime.ServerType) {
		case "tcp":
			waf.startTCPServer(netRuntime)
		case "udp":
			waf.startUDPServer(netRuntime)
		default:
			zlog.Warn("不支持的协议类型: " + netRuntime.ServerType)
		}
	}(netRuntime)
}

// StopAllTunnelServer 关闭所有隧道服务
func (waf *WafTunnelEngine) StopAllTunnelServer() {
	netMap := waf.NetListerOnline.GetAll()
	for _, v := range netMap {
		waf.StopTunnelServer(v)
	}
}

// StopTunnelServer 关闭指定隧道服务
func (waf *WafTunnelEngine) StopTunnelServer(netRuntime waftunnelmodel.NetRunTime) {
	portStr := strconv.Itoa(netRuntime.Port)

	// 关闭服务器
	if netRuntime.Svr != nil {
		// 根据不同类型关闭服务
		switch svr := netRuntime.Svr.(type) {
		case net.Listener:
			svr.Close()
		case *net.UDPConn:
			svr.Close()
		}
	}

	// 获取详细的连接统计
	tcpSourceCount := waf.TCPConnections.GetPortConnsCountByType(netRuntime.Port, waftunnelmodel.ConnTypeSource)
	tcpTargetCount := waf.TCPConnections.GetPortConnsCountByType(netRuntime.Port, waftunnelmodel.ConnTypeTarget)
	udpSourceCount := waf.UDPConnections.GetPortConnsCountByType(netRuntime.Port, waftunnelmodel.ConnTypeSource)
	udpTargetCount := waf.UDPConnections.GetPortConnsCountByType(netRuntime.Port, waftunnelmodel.ConnTypeTarget)

	// 总连接数
	tcpCount := tcpSourceCount + tcpTargetCount
	udpCount := udpSourceCount + udpTargetCount

	if tcpCount > 0 || udpCount > 0 {
		zlog.Info("正在关闭端口 " + portStr + " 的连接: " +
			"TCP总计=" + strconv.Itoa(tcpCount) +
			"(来源=" + strconv.Itoa(tcpSourceCount) +
			",目标=" + strconv.Itoa(tcpTargetCount) + "), " +
			"UDP总计=" + strconv.Itoa(udpCount) +
			"(来源=" + strconv.Itoa(udpSourceCount) +
			",目标=" + strconv.Itoa(udpTargetCount) + ")")

		waf.TCPConnections.ClosePortConns(netRuntime.Port)
		waf.UDPConnections.ClosePortConns(netRuntime.Port)
	}
}
