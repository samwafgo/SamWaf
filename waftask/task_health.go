package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/wafenginecore"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// healthTransportPool 复用 Transport，按实际拨号地址(ip:port)缓存，避免每次健康检测都创建新对象
var (
	healthTransportMu   sync.RWMutex
	healthTransportPool = make(map[string]*http.Transport)
)

// cleanupStaleTransports 关闭并删除不再使用的后端对应的 Transport，防止长期积累
func cleanupStaleTransports(validDialAddrs map[string]struct{}) {
	healthTransportMu.Lock()
	defer healthTransportMu.Unlock()
	for addr, t := range healthTransportPool {
		if _, ok := validDialAddrs[addr]; !ok {
			t.CloseIdleConnections()
			delete(healthTransportPool, addr)
		}
	}
}

func getHealthTransport(dialAddr string) *http.Transport {
	healthTransportMu.RLock()
	if t, ok := healthTransportPool[dialAddr]; ok {
		healthTransportMu.RUnlock()
		return t
	}
	healthTransportMu.RUnlock()

	healthTransportMu.Lock()
	defer healthTransportMu.Unlock()
	if t, ok := healthTransportPool[dialAddr]; ok {
		return t
	}
	captured := dialAddr
	t := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 2,
		// 空闲连接超过 90s 自动关闭，防止后端长期不可达时连接僵死
		IdleConnTimeout: 90 * time.Second,
		// 始终拨号到固定后端地址，忽略 URL 中的 host 部分
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, captured)
		},
	}
	healthTransportPool[dialAddr] = t
	return t
}

// buildValidKeys 根据当前运行的主机列表，同时返回：
//   - statusKeys：合法的 HealthyStatus map key（hostCode_backendID）
//   - dialAddrs：合法的 Transport Pool key（ip:port）
func buildValidKeys(hosts []model.Hosts) (statusKeys map[string]struct{}, dialAddrs map[string]struct{}) {
	statusKeys = make(map[string]struct{})
	dialAddrs = make(map[string]struct{})
	for _, host := range hosts {
		if host.IsEnableLoadBalance > 0 {
			loadBalances := waf_service.WafLoadBalanceServiceApp.GetListByHostCodeApi(host.Code)
			for i, lb := range loadBalances {
				statusKeys[host.Code+"_"+fmt.Sprintf("%d", i)] = struct{}{}
				if lb.Remote_ip != "" {
					dialAddrs[net.JoinHostPort(lb.Remote_ip, strconv.Itoa(lb.Remote_port))] = struct{}{}
				}
			}
		} else {
			statusKeys[host.Code+"_single"] = struct{}{}
			if host.Remote_ip != "" {
				dialAddrs[net.JoinHostPort(host.Remote_ip, strconv.Itoa(host.Remote_port))] = struct{}{}
			}
		}
	}
	return
}

// TaskHealth 后端主机状态检查
func TaskHealth() {
	// 检查是否收到关闭信号
	if global.GWAF_SHUTDOWN_SIGNAL {
		zlog.Info("TaskHealth - Shutdown")
		return
	}

	zlog.Debug("TaskHealth - 开始执行后端健康度检测")
	hosts := waf_service.WafHostServiceApp.GetAllRunningHostApi()

	maxConcurrent := 5
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	// 整体超时略小于调度间隔（30s），防止任务无限期阻塞导致后续触发全部被跳过
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	for _, host := range hosts {
		// 检查关闭信号
		if global.GWAF_SHUTDOWN_SIGNAL {
			zlog.Debug("TaskHealth - Shutdown detected")
			cancel()
			break
		}

		// 检查上下文是否已取消
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(h model.Hosts) {
			defer func() {
				<-sem
				wg.Done()
			}()
			checkHostHealth(h, ctx)
		}(host)
	}

	wg.Wait()
	close(sem)

	// 清理已删除主机/后端的残留条目，防止内存/连接持续增长
	statusKeys, dialAddrs := buildValidKeys(hosts)
	wafenginecore.CleanupStaleHealthStatus(statusKeys)
	cleanupStaleTransports(dialAddrs)

	zlog.Debug("TaskHealth - 后端健康度检测完成")
}

// checkHostHealth 检查单个主机的健康状态
func checkHostHealth(host model.Hosts, ctx context.Context) {
	// 解析健康检测配置
	var healthyConfig model.HealthyConfig
	err := json.Unmarshal([]byte(host.HealthyJSON), &healthyConfig)
	if err != nil {
		// 设置默认配置
		healthyConfig = model.HealthyConfig{
			IsEnableHealthy: 1, // 默认启用健康检测
			FailCount:       3,
			SuccessCount:    3,
			ResponseTime:    5,     // 默认5秒超时
			CheckMethod:     "GET", // 默认使用GET方法
			CheckPath:       "/",   // 默认检测根路径
			ExpectedCodes:   "200,",
		}

	}

	// 检查是否启用健康检测
	if healthyConfig.IsEnableHealthy != 1 {
		return
	}

	// 检查是否是负载均衡
	if host.IsEnableLoadBalance > 0 {
		// 获取负载均衡列表
		loadBalances := waf_service.WafLoadBalanceServiceApp.GetListByHostCodeApi(host.Code)
		if loadBalances == nil {
			return
		}
		// 检查每个后端服务器，整体预算耗尽时停止派发新检测
		for i, lb := range loadBalances {
			if ctx.Err() != nil {
				return
			}
			backendID := fmt.Sprintf("%d", i)
			checkBackendHealth(host, lb.Remote_ip, lb.Remote_port, healthyConfig, backendID)
		}
	} else {
		// 非负载均衡情况，只检查单一后端
		checkBackendHealth(host, host.Remote_ip, host.Remote_port, healthyConfig, "single")
	}
}

// checkBackendHealth 检查后端服务器健康状态
// 注意：不接收外部 ctx，内部自行创建 config.ResponseTime 超时的独立 context，
// 防止整体 TaskHealth 超时取消时误判慢但健康的后端为不健康
func checkBackendHealth(host model.Hosts, ip string, port int, config model.HealthyConfig, backendID string) {
	// 使用配置的检测路径
	checkPath := "/"
	if config.CheckPath != "" {
		checkPath = config.CheckPath
	}

	mainHost := host.Remote_host + ":" + strconv.Itoa(host.Remote_port)
	if host.Host == "*" {
		mainHost = strings.ReplaceAll(host.Remote_host, "*", host.Remote_ip) + ":" + strconv.Itoa(host.Remote_port)
	}
	// 构建检测URL
	checkURL := fmt.Sprintf("%s%s", mainHost, checkPath)

	// 校验 checkURL 是否可健康检测：空 host 或包含未解析的通配符 * 均无法检测
	// 这类情况属于"无法检测"而非"不健康"，直接跳过，不改变后端健康状态
	parsedURL, parseErr := url.Parse(checkURL)
	if parseErr != nil || parsedURL.Host == "" || strings.Contains(parsedURL.Host, "*") {
		zlog.Warn("健康检测跳过：URL 无效或包含未解析通配符",
			"主机", host.Host, "后端ID", backendID, "URL", checkURL)
		return
	}

	// 打印请求信息
	zlog.Debug("健康检测请求", "主机", host.Host, "后端ID", backendID, "URL", checkURL, "方法", config.CheckMethod)

	// 解析预期状态码
	expectedCodes := parseExpectedCodes(config.ExpectedCodes)

	// 确定实际拨号地址，优先使用明确配置的后端 IP
	var dialAddr string
	if host.IsEnableLoadBalance > 0 {
		dialAddr = net.JoinHostPort(ip, strconv.Itoa(port))
	} else if host.Remote_ip != "" {
		dialAddr = net.JoinHostPort(host.Remote_ip, strconv.Itoa(host.Remote_port))
	} else {
		dialAddr = parsedURL.Host // 回退到 URL 中的 host，由系统 DNS 解析
	}

	transport := getHealthTransport(dialAddr)

	// 每个请求独立创建超时 context，与 TaskHealth 整体超时隔离：
	// 即使整体 25s 预算到期，已在途的请求不会被取消，不会误判为不健康
	reqCtx, reqCancel := context.WithTimeout(context.Background(), time.Duration(config.ResponseTime)*time.Second)
	defer reqCancel()

	client := &http.Client{Transport: transport}

	// 创建请求
	req, err := http.NewRequestWithContext(reqCtx, config.CheckMethod, checkURL, nil)
	if err != nil {
		zlog.Debug("健康检测请求创建失败", "错误", err.Error())
		updateHealthStatus(host.Code, backendID, false, 0, "创建请求失败: "+err.Error(), ip, port, config)
		return
	}
	// 添加Host头
	if host.IsTransBackDomain == 1 {
		// 拆分主机名和端口
		hostPort := strings.Split(host.Remote_host, ":")
		if len(hostPort) == 2 {
			if req.Host != hostPort[0] {
				req.Host = hostPort[0]
			}
		}
	}

	// 打印请求头信息
	zlog.Debug("健康检测请求头", "Host", req.Host, "后端IP", ip, "后端端口", port)

	// 记录开始时间
	startTime := time.Now()

	// 发送请求
	resp, err := client.Do(req)

	// 计算响应时间
	responseTime := time.Since(startTime).Milliseconds()

	if err != nil {
		zlog.Debug("健康检测请求失败", "错误", err.Error(), "耗时(ms)", responseTime)
		updateHealthStatus(host.Code, backendID, false, responseTime, "请求失败: "+err.Error(), ip, port, config)
		return
	}
	defer resp.Body.Close()

	// 打印响应信息
	zlog.Debug("健康检测响应",
		"后端ID", backendID,
		"状态码", resp.StatusCode,
		"状态", resp.Status,
		"耗时(ms)", responseTime,
		"响应头", fmt.Sprintf("%v", resp.Header))

	// 最多读取 4KB 响应体，确保 TCP 连接能被正确归还，同时防止大响应体造成内存峰值
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	// 检查状态码是否符合预期
	isHealthy := false
	for _, code := range expectedCodes {
		if resp.StatusCode == code {
			isHealthy = true
			break
		}
	}

	if isHealthy {
		zlog.Debug("健康检测结果", "后端ID", backendID, "状态", "健康", "耗时(ms)", responseTime)
		updateHealthStatus(host.Code, backendID, true, responseTime, "", ip, port, config)
	} else {
		zlog.Debug("健康检测结果", "后端ID", backendID, "状态", "不健康", "耗时(ms)", responseTime, "原因", "状态码不符合预期")
		updateHealthStatus(host.Code, backendID, false, responseTime, checkURL+"状态码不符合预期: "+strconv.Itoa(resp.StatusCode), ip, port, config)
	}
}

// updateHealthStatus 更新健康状态
func updateHealthStatus(hostCode, backendID string, isSuccess bool, responseTime int64, errorReason string, ip string, port int, config model.HealthyConfig) {
	// 获取全局状态管理器
	hostStatus := wafenginecore.GetHostStatus()

	// 获取或创建主机健康状态
	hostStatus.Mux.Lock()
	defer hostStatus.Mux.Unlock()

	if hostStatus.HealthyStatus == nil {
		hostStatus.HealthyStatus = make(map[string]*wafenginmodel.HostHealthy)
	}

	// 生成唯一键
	key := hostCode + "_" + backendID

	// 获取或创建健康状态
	status, exists := hostStatus.HealthyStatus[key]
	if !exists {
		status = &wafenginmodel.HostHealthy{
			IsHealthy:     true, // 初始状态为健康
			LastCheckTime: time.Now(),
			BackIP:        ip,
			BackPort:      port,
		}
		hostStatus.HealthyStatus[key] = status
	}

	// 更新状态
	status.LastCheckTime = time.Now()

	if isSuccess {
		status.SuccessCount++
		status.FailCount = 0
		status.LastErrorReason = ""

		// 如果连续成功次数达到阈值，标记为健康
		if !status.IsHealthy && status.SuccessCount >= config.SuccessCount {
			status.IsHealthy = true
			if status.SuccessCount > 1000 {
				status.SuccessCount = 0
			}
			zlog.Info("健康检测", "后端服务器恢复健康", key)
		}
	} else {
		status.FailCount++
		status.SuccessCount = 0
		status.LastErrorReason = errorReason

		// 如果连续失败次数达到阈值，标记为不健康
		if status.IsHealthy && status.FailCount >= config.FailCount {
			status.IsHealthy = false
			if status.FailCount > 1000 {
				status.FailCount = 0 // 修复：此处应重置 FailCount 而非 SuccessCount
			}
			zlog.Info("健康检测", "后端服务器不健康", key, errorReason)
		}
	}
}

// parseExpectedCodes 解析预期状态码
func parseExpectedCodes(codesStr string) []int {
	if codesStr == "" {
		// 默认接受的状态码
		return []int{200, 201, 202, 203, 204, 301, 302, 303, 307, 308}
	}

	parts := strings.Split(codesStr, ",")
	codes := make([]int, 0, len(parts))

	for _, part := range parts {
		code, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil {
			codes = append(codes, code)
		}
	}

	if len(codes) == 0 {
		// 如果没有有效的状态码，使用默认值
		return []int{200, 201, 202, 203, 204, 301, 302, 303, 307, 308}
	}

	return codes
}
