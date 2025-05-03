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
	"strconv"
	"strings"
	"sync"
	"time"
)

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

	// 创建一个上下文，用于在收到关闭信号时取消所有正在进行的检查
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动一个协程监控关闭信号
	go func() {
		for {
			if global.GWAF_SHUTDOWN_SIGNAL {
				zlog.Info("TaskHealth - Shutdown ")
				cancel()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	for _, host := range hosts {
		// 检查上下文是否已取消
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h model.Hosts) {
			defer func() {
				<-sem // 释放信号量
				wg.Done()
			}()
			checkHostHealth(h)
		}(host)
	}

	wg.Wait()
	close(sem)
	zlog.Debug("TaskHealth - 后端健康度检测完成")
}

// checkHostHealth 检查单个主机的健康状态
func checkHostHealth(host model.Hosts) {
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
		// 检查每个后端服务器
		for i, lb := range loadBalances {
			backendID := fmt.Sprintf("%d", i)
			checkBackendHealth(host, lb.Remote_ip, lb.Remote_port, healthyConfig, backendID)
		}
	} else {
		// 非负载均衡情况，只检查单一后端
		checkBackendHealth(host, host.Remote_ip, host.Remote_port, healthyConfig, "single")
	}
}

// checkBackendHealth 检查后端服务器健康状态
func checkBackendHealth(host model.Hosts, ip string, port int, config model.HealthyConfig, backendID string) {
	// 使用配置的检测路径
	checkPath := "/"
	if config.CheckPath != "" {
		checkPath = config.CheckPath
	}
	mainHost := host.Remote_host + ":" + strconv.Itoa(host.Remote_port)

	// 构建检测URL
	checkURL := fmt.Sprintf("%s%s", mainHost, checkPath)

	// 打印请求信息
	zlog.Debug("健康检测请求", "主机", host.Host, "后端ID", backendID, "URL", checkURL, "方法", config.CheckMethod)

	// 解析预期状态码
	expectedCodes := parseExpectedCodes(config.ExpectedCodes)

	client := &http.Client{
		Timeout: time.Duration(config.ResponseTime) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ResponseHeaderTimeout: time.Duration(config.ResponseTime) * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: time.Duration(config.ResponseTime) * time.Second,
				}
				if host.IsEnableLoadBalance > 0 {
					conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(port)))
					if err == nil {
						return conn, nil
					}
				} else {
					if host.Remote_ip != "" {
						conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(host.Remote_ip, strconv.Itoa(host.Remote_port)))
						if err == nil {
							return conn, nil
						}
					}
				}

				return dialer.DialContext(ctx, network, addr)
			},
		},
	}

	// 创建请求
	req, err := http.NewRequest(config.CheckMethod, checkURL, nil)
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

	// 读取响应体内容（限制大小，避免过大）
	var bodyBytes []byte
	if resp.ContentLength > 0 && resp.ContentLength < 1024 {
		bodyBytes = make([]byte, resp.ContentLength)
		_, err = resp.Body.Read(bodyBytes)
		if err == nil || err == io.EOF {
			zlog.Debug("健康检测响应体", "内容", string(bodyBytes))
		}
	} else {
		// 如果响应体太大或未知大小，只读取前512字节
		bodyBytes = make([]byte, 512)
		n, err := resp.Body.Read(bodyBytes)
		if err == nil || err == io.EOF {
			zlog.Debug("健康检测响应体(部分)", "内容", string(bodyBytes[:n]))
		}
	}

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
				status.SuccessCount = 0
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
