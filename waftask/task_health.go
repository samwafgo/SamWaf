package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/wafenginecore"
	"SamWaf/wafhealth"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// buildValidKeys returns active status keys and transport dial addresses.
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
	if global.GWAF_SHUTDOWN_SIGNAL {
		zlog.Info("TaskHealth - Shutdown")
		return
	}
	zlog.Debug("TaskHealth - 开始执行后端健康度检测")
	hosts := waf_service.WafHostServiceApp.GetAllRunningHostApi()
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	for _, host := range hosts {
		if global.GWAF_SHUTDOWN_SIGNAL {
			zlog.Debug("TaskHealth - Shutdown detected")
			cancel()
			break
		}
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
	statusKeys, dialAddrs := buildValidKeys(hosts)
	wafenginecore.CleanupStaleHealthStatus(statusKeys)
	wafhealth.CleanupTransports(dialAddrs)
	zlog.Debug("TaskHealth - 后端健康度检测完成")
}

func scheduledHealthConfig(raw string) model.HealthyConfig {
	var config model.HealthyConfig
	if json.Unmarshal([]byte(raw), &config) != nil {
		config = model.HealthyConfig{
			IsEnableHealthy: 1,
			FailCount:       3,
			SuccessCount:    3,
			ResponseTime:    5,
			CheckMethod:     "GET",
			CheckPath:       "/",
			ExpectedCodes:   "200,",
		}
	}
	return config
}

// checkHostHealth 检查单个主机的健康状态
func checkHostHealth(host model.Hosts, ctx context.Context) {
	config := scheduledHealthConfig(host.HealthyJSON)
	if config.IsEnableHealthy != 1 {
		return
	}
	if host.IsEnableLoadBalance > 0 {
		loadBalances := waf_service.WafLoadBalanceServiceApp.GetListByHostCodeApi(host.Code)
		if loadBalances == nil {
			return
		}
		for i, lb := range loadBalances {
			if ctx.Err() != nil {
				return
			}
			checkBackendHealth(host, lb.Remote_ip, lb.Remote_port, config, fmt.Sprintf("%d", i))
		}
	} else {
		checkBackendHealth(host, host.Remote_ip, host.Remote_port, config, "single")
	}
}

// Scheduled probes have an independent per-request timeout.
func checkBackendHealth(host model.Hosts, ip string, port int, config model.HealthyConfig, backendID string) {
	result := wafhealth.Probe(context.Background(), host, ip, port, config, backendID, true)
	if result.Outcome == wafhealth.Skipped {
		zlog.Warn("健康检测跳过", "主机", host.Host, "后端ID", backendID, "URL", result.URL, "原因", result.ErrorReason)
		return
	}
	zlog.Debug("健康检测结果", "后端ID", backendID, "URL", result.URL, "方法", result.Method,
		"Host", result.RequestHost, "后端IP", ip, "后端端口", port, "状态码", result.StatusCode,
		"状态", result.Outcome, "耗时(ms)", result.ElapsedMS, "原因", result.ErrorReason)
	updateHealthStatus(host.Code, backendID, result.Outcome == wafhealth.Passed, result.ElapsedMS, result.ErrorReason, ip, port, config)
}

// updateHealthStatus 更新健康状态
func updateHealthStatus(hostCode, backendID string, isSuccess bool, responseTime int64, errorReason string, ip string, port int, config model.HealthyConfig) {
	hostStatus := wafenginecore.GetHostStatus()
	hostStatus.Mux.Lock()
	defer hostStatus.Mux.Unlock()
	if hostStatus.HealthyStatus == nil {
		hostStatus.HealthyStatus = make(map[string]*wafenginmodel.HostHealthy)
	}
	key := hostCode + "_" + backendID
	status, exists := hostStatus.HealthyStatus[key]
	if !exists {
		status = &wafenginmodel.HostHealthy{
			IsHealthy:     true,
			LastCheckTime: time.Now(),
			BackIP:        ip,
			BackPort:      port,
		}
		hostStatus.HealthyStatus[key] = status
	}
	if applyHealthResult(status, isSuccess, errorReason, config) {
		if status.IsHealthy {
			zlog.Info("健康检测", "后端服务器恢复健康", key)
		} else {
			zlog.Info("健康检测", "后端服务器不健康", key, errorReason)
		}
	}
}

func applyHealthResult(status *wafenginmodel.HostHealthy, isSuccess bool, errorReason string, config model.HealthyConfig) bool {
	status.LastCheckTime = time.Now()
	if isSuccess {
		status.SuccessCount++
		status.FailCount = 0
		status.LastErrorReason = ""
		if !status.IsHealthy && status.SuccessCount >= config.SuccessCount {
			status.IsHealthy = true
			if status.SuccessCount > 1000 {
				status.SuccessCount = 0
			}
			return true
		}
	} else {
		status.FailCount++
		status.SuccessCount = 0
		status.LastErrorReason = errorReason
		if status.IsHealthy && status.FailCount >= config.FailCount {
			status.IsHealthy = false
			if status.FailCount > 1000 {
				status.FailCount = 0
			}
			return true
		}
	}
	return false
}
