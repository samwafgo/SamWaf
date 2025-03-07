package wafenginecore

import (
	"SamWaf/model/wafenginmodel"
)

var hostStatus = &wafenginmodel.HostStatus{}

// GetHostStatus 获取主机状态管理器
func GetHostStatus() *wafenginmodel.HostStatus {
	return hostStatus
}

// IsBackendHealthy 检查后端服务器是否健康
func IsBackendHealthy(hostCode string, backendID string) bool {
	hostStatus.Mux.Lock()
	defer hostStatus.Mux.Unlock()

	if hostStatus.HealthyStatus == nil {
		return true // 默认健康
	}

	key := hostCode + "_" + backendID
	status, exists := hostStatus.HealthyStatus[key]
	if !exists {
		return true // 默认健康
	}

	return status.IsHealthy
}

// GetBackendHealthy 通过信息获取状态
func GetBackendHealthy(hostCode string, backendID string) *wafenginmodel.HostHealthy {
	hostStatus.Mux.Lock()
	defer hostStatus.Mux.Unlock()

	if hostStatus.HealthyStatus == nil {
		return nil // 默认健康
	}

	key := hostCode + "_" + backendID
	status, exists := hostStatus.HealthyStatus[key]
	if exists {
		return status
	} else {
		return nil
	}
}
