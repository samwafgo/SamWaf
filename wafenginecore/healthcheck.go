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

// CleanupStaleHealthStatus 删除不再运行的主机/后端在 map 中的残留条目，防止内存持续增长
func CleanupStaleHealthStatus(validKeys map[string]struct{}) {
	hostStatus.Mux.Lock()
	defer hostStatus.Mux.Unlock()
	for k := range hostStatus.HealthyStatus {
		if _, ok := validKeys[k]; !ok {
			delete(hostStatus.HealthyStatus, k)
		}
	}
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
