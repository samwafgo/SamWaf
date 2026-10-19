package wafenginecore

import (
	"SamWaf/model/wafenginmodel"
	"testing"
)

func TestCleanupHostHealthStatus(t *testing.T) {
	status := GetHostStatus()
	status.Mux.Lock()
	previous := status.HealthyStatus
	status.HealthyStatus = map[string]*wafenginmodel.HostHealthy{
		"site1_single": {},
		"site1_0":      {},
		"site1_1":      {},
		"site2_single": {},
	}
	status.Mux.Unlock()
	t.Cleanup(func() {
		status.Mux.Lock()
		status.HealthyStatus = previous
		status.Mux.Unlock()
	})

	CleanupHostHealthStatus("site1")
	if GetBackendHealthy("site1", "single") != nil || GetBackendHealthy("site1", "0") != nil || GetBackendHealthy("site1", "1") != nil {
		t.Fatal("site1 entries not cleaned")
	}
	if GetBackendHealthy("site2", "single") == nil {
		t.Fatal("site2 entry should be kept")
	}
	// 前缀带下划线：清理 site 不能误伤 site1/site2
	CleanupHostHealthStatus("site")
	if GetBackendHealthy("site2", "single") == nil {
		t.Fatal("prefix without underscore must not match site2")
	}
}
