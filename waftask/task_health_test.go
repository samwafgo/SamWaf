package waftask

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore"
	"SamWaf/wafhealth"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func isolateHealthStatus(t *testing.T) *wafenginmodel.HostStatus {
	t.Helper()
	status := wafenginecore.GetHostStatus()
	status.Mux.Lock()
	previous := status.HealthyStatus
	status.HealthyStatus = make(map[string]*wafenginmodel.HostHealthy)
	status.Mux.Unlock()
	t.Cleanup(func() {
		status.Mux.Lock()
		status.HealthyStatus = previous
		status.Mux.Unlock()
		wafhealth.CleanupTransports(nil)
	})
	return status
}

func TestHealthThresholdTransitions(t *testing.T) {
	config := model.HealthyConfig{FailCount: 3, SuccessCount: 2}
	status := &wafenginmodel.HostHealthy{IsHealthy: true, BackIP: "127.0.0.1", BackPort: 8080}
	for i := 1; i <= 3; i++ {
		changed := applyHealthResult(status, false, "failed", config)
		if changed != (i == 3) || status.IsHealthy != (i < 3) || status.FailCount != i || status.SuccessCount != 0 {
			t.Fatalf("failure %d: %+v, changed=%v", i, status, changed)
		}
	}
	if status.LastErrorReason != "failed" || status.LastCheckTime.IsZero() {
		t.Fatalf("failure metadata: %+v", status)
	}
	for i := 1; i <= 2; i++ {
		changed := applyHealthResult(status, true, "", config)
		if changed != (i == 2) || status.IsHealthy != (i == 2) || status.SuccessCount != i || status.FailCount != 0 || status.LastErrorReason != "" {
			t.Fatalf("success %d: %+v, changed=%v", i, status, changed)
		}
	}
	for i := 0; i < 4; i++ {
		if applyHealthResult(status, false, "failed", config) || !status.IsHealthy || status.SuccessCount != 0 || status.FailCount != 1 {
			t.Fatalf("alternating failure: %+v", status)
		}
		if applyHealthResult(status, true, "", config) || !status.IsHealthy || status.FailCount != 0 || status.SuccessCount != 1 {
			t.Fatalf("alternating success: %+v", status)
		}
	}
	if status.BackIP != "127.0.0.1" || status.BackPort != 8080 {
		t.Fatalf("backend metadata: %+v", status)
	}
}

func TestHealthThresholdLargeCounterReset(t *testing.T) {
	config := model.HealthyConfig{FailCount: 1001, SuccessCount: 1001}
	status := &wafenginmodel.HostHealthy{IsHealthy: true, FailCount: 1000}
	if !applyHealthResult(status, false, "failed", config) || status.IsHealthy || status.FailCount != 0 {
		t.Fatalf("failure reset: %+v", status)
	}
	status.SuccessCount = 1000
	if !applyHealthResult(status, true, "", config) || !status.IsHealthy || status.SuccessCount != 0 {
		t.Fatalf("success reset: %+v", status)
	}
}

func TestHealthStatusIsolationAndCleanup(t *testing.T) {
	isolateHealthStatus(t)
	config := model.HealthyConfig{FailCount: 2, SuccessCount: 2}
	if !wafenginecore.IsBackendHealthy("a", "single") {
		t.Fatal("new backend should be healthy")
	}
	updateHealthStatus("a", "single", false, 10, "failed", "127.0.0.1", 8080, config)
	if !wafenginecore.IsBackendHealthy("a", "single") {
		t.Fatal("first failure changed status")
	}
	updateHealthStatus("a", "single", false, 10, "failed", "127.0.0.1", 8080, config)
	updateHealthStatus("b", "single", true, 10, "", "127.0.0.2", 8081, config)
	updateHealthStatus("a", "0", true, 10, "", "127.0.0.3", 8082, config)
	if wafenginecore.IsBackendHealthy("a", "single") || !wafenginecore.IsBackendHealthy("b", "single") || !wafenginecore.IsBackendHealthy("a", "0") {
		t.Fatal("host/backend states crossed")
	}
	wafenginecore.CleanupStaleHealthStatus(map[string]struct{}{"b_single": {}})
	if wafenginecore.GetBackendHealthy("a", "single") != nil || wafenginecore.GetBackendHealthy("a", "0") != nil || wafenginecore.GetBackendHealthy("b", "single") == nil {
		t.Fatal("stale status cleanup failed")
	}
}

func TestHealthScheduledConfig(t *testing.T) {
	want := model.HealthyConfig{IsEnableHealthy: 1, FailCount: 3, SuccessCount: 3, ResponseTime: 5, CheckMethod: "GET", CheckPath: "/", ExpectedCodes: "200,"}
	for _, raw := range []string{"", "{", `{"response_time":"5"}`} {
		if got := scheduledHealthConfig(raw); got != want {
			t.Fatalf("%q: %+v", raw, got)
		}
	}
	for _, raw := range []string{"{}", "null"} {
		if got := scheduledHealthConfig(raw); got != (model.HealthyConfig{}) {
			t.Fatalf("%q must keep zero values: %+v", raw, got)
		}
	}
	if got := scheduledHealthConfig(`{"is_enable_healthy":1,"response_time":0,"check_method":"","expected_codes":""}`); got.ResponseTime != 0 || got.CheckMethod != "" || got.ExpectedCodes != "" {
		t.Fatalf("valid config defaulted: %+v", got)
	}
}

func TestHealthDisabledAndSkippedNoMutation(t *testing.T) {
	status := isolateHealthStatus(t)
	initial := &wafenginmodel.HostHealthy{IsHealthy: false, FailCount: 7, LastErrorReason: "previous", LastCheckTime: time.Unix(10, 0), BackIP: "127.0.0.1", BackPort: 80}
	status.HealthyStatus["site_single"] = initial
	before := *initial
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	host := model.Hosts{Code: "site", Host: "site.example", Remote_host: "http://url.example", Remote_ip: "127.0.0.1", Remote_port: port, HealthyJSON: `{"is_enable_healthy":0}`}
	checkHostHealth(host, context.Background())
	if calls.Load() != 0 || !reflect.DeepEqual(before, *initial) {
		t.Fatal("disabled check mutated state or sent request")
	}
	host.HealthyJSON = `{"is_enable_healthy":1,"response_time":1,"check_method":"GET"}`
	host.Remote_host = "http://*.example"
	checkHostHealth(host, context.Background())
	host.Code = "new-site"
	checkHostHealth(host, context.Background())
	if calls.Load() != 0 || !reflect.DeepEqual(before, *initial) || len(status.HealthyStatus) != 1 {
		t.Fatal("skipped check mutated state or sent request")
	}
}

func TestHealthScheduledIndependentTimeout(t *testing.T) {
	isolateHealthStatus(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	host := model.Hosts{Code: "site", Host: "site.example", Remote_host: "http://url.example", Remote_ip: "127.0.0.1", Remote_port: port,
		HealthyJSON: `{"is_enable_healthy":1,"response_time":1,"check_method":"GET","expected_codes":"204","fail_count":1,"success_count":1}`}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checkHostHealth(host, ctx)
	got := wafenginecore.GetBackendHealthy("site", "single")
	if got == nil || !got.IsHealthy || got.SuccessCount != 1 || got.FailCount != 0 {
		t.Fatalf("single scheduled probe canceled by dispatch context: %+v", got)
	}
	host.HealthyJSON = `{"is_enable_healthy":1,"response_time":1,"check_method":"GET","expected_codes":"200","fail_count":1,"success_count":1}`
	checkHostHealth(host, context.Background())
	if got.IsHealthy || got.FailCount != 1 || got.SuccessCount != 0 {
		t.Fatalf("failed probe not applied: %+v", got)
	}
}

func TestHealthValidSingleKeys(t *testing.T) {
	hosts := []model.Hosts{
		{Code: "ipv4", Remote_ip: "127.0.0.1", Remote_port: 8080},
		{Code: "ipv6", Remote_ip: "::1", Remote_port: 8081},
		{Code: "dns", Remote_host: "http://example.test", Remote_port: 80},
	}
	keys, addrs := buildValidKeys(hosts)
	if !reflect.DeepEqual(keys, map[string]struct{}{"ipv4_single": {}, "ipv6_single": {}, "dns_single": {}}) {
		t.Fatalf("keys: %v", keys)
	}
	if !reflect.DeepEqual(addrs, map[string]struct{}{"127.0.0.1:8080": {}, "[::1]:8081": {}}) {
		t.Fatalf("dial addresses: %v", addrs)
	}
}
