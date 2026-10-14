package api

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/wafenginecore"
	"SamWaf/wafhealth"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

func healthTestRequest(t *testing.T, server *httptest.Server) request.WafHostHealthTestReq {
	t.Helper()
	ip, rawPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(rawPort)
	cfg := model.HealthyConfig{IsEnableHealthy: 0, FailCount: 3, SuccessCount: 3, ResponseTime: 2, CheckMethod: "GET", CheckPath: "/health?source=test", ExpectedCodes: "200,"}
	raw, _ := json.Marshal(cfg)
	return request.WafHostHealthTestReq{Host: "demo.example", RemoteHost: "http://origin.example", RemoteIP: ip, RemotePort: port, HealthyJSON: string(raw), Limit: 5}
}

func callHealthTest(t *testing.T, req request.WafHostHealthTestReq) (int, waf_service.HealthTestResponse, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/test", func(c *gin.Context) { c.Set("is_openapi", true); new(WafHostAPi).TestHealthApi(c) })
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, httpReq)
	var res struct {
		Code int                            `json:"code"`
		Data waf_service.HealthTestResponse `json:"data"`
		Msg  string                         `json:"msg"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return res.Code, res.Data, res.Msg
}

func TestHealthTestValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	base := healthTestRequest(t, server)
	tests := []struct {
		name   string
		change func(*request.WafHostHealthTestReq)
	}{
		{"bad json", func(r *request.WafHostHealthTestReq) { r.HealthyJSON = "{" }},
		{"wrong method", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, "GET", "POST")
		}},
		{"timeout zero", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, `"response_time":2`, `"response_time":0`)
		}},
		{"timeout large", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, `"response_time":2`, `"response_time":121`)
		}},
		{"counts", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, `"fail_count":3`, `"fail_count":11`)
		}},
		{"absolute path", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, "/health?source=test", "http://other.example/")
		}},
		{"relative host", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, "/health?source=test", "//other.example/")
		}},
		{"fragment", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, "/health?source=test", "/health#fragment")
		}},
		{"codes", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, "200,", "invalid,")
		}},
		{"codes range", func(r *request.WafHostHealthTestReq) {
			r.HealthyJSON = strings.ReplaceAll(r.HealthyJSON, "200,", "600,")
		}},
		{"invalid ip", func(r *request.WafHostHealthTestReq) { r.RemoteIP = "invalid" }},
		{"invalid port", func(r *request.WafHostHealthTestReq) { r.RemotePort = 65536 }},
		{"origin userinfo", func(r *request.WafHostHealthTestReq) { r.RemoteHost = "http://user:secret@origin.example" }},
		{"origin port", func(r *request.WafHostHealthTestReq) { r.RemoteHost = "http://origin.example:80" }},
		{"origin path", func(r *request.WafHostHealthTestReq) { r.RemoteHost = "http://origin.example/path" }},
		{"origin scheme", func(r *request.WafHostHealthTestReq) { r.RemoteHost = "ftp://origin.example" }},
		{"origin control", func(r *request.WafHostHealthTestReq) { r.RemoteHost = "http://origin.example\r\n" }},
		{"offset", func(r *request.WafHostHealthTestReq) { r.Offset = -1 }},
		{"batch", func(r *request.WafHostHealthTestReq) { r.Limit = 6 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := base
			test.change(&req)
			if _, err := validateHealthTest(&req); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	base.Limit = 0
	if _, err := validateHealthTest(&base); err != nil || base.Limit != 5 {
		t.Fatalf("default batch: %v %d", err, base.Limit)
	}
}

func TestHealthTestUnsavedConfigurationNoSideEffects(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.RequestURI() != "/health?source=test" || !strings.HasPrefix(r.Host, "origin.example:") {
			t.Errorf("unexpected request %s %s", r.URL, r.Host)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	setupNotifyTestEnv(t, &model.Hosts{}, &model.LoadBalance{})
	stored := model.Hosts{BaseOrm: baseorm.BaseOrm{Id: "saved-id", Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}, Code: "saved", Host: "saved.example", Remote_host: "http://saved.example", Remote_port: 80, HealthyJSON: `{"check_path":"/saved"}`}
	if err := global.GWAF_LOCAL_DB.Create(&stored).Error; err != nil {
		t.Fatal(err)
	}
	status := wafenginecore.GetHostStatus()
	status.Mux.Lock()
	before, _ := json.Marshal(status.HealthyStatus)
	status.Mux.Unlock()
	req := healthTestRequest(t, server)
	req.Code = stored.Code
	for _, expected := range []string{"200,", "503,"} {
		req.HealthyJSON = strings.ReplaceAll(req.HealthyJSON, "200,", expected)
		code, data, msg := callHealthTest(t, req)
		if code != 0 || len(data.Results) != 1 {
			t.Fatalf("code=%d data=%+v msg=%s", code, data, msg)
		}
		want := wafhealth.Passed
		if expected == "503," {
			want = wafhealth.Failed
		}
		if data.Results[0].Outcome != want || data.Results[0].StatusCode != 200 || data.NextOffset != -1 {
			t.Fatalf("unexpected result %+v", data)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("hits %d", hits.Load())
	}
	var after model.Hosts
	if err := global.GWAF_LOCAL_DB.Where("code = ?", stored.Code).First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored, after) {
		t.Fatal("saved website changed")
	}
	status.Mux.Lock()
	afterStatus, _ := json.Marshal(status.HealthyStatus)
	status.Mux.Unlock()
	if !bytes.Equal(before, afterStatus) {
		t.Fatal("runtime health changed")
	}
	if msgs := drainChanMsg(); len(msgs) != 0 {
		t.Fatalf("unexpected notifications %d", len(msgs))
	}
}

func TestHealthTestLoadBalancePaginationAndOwnership(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	setupNotifyTestEnv(t, &model.Hosts{}, &model.LoadBalance{})
	req := healthTestRequest(t, server)
	req.Code = "balanced"
	req.IsEnableLoadBalance = 1
	host := model.Hosts{BaseOrm: baseorm.BaseOrm{Id: "host-id", Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}, Code: req.Code}
	if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
		t.Fatal(err)
	}
	ports := []int{req.RemotePort}
	for i := 1; i < 7; i++ {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
		t.Cleanup(backend.Close)
		_, portText, _ := net.SplitHostPort(backend.Listener.Addr().String())
		port, _ := strconv.Atoi(portText)
		ports = append(ports, port)
	}
	for i := 6; i >= 0; i-- {
		lb := model.LoadBalance{BaseOrm: baseorm.BaseOrm{Id: fmt.Sprintf("backend-%d", i), Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}, HostCode: req.Code, Remote_ip: req.RemoteIP, Remote_port: ports[i]}
		if err := global.GWAF_LOCAL_DB.Create(&lb).Error; err != nil {
			t.Fatal(err)
		}
	}
	other := model.LoadBalance{BaseOrm: baseorm.BaseOrm{Id: "foreign", Tenant_ID: "different", USER_CODE: global.GWAF_USER_CODE}, HostCode: req.Code, Remote_ip: req.RemoteIP, Remote_port: req.RemotePort}
	if err := global.GWAF_LOCAL_DB.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	code, first, msg := callHealthTest(t, req)
	if code != 0 || first.Total != 7 || len(first.Results) != 5 || first.NextOffset != 5 {
		t.Fatalf("first=%+v code=%d msg=%s", first, code, msg)
	}
	req.Offset = first.NextOffset
	code, second, msg := callHealthTest(t, req)
	if code != 0 || second.Total != 7 || len(second.Results) != 2 || second.NextOffset != -1 || hits.Load() != 7 {
		t.Fatalf("second=%+v code=%d msg=%s hits=%d", second, code, msg, hits.Load())
	}
	for i, result := range append(first.Results, second.Results...) {
		if result.BackPort != ports[i] {
			t.Fatalf("unstable target order index=%d port=%d", i, result.BackPort)
		}
	}
	req.Code = "missing"
	req.Offset = 0
	if code, _, _ := callHealthTest(t, req); code == 0 {
		t.Fatal("missing website accepted")
	}
	req.Code = ""
	if code, _, _ := callHealthTest(t, req); code == 0 {
		t.Fatal("unsaved load balance accepted")
	}
	if hits.Load() != 7 {
		t.Fatal("invalid website was probed")
	}
}

func TestHealthTestRouteRegistered(t *testing.T) {
	router, err := os.ReadFile("../router/waf_host.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(router, []byte(`hostRouter.POST("/api/v1/wafhost/host/health/test", middleware.RequireRole(enums.ROLE_SECURITY_ADMIN), hostApi.TestHealthApi)`)) {
		t.Fatal("health test route missing")
	}
	server, err := os.ReadFile("../wafmangeweb/localserver.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(server, []byte("middleware.Auth()")) || !bytes.Contains(server, []byte("InitHostRouter(RouterGroup)")) {
		t.Fatal("host routes must use authenticated group")
	}
}
