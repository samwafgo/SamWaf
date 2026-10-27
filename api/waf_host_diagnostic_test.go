package api

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestWebsiteDiagnosticWildcardInspection(t *testing.T) {
	setupNotifyTestEnv(t, &model.Hosts{}, &model.LoadBalance{}, &model.HostPathRule{})
	host := model.Hosts{BaseOrm: baseorm.BaseOrm{Id: "wildcard-diagnostic", Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}, Code: "wildcard-diagnostic", Host: "*", Port: 7822}
	if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
		t.Fatal(err)
	}
	snap := wafenginmodel.WebsiteDiagnosticSnapshot{Host: host, Loaded: true, MatchCode: host.Code, MatchKind: "catch_all", Mode: "static"}
	env := waf_service.WebsiteDiagnosticEnvironment{Snapshot: func(string, string, string, http.Header) (wafenginmodel.WebsiteDiagnosticSnapshot, error) {
		return snap, nil
	}}
	req := request.WafHostDiagnosticReq{HostCode: host.Code, Phase: "inspect", Method: "GET"}
	result, err := waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err != nil || len(result.Checks) != 1 || result.Checks[0].Reason != "URL_REQUIRED" || result.ConfigFingerprint != "" {
		t.Fatalf("empty wildcard URL: %+v %v", result, err)
	}
	for _, address := range []string{"http://site.example:7822/?token=hidden-query", "http://192.0.2.10:7822/"} {
		req.VisitorURL = address
		result, err = waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
		if err != nil || result.Checks[0].Status != "passed" || !strings.Contains(result.Checks[0].Message, "命中所选通配网站") {
			t.Fatalf("concrete wildcard URL: %+v %v", result, err)
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), "hidden-query") {
			t.Fatal("wildcard inspection echoed query value")
		}
	}
	snap.MatchCode = "another-site"
	result, err = waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err != nil || result.Checks[0].Reason != "HOST_MISMATCH" {
		t.Fatalf("different site must not pass: %+v %v", result, err)
	}
}

func TestWebsiteDiagnosticValidation(t *testing.T) {
	base := request.WafHostDiagnosticReq{HostCode: "host-1", Phase: "inspect", VisitorURL: "http://site.example:9112/", Method: "GET"}
	if err := validateWebsiteDiagnostic(&base); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*request.WafHostDiagnosticReq)
	}{
		{"method", func(r *request.WafHostDiagnosticReq) { r.Method = "POST" }},
		{"phase", func(r *request.WafHostDiagnosticReq) { r.Phase = "other" }},
		{"fingerprint", func(r *request.WafHostDiagnosticReq) { r.Phase = "origin" }},
		{"credentials", func(r *request.WafHostDiagnosticReq) { r.VisitorURL = "http://user:pass@site.example/" }},
		{"fragment", func(r *request.WafHostDiagnosticReq) { r.VisitorURL += "#part" }},
		{"wildcard", func(r *request.WafHostDiagnosticReq) { r.VisitorURL = "http://*.example/" }},
		{"port", func(r *request.WafHostDiagnosticReq) { r.VisitorURL = "http://site.example:65536/" }},
		{"negative cursor", func(r *request.WafHostDiagnosticReq) { r.OriginCursor = -1 }},
		{"header host", func(r *request.WafHostDiagnosticReq) {
			r.Headers = []request.WebsiteDiagnosticHeader{{Name: "Host", Value: "other"}}
		}},
		{"header control", func(r *request.WafHostDiagnosticReq) {
			r.Headers = []request.WebsiteDiagnosticHeader{{Name: "X-Test", Value: "a\r\nb"}}
		}},
		{"header transport", func(r *request.WafHostDiagnosticReq) {
			r.Headers = []request.WebsiteDiagnosticHeader{{Name: "Connection", Value: "X-Test"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.edit(&req)
			if validateWebsiteDiagnostic(&req) == nil {
				t.Fatal("invalid diagnostic request accepted")
			}
		})
	}
}

func TestWebsiteDiagnosticSavedConfigAndProbe(t *testing.T) {
	setupNotifyTestEnv(t, &model.Hosts{}, &model.LoadBalance{}, &model.HostPathRule{})
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Host != "site.example:9112" {
			t.Errorf("unexpected Host %q", r.Host)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=cookie-secret")
		_, _ = w.Write([]byte(`{"status":"ok","token":"body-secret"}`))
	}))
	defer origin.Close()
	hostIP, portText, _ := net.SplitHostPort(origin.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	host := model.Hosts{BaseOrm: baseorm.BaseOrm{Id: "diagnostic-host", Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}, Code: "diagnostic-host", Host: "site.example", Port: 9112, Remote_host: "http://origin.example", Remote_ip: hostIP, Remote_port: port}
	if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
		t.Fatal(err)
	}
	snap := wafenginmodel.WebsiteDiagnosticSnapshot{Loaded: true, Host: host, MatchCode: host.Code, MatchKind: "exact", Mode: "proxy", OriginPlans: []wafenginmodel.WebsiteDiagnosticOriginPlan{{URL: "http://origin.example:" + portText + "/", Host: "site.example:9112", FixedAddress: origin.Listener.Addr().String(), FallbackAddress: "origin.example:" + portText}}}
	env := waf_service.WebsiteDiagnosticEnvironment{Snapshot: func(string, string, string, http.Header) (wafenginmodel.WebsiteDiagnosticSnapshot, error) {
		return snap, nil
	}}
	req := request.WafHostDiagnosticReq{HostCode: host.Code, Phase: "inspect", VisitorURL: "http://site.example:9112/?token=input-secret", Method: "GET"}
	res, err := waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err != nil || len(res.Checks) != 1 || res.Checks[0].Status != "passed" || hits.Load() != 0 {
		t.Fatalf("inspect: %+v %v hits=%d", res, err, hits.Load())
	}
	body, _ := json.Marshal(res)
	if strings.Contains(string(body), "input-secret") {
		t.Fatal("inspection echoed sensitive query")
	}
	req.ConfigFingerprint, req.Phase = res.ConfigFingerprint, "origin"
	res, err = waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err != nil || len(res.Checks) != 1 || res.Checks[0].StatusCode != 200 || hits.Load() != 1 {
		t.Fatalf("origin: %+v %v hits=%d", res, err, hits.Load())
	}
	body, _ = json.Marshal(res)
	for _, secret := range []string{"cookie-secret", "body-secret", "input-secret"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("response contains %s", secret)
		}
	}
	if err := global.GWAF_LOCAL_DB.Model(&host).Update("remote_port", port+1).Error; err != nil {
		t.Fatal(err)
	}
	res, err = waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err == nil || res.ErrorCode != "CONFIG_CHANGED" || hits.Load() != 1 {
		t.Fatalf("changed config should stop: %+v %v", res, err)
	}
	if err := global.GWAF_LOCAL_DB.Model(&host).Update("tenant_id", "other-tenant").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env); err == nil {
		t.Fatal("foreign website accepted")
	}
}

func TestWebsiteDiagnosticRejectsOpenAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/wafhost/host/diagnostic", strings.NewReader(`{"host_code":"host-1","phase":"inspect","method":"GET"}`))
	c.Set("is_openapi", true)
	new(WafHostAPi).DiagnosticApi(c)
	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Msg != "诊断功能仅支持登录用户调用" {
		t.Fatalf("openapi key caller must be rejected: %s", w.Body.String())
	}
}

func TestWebsiteDiagnosticLocalPortAndRuntimeBoundaries(t *testing.T) {
	setupNotifyTestEnv(t, &model.Hosts{}, &model.LoadBalance{}, &model.HostPathRule{})
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	host := model.Hosts{BaseOrm: baseorm.BaseOrm{Id: "local-diagnostic", Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE}, Code: "local-diagnostic", Host: "site.example", Port: port, Remote_host: "http://origin.example", Remote_port: 8080}
	if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
		t.Fatal(err)
	}
	listeners := wafenginmodel.NewSafeServerMap()
	listeners.Set(port, innerbean.ServerRunTime{Port: port, ServerType: "http", Status: 0, Svr: server.Config})
	snap := wafenginmodel.WebsiteDiagnosticSnapshot{Host: host, Loaded: true, MatchCode: host.Code, MatchKind: "exact", Mode: "static"}
	env := waf_service.WebsiteDiagnosticEnvironment{Snapshot: func(string, string, string, http.Header) (wafenginmodel.WebsiteDiagnosticSnapshot, error) {
		return snap, nil
	}, Listeners: listeners}
	req := request.WafHostDiagnosticReq{HostCode: host.Code, Phase: "inspect", VisitorURL: "http://site.example:" + portText + "/", Method: "HEAD"}
	inspected, err := waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err != nil {
		t.Fatal(err)
	}
	req.Phase, req.ConfigFingerprint = "local_ingress", inspected.ConfigFingerprint
	result, err := waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err != nil || result.Checks[0].StatusCode != 204 || hits.Load() != 1 {
		t.Fatalf("local result %+v %v", result, err)
	}
	oldPort := global.GWAF_LOCAL_SERVER_PORT
	global.GWAF_LOCAL_SERVER_PORT = port
	t.Cleanup(func() { global.GWAF_LOCAL_SERVER_PORT = oldPort })
	result, err = waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err != nil || result.Checks[0].Status != "skipped" || hits.Load() != 1 {
		t.Fatalf("management listener must not be called: %+v %v", result, err)
	}
	global.GWAF_LOCAL_SERVER_PORT = oldPort
	snap.Host.Remote_port++
	result, err = waf_service.WafHostDiagnosticServiceApp.Diagnose(context.Background(), req, env)
	if err == nil || result.ErrorCode != "RUNTIME_CHANGED" || hits.Load() != 1 {
		t.Fatalf("runtime changes must stop: %+v %v", result, err)
	}
}
