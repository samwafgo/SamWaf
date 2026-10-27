package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/wafenginmodel"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestWebsiteDiagnosticRoute(t *testing.T) {
	tests := []struct {
		name, authority string
		secure          bool
		hosts           map[string]string
		aliases, loose  map[string]string
		code, kind      string
	}{
		{name: "http default", authority: "example.com", hosts: map[string]string{"example.com:80": "a"}, code: "a", kind: "exact"},
		{name: "https default", authority: "example.com", secure: true, hosts: map[string]string{"example.com:443": "a"}, code: "a", kind: "exact"},
		{name: "explicit port", authority: "example.com:8443", hosts: map[string]string{"example.com:8443": "a"}, code: "a", kind: "exact"},
		{name: "alias", authority: "alias.com:8080", aliases: map[string]string{"alias.com:8080": "a"}, code: "a", kind: "alias"},
		{name: "wildcard", authority: "one.example.com", hosts: map[string]string{"*.example.com:80": "a"}, code: "a", kind: "wildcard"},
		{name: "wildcard alias", authority: "one.example.com", aliases: map[string]string{"*.example.com:80": "a"}, code: "a", kind: "alias_wildcard"},
		{name: "only first label masked", authority: "one.two.example.com", hosts: map[string]string{"*.example.com:80": "a"}, kind: "unmatched"},
		{name: "exact before wildcard alias", authority: "one.example.com", hosts: map[string]string{"one.example.com:80": "a"}, aliases: map[string]string{"*.example.com:80": "b"}, code: "a", kind: "exact"},
		{name: "loose port", authority: "example.com:9900", hosts: map[string]string{"example.com:80": "a"}, loose: map[string]string{"example.com": "example.com:80"}, code: "a", kind: "no_port"},
		{name: "loose alias", authority: "alias.com:9900", hosts: map[string]string{"example.com:80": "a"}, loose: map[string]string{"alias.com": "example.com:80"}, code: "a", kind: "no_port"},
		{name: "catch all", authority: "other.com:8080", hosts: map[string]string{"*:8080": "b"}, code: "b", kind: "catch_all"},
		{name: "catch all replaces exact", authority: "example.com", hosts: map[string]string{"example.com:80": "a", "*:80": "b"}, code: "b", kind: "catch_all"},
		{name: "catch all uses visitor port after loose", authority: "example.com:9900", hosts: map[string]string{"example.com:80": "a", "*:9900": "b"}, loose: map[string]string{"example.com": "example.com:80"}, code: "b", kind: "catch_all"},
		{name: "loose catch all replaces exact", authority: "example.com", hosts: map[string]string{"example.com:80": "a", "*:8080": "b"}, loose: map[string]string{"*": "*:8080"}, code: "b", kind: "catch_all_no_port"},
		{name: "missing loose catch all skips port fallback", authority: "example.com", hosts: map[string]string{"example.com:80": "a", "*:80": "b"}, loose: map[string]string{"*": "*:8080"}, code: "a", kind: "exact"},
		{name: "case preserved", authority: "EXAMPLE.com", hosts: map[string]string{"example.com:80": "a"}, kind: "unmatched"},
		{name: "ipv6 authority preserved", authority: "[::1]:8080", hosts: map[string]string{"[::1]:8080": "a", "*:8080": "b"}, code: "a", kind: "exact"},
		{name: "unmatched", authority: "missing.com", kind: "unmatched"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRoutingTable()
			for key, code := range tc.hosts {
				rt.HostTarget[key] = &wafenginmodel.HostSafe{Host: model.Hosts{Code: code}}
			}
			for k, v := range tc.aliases {
				rt.HostTargetMoreDomain[k] = v
			}
			for k, v := range tc.loose {
				rt.HostTargetNoPort[k] = v
			}
			result := resolveRequestHost(rt, tc.authority, tc.secure, true)
			if result.Code != tc.code || result.Kind != tc.kind || result.Found != (tc.code != "") {
				t.Fatalf("route = %+v, want %s/%s", result, tc.code, tc.kind)
			}
			if len(result.Steps) == 0 {
				t.Fatal("route trace is empty")
			}
			quiet := resolveRequestHost(rt, tc.authority, tc.secure, false)
			if quiet.Steps != nil || quiet.Code != result.Code || quiet.Host != result.Host || quiet.Port != result.Port {
				t.Fatalf("production route differs from traced route: %+v / %+v", quiet, result)
			}
		})
	}
}

func diagnosticTestEngine(host *wafenginmodel.HostSafe) *WafEngine {
	waf := &WafEngine{}
	rt := newRoutingTable()
	rt.HostTarget["site.test:443"] = host
	rt.HostCode[host.Host.Code] = "site.test:443"
	waf.routing.Store(rt)
	return waf
}

func TestWebsiteDiagnosticOriginPlan(t *testing.T) {
	host := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Code: "site", Remote_ip: "192.0.2.1", Remote_port: 9443, IsTransBackDomain: 1,
			CustomHeadersJSON: `{"is_enable_custom_headers":1,"headers":[{"header_name":"X-Config","header_value":"saved"},{"header_name":"X-Visitor","header_value":"${host}|${scheme}|${request_uri}|${request_method}"},{"header_name":"X-Remove","header_value":""},{"header_name":"X-Forwarded-For","header_value":"192.0.2.8"}]}`,
		},
		TargetHost: "https://origin.test:9443/base?source=1",
	}
	waf := diagnosticTestEngine(host)
	headers := http.Header{"X-Config": {"caller"}, "X-Remove": {"remove"}, "X-Test": {"input"}, "Connection": {"X-Hop"}, "X-Hop": {"remove"}}
	before := headers.Clone()
	snapshot, err := waf.DiagnosticSnapshot("site", "https://site.test/a%2Fb?q=2", "HEAD", headers)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Loaded || snapshot.MatchCode != "site" || snapshot.Mode != "proxy" || len(snapshot.OriginPlans) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	plan := snapshot.OriginPlans[0]
	if plan.URL != "https://origin.test:9443/base/a%2Fb?source=1&q=2" || plan.Host != "origin.test" || plan.ServerName != "origin.test" || plan.FixedAddress != "192.0.2.1:9443" || plan.FallbackAddress != "origin.test:9443" {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.Headers.Get("X-Config") != "saved" || plan.Headers.Get("X-Test") != "input" || plan.Headers.Get("X-Visitor") != "site.test|https|/a%2Fb?q=2|HEAD" || plan.Headers.Get("X-Forwarded-Proto") != "https" || plan.Headers.Get("X-Forwarded-For") != "192.0.2.8" {
		t.Fatalf("headers = %v", plan.Headers)
	}
	for _, name := range []string{"X-Remove", "Connection", "X-Hop", "X-Waf-Custom-XFF-Control"} {
		if plan.Headers.Get(name) != "" {
			t.Fatalf("header %s should be removed", name)
		}
	}
	if !reflect.DeepEqual(headers, before) || waf.TransportPool != nil {
		t.Fatal("planning changed input headers or transport cache")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("internal snapshot serialized: %s / %v", encoded, err)
	}
}

func TestWebsiteDiagnosticPathPlan(t *testing.T) {
	host := &wafenginmodel.HostSafe{
		Host: model.Hosts{Code: "site", CustomHeadersJSON: `{"is_enable_custom_headers":1,"headers":[{"header_name":"X-Saved","header_value":"value"}]}`},
		PathRules: []model.HostPathRule{
			{RuleName: "later", Priority: 10, MatchType: 1, Path: "/", TargetType: 1},
			{RuleName: "chosen", Priority: 1, MatchType: 1, Path: "/api", StripPrefix: 1, RemoteHost: "path.test", RemotePort: 8080, RemoteIP: "2001:db8::1", RemoteScheme: "http"},
		},
	}
	waf := diagnosticTestEngine(host)
	before := append([]model.HostPathRule(nil), host.PathRules...)
	snapshot, err := waf.DiagnosticSnapshot("site", "https://site.test/api/a%2Fb?x=1", "GET", http.Header{"X-Input": {"value"}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Mode != "path_proxy" || snapshot.PathRule.RuleName != "chosen" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	plan := snapshot.OriginPlans[0]
	if plan.URL != "http://path.test:8080/a%2Fb?x=1" || plan.Host != "site.test" || plan.FixedAddress != "[2001:db8::1]:8080" || plan.Headers.Get("X-Saved") != "" || plan.Headers.Get("X-Input") != "value" || plan.Headers.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("path plan = %+v", plan)
	}
	snapshot.PathRules[0].Path = "changed"
	snapshot.PathRule.Path = "changed"
	if !reflect.DeepEqual(host.PathRules, before) {
		t.Fatal("planning or snapshot mutation changed runtime path rules")
	}
}

func TestWebsiteDiagnosticZeroPortKeepsDomainFallback(t *testing.T) {
	// Remote_port/RemotePort 为 0 时不能生成 ip:0 固定地址，必须回落域名地址
	zeroPortHost := &wafenginmodel.HostSafe{
		Host:       model.Hosts{Code: "site", Remote_ip: "192.0.2.1"},
		TargetHost: "https://origin.test/base",
	}
	snapshot, err := diagnosticTestEngine(zeroPortHost).DiagnosticSnapshot("site", "https://site.test/a", "GET", nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan := snapshot.OriginPlans[0]; plan.FixedAddress != "" || plan.FallbackAddress != "origin.test:443" {
		t.Fatalf("single-origin zero port plan = %+v", plan)
	}

	lbHost := &wafenginmodel.HostSafe{
		Host: model.Hosts{Code: "site", IsEnableLoadBalance: 1},
		TargetHost: "http://origin.test",
		LoadBalanceLists: []model.LoadBalance{
			{BaseOrm: baseorm.BaseOrm{Id: "one"}, Remote_ip: "192.0.2.1"},
		},
	}
	snapshot, err = diagnosticTestEngine(lbHost).DiagnosticSnapshot("site", "http://site.test/", "GET", nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan := snapshot.OriginPlans[0]; plan.FixedAddress != "" || plan.FallbackAddress != "origin.test:80" {
		t.Fatalf("load-balance zero port plan = %+v", plan)
	}

	pathHost := &wafenginmodel.HostSafe{
		Host: model.Hosts{Code: "site"},
		PathRules: []model.HostPathRule{
			{RuleName: "zero", Priority: 1, MatchType: 1, Path: "/", TargetType: 1, RemoteHost: "path.test", RemoteIP: "192.0.2.1"},
		},
	}
	snapshot, err = diagnosticTestEngine(pathHost).DiagnosticSnapshot("site", "http://site.test/x", "GET", nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan := snapshot.OriginPlans[0]; plan.FixedAddress != "" || plan.FallbackAddress != "path.test:80" || plan.URL != "http://path.test/x" {
		t.Fatalf("path-rule zero port plan = %+v", plan)
	}
}

func TestWebsiteDiagnosticLoadBalanceReadOnly(t *testing.T) {
	host := &wafenginmodel.HostSafe{
		Host: model.Hosts{Code: "site", IsEnableLoadBalance: 1}, TargetHost: "http://origin.test:80",
		LoadBalanceLists: []model.LoadBalance{
			{BaseOrm: baseorm.BaseOrm{Id: "one"}, Remote_ip: "192.0.2.1", Remote_port: 8080},
			{BaseOrm: baseorm.BaseOrm{Id: "two"}, Remote_ip: "192.0.2.2", Remote_port: 8081},
		},
		LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{CurrentProxyIndex: 17},
	}
	waf := diagnosticTestEngine(host)
	snapshot, err := waf.DiagnosticSnapshot("site", "https://site.test/", "GET", nil)
	if err != nil || len(snapshot.OriginPlans) != 2 {
		t.Fatalf("snapshot = %+v / %v", snapshot, err)
	}
	if snapshot.OriginPlans[1].FixedAddress != "192.0.2.2:8081" || snapshot.OriginPlans[1].BackendID != "two" || snapshot.OriginPlans[1].URL != "http://origin.test:80/" {
		t.Fatalf("LB plan = %+v", snapshot.OriginPlans[1])
	}
	snapshot.Backends[0].Remote_ip = "changed"
	if host.LoadBalanceLists[0].Remote_ip != "192.0.2.1" || host.LoadBalanceRuntime.CurrentProxyIndex != 17 || len(host.LoadBalanceRuntime.RevProxies) != 0 || waf.TransportPool != nil {
		t.Fatal("diagnostic changed runtime load balance state")
	}
}

func TestWebsiteDiagnosticNonOriginModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*wafenginmodel.HostSafe)
		mode string
	}{
		{"disabled", func(h *wafenginmodel.HostSafe) { h.Host.START_STATUS = 1 }, "disabled"},
		{"static", func(h *wafenginmodel.HostSafe) { h.Host.StaticSiteJSON = `{"is_enable_static_site":1}` }, "static"},
		{"path static", func(h *wafenginmodel.HostSafe) { h.PathRules[0].TargetType = 2 }, "path_static"},
		{"path redirect", func(h *wafenginmodel.HostSafe) { h.PathRules[0].TargetType = 3 }, "redirect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "site"}, PathRules: []model.HostPathRule{{MatchType: 1, Path: "/"}}}
			tc.edit(host)
			snapshot, err := diagnosticTestEngine(host).DiagnosticSnapshot("site", "https://site.test/", "GET", nil)
			if err != nil || snapshot.Mode != tc.mode || len(snapshot.OriginPlans) != 0 {
				t.Fatalf("snapshot = %+v / %v", snapshot, err)
			}
		})
	}
}

func TestWebsiteDiagnosticRootAndHTTPSRedirect(t *testing.T) {
	host := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "site", Host: "site.test", Ssl: 1, AutoJumpHTTPS: 1}, TargetHost: "http://origin.test:80", PathRules: []model.HostPathRule{{MatchType: 2, Path: "/", TargetType: 3}}}
	waf := diagnosticTestEngine(host)
	waf.rt().HostTarget["site.test:80"] = host
	snapshot, err := waf.DiagnosticSnapshot("site", "http://site.test#fragment", "GET", nil)
	if err != nil || snapshot.Mode != "https_redirect" || len(snapshot.OriginPlans) != 0 {
		t.Fatalf("HTTPS redirect = %+v / %v", snapshot, err)
	}
	snapshot, err = waf.DiagnosticSnapshot("site", "https://site.test#fragment", "GET", nil)
	if err != nil || snapshot.Mode != "redirect" {
		t.Fatalf("root path match = %+v / %v", snapshot, err)
	}
	host.PathRules = nil
	snapshot, err = waf.DiagnosticSnapshot("site", "https://site.test#fragment", "GET", nil)
	if err != nil || snapshot.OriginPlans[0].URL != "http://origin.test:80/" {
		t.Fatalf("root origin = %+v / %v", snapshot, err)
	}
}

func TestWebsiteDiagnosticMissingAndInvalid(t *testing.T) {
	waf := &WafEngine{}
	snapshot, err := waf.DiagnosticSnapshot("missing", "https://site.test/", "GET", nil)
	if err != nil || snapshot.Loaded || snapshot.MatchKind != "unmatched" {
		t.Fatalf("snapshot = %+v / %v", snapshot, err)
	}
	for _, input := range []string{"file:///tmp/a", "https://user:pass@site.test/", "/relative", "http://%/"} {
		if _, err := waf.DiagnosticSnapshot("missing", input, "GET", nil); err == nil {
			t.Errorf("accepted invalid URL %q", input)
		}
	}
	if _, err := waf.DiagnosticSnapshot("missing", "https://site.test/", "BAD\nMETHOD", nil); err == nil {
		t.Fatal("accepted invalid method")
	}
	host := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "site"}, TargetHost: "missing-scheme:80"}
	snapshot, err = diagnosticTestEngine(host).DiagnosticSnapshot("site", "https://site.test/", "GET", nil)
	if err != nil || !strings.Contains(snapshot.OriginPlans[0].Error, "origin URL") {
		t.Fatalf("invalid runtime origin should preserve snapshot: %+v / %v", snapshot, err)
	}
}
