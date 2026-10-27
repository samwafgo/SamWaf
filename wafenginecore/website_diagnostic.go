package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafproxy"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// DiagnosticSnapshot 读取单次发布的路由快照，不选择后端或建立连接。
func (waf *WafEngine) DiagnosticSnapshot(hostCode, visitorURL, method string, headers http.Header) (wafenginmodel.WebsiteDiagnosticSnapshot, error) {
	var snapshot wafenginmodel.WebsiteDiagnosticSnapshot
	u, err := url.Parse(visitorURL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return snapshot, errors.New("invalid diagnostic visitor URL")
	}
	req, err := http.NewRequest(method, visitorURL, nil)
	if err != nil {
		return snapshot, errors.New("invalid diagnostic request")
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}
	req.URL.Fragment, req.URL.RawFragment = "", ""
	req.RequestURI = req.URL.RequestURI()
	if u.Scheme == "https" {
		req.TLS = &tls.ConnectionState{}
	}
	rt := waf.rt()
	match := resolveRequestHost(rt, req.Host, req.TLS != nil, true)
	snapshot.MatchCode, snapshot.MatchKind, snapshot.Steps = match.Code, match.Kind, match.Steps
	host := rt.HostTarget[rt.HostCode[hostCode]]
	if host == nil {
		return snapshot, nil
	}
	snapshot.Loaded = true
	snapshot.Host, snapshot.TargetHost = host.Host, host.TargetHost
	snapshot.Backends = append([]model.LoadBalance(nil), host.LoadBalanceLists...)
	snapshot.PathRules = append([]model.HostPathRule(nil), host.PathRules...)
	snapshot.Limitations = []string{
		"Request planning does not execute WAF rules, authentication, cache lookup, or local file reads.",
		"Client address variables and automatic X-Forwarded-For appending cannot be reproduced without a live visitor connection.",
	}
	if host.Host.START_STATUS == 1 {
		snapshot.Mode = "disabled"
		return snapshot, nil
	}
	if req.TLS == nil {
		if jump, _ := shouldAutoJumpHTTPS(match.Host, host.Host.Host, req.URL.RequestURI(), host.Host.AutoJumpHTTPS, host.Host.Ssl); jump {
			snapshot.Mode = "https_redirect"
			return snapshot, nil
		}
	}
	staticConfig := InitDefaultStaticSiteConfig()
	_ = json.Unmarshal([]byte(host.Host.StaticSiteJSON), &staticConfig)
	if staticConfig.IsEnableStaticSite == 1 {
		snapshot.Mode = "static"
		return snapshot, nil
	}
	if _, err := url.Parse(host.TargetHost); err != nil {
		snapshot.Mode = "proxy"
		snapshot.OriginPlans = []wafenginmodel.WebsiteDiagnosticOriginPlan{{Kind: "proxy", Error: "invalid runtime origin URL"}}
		return snapshot, nil
	}
	if rule := MatchPathRule(host.PathRules, req.URL.Path); rule != nil {
		snapshot.PathRule = rule
		switch rule.TargetType {
		case 2:
			snapshot.Mode = "path_static"
			return snapshot, nil
		case 3:
			snapshot.Mode = "redirect"
			return snapshot, nil
		default:
			snapshot.Mode = "path_proxy"
			snapshot.OriginPlans = []wafenginmodel.WebsiteDiagnosticOriginPlan{waf.diagnosticPathPlan(req, host, rule)}
			return snapshot, nil
		}
	}
	snapshot.Mode = "proxy"
	if host.Host.IsEnableLoadBalance > 0 {
		snapshot.Mode = "load_balance"
		snapshot.Limitations = append(snapshot.Limitations, "Load balance plans enumerate configured backends without advancing selection state; existing proxy headers may originate from the first live request.")
		for _, backend := range snapshot.Backends {
			snapshot.OriginPlans = append(snapshot.OriginPlans, waf.diagnosticOriginPlan(req, host, &backend))
		}
	} else {
		snapshot.OriginPlans = []wafenginmodel.WebsiteDiagnosticOriginPlan{waf.diagnosticOriginPlan(req, host, nil)}
	}
	return snapshot, nil
}

func (waf *WafEngine) diagnosticOriginPlan(req *http.Request, host *wafenginmodel.HostSafe, backend *model.LoadBalance) wafenginmodel.WebsiteDiagnosticOriginPlan {
	plan := wafenginmodel.WebsiteDiagnosticOriginPlan{Kind: "proxy"}
	var lb model.LoadBalance
	if backend != nil {
		lb = *backend
		plan.Kind, plan.BackendID = "load_balance", lb.Id
		if lb.Remote_port > 0 {
			plan.FixedAddress = net.JoinHostPort(lb.Remote_ip, strconv.Itoa(lb.Remote_port))
		}
	} else if host.Host.Remote_ip != "" && host.Host.Remote_port > 0 {
		plan.FixedAddress = net.JoinHostPort(host.Host.Remote_ip, strconv.Itoa(host.Host.Remote_port))
	}
	target, err := url.Parse(host.TargetHost)
	if err != nil || target == nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
		plan.Error = "invalid runtime origin URL"
		return plan
	}
	customHeaders := waf.getCustomHeaders(req, req.Host, host.Host.IsEnableLoadBalance, lb, host)
	return finishDiagnosticPlan(plan, req, target, customHeaders, host)
}

func (waf *WafEngine) diagnosticPathPlan(req *http.Request, host *wafenginmodel.HostSafe, rule *model.HostPathRule) wafenginmodel.WebsiteDiagnosticOriginPlan {
	plan := wafenginmodel.WebsiteDiagnosticOriginPlan{Kind: "path_proxy"}
	if rule.RemoteIP != "" && rule.RemotePort > 0 {
		plan.FixedAddress = net.JoinHostPort(rule.RemoteIP, strconv.Itoa(rule.RemotePort))
	}
	targetString := resolvePathRuleScheme(req, rule) + "://" + rule.RemoteHost
	if rule.RemotePort > 0 {
		targetString += ":" + strconv.Itoa(rule.RemotePort)
	}
	target, err := url.Parse(targetString)
	if err != nil || target.Hostname() == "" {
		plan.Error = "invalid runtime path origin URL"
		return plan
	}
	req = req.Clone(req.Context())
	if rule.StripPrefix == 1 && strings.HasPrefix(req.URL.Path, rule.Path) {
		req.URL.Path = diagnosticStripPrefix(req.URL.Path, rule.Path)
		if req.URL.RawPath != "" {
			req.URL.RawPath = diagnosticStripPrefix(req.URL.RawPath, rule.Path)
		}
	}
	customHeaders := map[string]string{}
	if req.TLS != nil {
		customHeaders["X-FORWARDED-PROTO"] = "https"
	}
	return finishDiagnosticPlan(plan, req, target, customHeaders, host)
}

func diagnosticStripPrefix(path, prefix string) string {
	path = strings.TrimPrefix(path, prefix)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func finishDiagnosticPlan(plan wafenginmodel.WebsiteDiagnosticOriginPlan, req *http.Request, target *url.URL, customHeaders map[string]string, host *wafenginmodel.HostSafe) wafenginmodel.WebsiteDiagnosticOriginPlan {
	out := wafproxy.BuildDiagnosticRequest(req, target, customHeaders, map[string]string{"IsTransBackDomain": strconv.Itoa(host.Host.IsTransBackDomain)})
	plan.URL, plan.Host, plan.Headers = out.URL.String(), out.Host, out.Header
	plan.ServerName = target.Hostname()
	plan.InsecureSkipVerify = host.Host.InsecureSkipVerify == 1
	port := target.Port()
	if port == "" {
		port = "80"
		if target.Scheme == "https" {
			port = "443"
		}
	}
	plan.FallbackAddress = net.JoinHostPort(target.Hostname(), port)
	return plan
}
