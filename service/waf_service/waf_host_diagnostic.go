package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	resp "SamWaf/model/response"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"SamWaf/wafdiagnose"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type WafHostDiagnosticService struct{}

var WafHostDiagnosticServiceApp = new(WafHostDiagnosticService)
var websiteDiagnosticSlots = make(chan struct{}, 2)
var diagnosticFingerprintKey = func() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("diagnostic fingerprint initialization failed")
	}
	return key
}()

type WebsiteDiagnosticEnvironment struct {
	Snapshot  func(string, string, string, http.Header) (wafenginmodel.WebsiteDiagnosticSnapshot, error)
	Listeners *wafenginmodel.SafeServerMap
}

type diagnosticConfiguration struct {
	Host     model.Hosts
	Backends []model.LoadBalance
	Rules    []model.HostPathRule
}

func diagnosticHostConfiguration(h model.Hosts) model.Hosts {
	h.BaseOrm = baseorm.BaseOrm{}
	h.Nickname, h.REMARKS, h.GroupCode = "", "", ""
	return h
}

func diagnosticConfigBytes(cfg diagnosticConfiguration) []byte {
	backends := append([]model.LoadBalance(nil), cfg.Backends...)
	rules := append([]model.HostPathRule(nil), cfg.Rules...)
	for i := range backends {
		id := backends[i].Id
		backends[i].BaseOrm = baseorm.BaseOrm{Id: id}
	}
	for i := range rules {
		id := rules[i].Id
		rules[i].BaseOrm = baseorm.BaseOrm{Id: id}
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].Id < backends[j].Id })
	sort.Slice(rules, func(i, j int) bool { return rules[i].Id < rules[j].Id })
	data, _ := json.Marshal([]interface{}{diagnosticHostConfiguration(cfg.Host), backends, rules})
	return data
}

func diagnosticFingerprint(cfg diagnosticConfiguration, snap wafenginmodel.WebsiteDiagnosticSnapshot, req request.WafHostDiagnosticReq) string {
	mac := hmac.New(sha256.New, diagnosticFingerprintKey)
	mac.Write(diagnosticConfigBytes(cfg))
	data, _ := json.Marshal([]interface{}{snap.Loaded, snap.MatchCode, snap.MatchKind, req.VisitorURL, req.Method, req.Headers, req.UseSystemProxy})
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func loadDiagnosticConfiguration(ctx context.Context, code string) (diagnosticConfiguration, error) {
	var cfg diagnosticConfiguration
	if global.GWAF_LOCAL_DB == nil {
		return cfg, errors.New("网站配置存储不可用")
	}
	db := global.GWAF_LOCAL_DB.WithContext(ctx)
	if err := db.Where("code = ? AND tenant_id = ? AND user_code = ?", code, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).First(&cfg.Host).Error; err != nil {
		return cfg, errors.New("网站不存在或不可访问")
	}
	if cfg.Host.GLOBAL_HOST == 1 {
		return cfg, errors.New("请选择具体网站进行诊断")
	}
	if err := db.Where("host_code = ? AND tenant_id = ? AND user_code = ?", code, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Order("create_time asc").Order("id asc").Find(&cfg.Backends).Error; err != nil {
		return cfg, errors.New("读取网站后端失败")
	}
	if err := db.Where("host_code = ?", code).Find(&cfg.Rules).Error; err != nil {
		return cfg, errors.New("读取网站路径配置失败")
	}
	return cfg, nil
}

func defaultDiagnosticURL(h model.Hosts) string {
	if h.Host == "" || strings.Contains(h.Host, "*") {
		return ""
	}
	for _, listen := range utils.ResolveHostListens(h) {
		if listen.IsMain {
			return (&url.URL{Scheme: listen.Protocol, Host: net.JoinHostPort(h.Host, strconv.Itoa(listen.Port)), Path: "/"}).String()
		}
	}
	return ""
}

func diagnosticField(label, value string) resp.WebsiteDiagnosticField {
	return resp.WebsiteDiagnosticField{Label: label, Value: value}
}

func diagnosticAdvice(code, message, section string) resp.WebsiteDiagnosticAdvice {
	tab := "basic"
	if section == "tls" {
		tab = "other"
	}
	return resp.WebsiteDiagnosticAdvice{Code: code, Message: message, Tab: tab, Section: section}
}

func diagnosticCheck(id, title, status, reason, message string) resp.WebsiteDiagnosticCheck {
	return resp.WebsiteDiagnosticCheck{ID: id, Title: title, Status: status, Reason: reason, Message: message,
		Overview: []resp.WebsiteDiagnosticField{}, Connection: []resp.WebsiteDiagnosticField{}, Advice: []resp.WebsiteDiagnosticAdvice{}}
}

func (s *WafHostDiagnosticService) Diagnose(ctx context.Context, req request.WafHostDiagnosticReq, env WebsiteDiagnosticEnvironment) (resp.WafHostDiagnosticResponse, error) {
	result := resp.WafHostDiagnosticResponse{Phase: req.Phase, Checks: []resp.WebsiteDiagnosticCheck{}, NextCursor: -1}
	select {
	case websiteDiagnosticSlots <- struct{}{}:
		defer func() { <-websiteDiagnosticSlots }()
	default:
		return result, errors.New("网站诊断繁忙，请稍后重试")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg, err := loadDiagnosticConfiguration(ctx, req.HostCode)
	if err != nil {
		return result, err
	}
	defaultURL := ""
	if req.VisitorURL == "" {
		req.VisitorURL = defaultDiagnosticURL(cfg.Host)
		defaultURL = req.VisitorURL
	}
	result.Site = resp.WebsiteDiagnosticSite{HostCode: cfg.Host.Code, Title: fmt.Sprintf("%s:%d", cfg.Host.Host, cfg.Host.Port), VisitorURL: defaultURL}
	if req.VisitorURL == "" {
		result.Checks = append(result.Checks, diagnosticCheck("inspect", "配置与匹配", "warning", "URL_REQUIRED", "通配域名需要填写用户实际访问的网址"))
		return result, nil
	}
	visitor, err := url.Parse(req.VisitorURL)
	if err != nil || visitor.Hostname() == "" || (visitor.Scheme != "http" && visitor.Scheme != "https") {
		return result, errors.New("访问网址格式不正确")
	}
	headers := make(http.Header)
	for _, h := range req.Headers {
		headers.Add(h.Name, h.Value)
	}
	var snap wafenginmodel.WebsiteDiagnosticSnapshot
	if env.Snapshot != nil {
		snap, err = env.Snapshot(req.HostCode, req.VisitorURL, req.Method, headers)
		if err != nil {
			return result, errors.New("读取网站运行视图失败")
		}
	}
	result.ConfigFingerprint = diagnosticFingerprint(cfg, snap, req)
	if req.Phase != "inspect" && !hmac.Equal([]byte(req.ConfigFingerprint), []byte(result.ConfigFingerprint)) {
		result.ErrorCode = "CONFIG_CHANGED"
		return result, errors.New("配置或访问参数已变化，请重新诊断")
	}
	consistent := snap.Loaded && hmac.Equal(diagnosticConfigBytes(cfg), diagnosticConfigBytes(diagnosticConfiguration{snap.Host, snap.Backends, snap.PathRules}))
	if req.Phase == "inspect" {
		check := diagnosticCheck("inspect", "配置与匹配", "passed", "CONFIG_MATCHED", "当前URL按运行路由匹配到所选网站；CDN/NAT改写后的请求需另行确认")
		if !snap.Loaded {
			check.Status, check.Reason, check.Message = "unknown", "NOT_LOADED", "当前运行视图中尚未加载所选网站"
		} else if !consistent {
			check.Status, check.Reason, check.Message = "warning", "RUNTIME_CHANGED", "保存配置与运行配置不同，网络阶段将停止，请确认配置加载状态后重测"
		} else if snap.MatchCode != cfg.Host.Code {
			check.Status, check.Reason, check.Message = "warning", "HOST_MISMATCH", "按访问URL推演未匹配所选网站；请核对域名、端口或前置转发改写"
		}
		matchType := snap.MatchKind
		switch snap.MatchKind {
		case "exact":
			matchType = "精确匹配（域名 + 端口）"
		case "no_port":
			matchType = "来源不限端口匹配"
		case "alias":
			matchType = "别名精确匹配"
		case "wildcard", "alias_wildcard":
			matchType = "子域名通配匹配"
		case "catch_all":
			matchType = "通用网站匹配（* + 端口）"
		case "catch_all_no_port":
			matchType = "通用网站匹配（*，不限制来源端口）"
		case "unmatched":
			matchType = "未匹配到任何网站"
		}
		if check.Status == "passed" && strings.Contains(cfg.Host.Host, "*") {
			check.Message = fmt.Sprintf("本次访问 %s 命中所选通配网站 %s（%s）；结论仅适用于本次具体访问地址，CDN/NAT改写后的请求需另行确认", visitor.Host, cfg.Host.Host, matchType)
		}
		port := diagnosticURLPort(visitor)
		matchedListener := false
		var listens []string
		for _, listen := range utils.ResolveHostListens(cfg.Host) {
			listens = append(listens, fmt.Sprintf("%d / %s / %s", listen.Port, listen.Protocol, listen.IPVersion))
			if strconv.Itoa(listen.Port) == port && listen.Protocol == visitor.Scheme {
				matchedListener = true
			}
		}
		if check.Status == "passed" && !matchedListener {
			check.Status, check.Reason, check.Message = "warning", "LISTENER_MISMATCH", "访问协议或端口与本站监听不一致；公网映射场景需核对映射后的入口"
		}
		check.Overview = []resp.WebsiteDiagnosticField{diagnosticField("实际访问域名", visitor.Hostname()), diagnosticField("访问协议与端口", visitor.Scheme+" / "+port), diagnosticField("保存监听", strings.Join(listens, "；")), diagnosticField("所选网站", cfg.Host.Host), diagnosticField("是否命中所选网站", strconv.FormatBool(snap.MatchCode == cfg.Host.Code)), diagnosticField("路由匹配类型", matchType), diagnosticField("保存与运行时一致", strconv.FormatBool(consistent)), diagnosticField("运行处理方式", snap.Mode), diagnosticField("来源严格端口", strconv.FormatBool(cfg.Host.UnrestrictedPort == 0))}
		check.Advice = append(check.Advice, diagnosticAdvice(check.Reason, "核对访问域名、协议、端口与网站配置；经过CDN/NAT时核对转发后的Host及目标端口", "listen"))
		result.Checks = append(result.Checks, check)
		return result, nil
	}
	if !consistent {
		result.ErrorCode = "RUNTIME_CHANGED"
		return result, errors.New("保存配置与运行时不一致，请确认加载状态后重新诊断")
	}
	guard, err := newHealthDialGuard(env.Listeners)
	if err != nil {
		return result, err
	}
	switch req.Phase {
	case "local_ingress":
		result.Checks = []resp.WebsiteDiagnosticCheck{s.localIngress(ctx, req, cfg, snap, visitor, headers, env.Listeners, guard)}
	case "origin":
		result.Total = len(snap.OriginPlans)
		if len(snap.OriginPlans) == 0 {
			result.Checks = append(result.Checks, diagnosticCheck("origin", "源站检测", "skipped", "NO_ORIGIN", "当前路径处理方式为"+snap.Mode+"，没有需要独立检测的回源目标"))
			break
		}
		if req.OriginCursor >= len(snap.OriginPlans) {
			return result, errors.New("源站分页已变化，请重新诊断")
		}
		end := req.OriginCursor + 5
		if end > len(snap.OriginPlans) {
			end = len(snap.OriginPlans)
		}
		plans := snap.OriginPlans[req.OriginCursor:end]
		result.Checks = make([]resp.WebsiteDiagnosticCheck, len(plans))
		var wg sync.WaitGroup
		workers := make(chan struct{}, 2)
		for i, plan := range plans {
			wg.Add(1)
			go func(i int, plan wafenginmodel.WebsiteDiagnosticOriginPlan) {
				defer wg.Done()
				select {
				case workers <- struct{}{}:
					defer func() { <-workers }()
				case <-ctx.Done():
					result.Checks[i] = diagnosticCheck(fmt.Sprintf("origin-%d", req.OriginCursor+i), "源站检测", "skipped", "CANCELLED", "诊断已取消或超时")
					return
				}
				id := fmt.Sprintf("origin-%d", req.OriginCursor+i)
				if plan.Error != "" {
					result.Checks[i] = diagnosticCheck(id, "源站检测", "failed", "ORIGIN_CONFIG", "源站地址无法构造，请检查已保存的回源配置")
					return
				}
				r := wafdiagnose.Run(ctx, wafdiagnose.Target{URL: plan.URL, Method: req.Method, Headers: plan.Headers, Host: plan.Host, FixedAddress: plan.FixedAddress, Fallback: plan.FallbackAddress != "", InsecureSkipVerify: plan.InsecureSkipVerify, DialGuard: guard})
				result.Checks[i] = diagnosticProbeCheck(id, "源站检测 "+strconv.Itoa(req.OriginCursor+i+1), "独立源站请求，不是WAF实际转发报文", r)
			}(i, plan)
		}
		wg.Wait()
		if end < result.Total {
			result.NextCursor, result.HasMore = end, true
		}
	case "access_url":
		r := wafdiagnose.Run(ctx, wafdiagnose.Target{URL: req.VisitorURL, Method: req.Method, Headers: headers, Public: true, AllowProxy: req.UseSystemProxy, DialGuard: guard})
		source := "服务器视角直连且不使用环境代理，不能代表用户浏览器网络"
		if req.UseSystemProxy {
			source = "服务器视角经系统代理访问，不能代表用户浏览器网络"
		}
		check := diagnosticProbeCheck("access_url", "实际访问地址", source, r)
		if !req.UseSystemProxy && utils.HasSystemProxy() && check.Status == "failed" {
			check.Advice = append(check.Advice, diagnosticAdvice("USE_SYSTEM_PROXY",
				"检测到运行环境已配置系统代理；如本站经代理出网，可开启「跟随系统代理」后重试", "listen"))
		}
		result.Checks = []resp.WebsiteDiagnosticCheck{check}
	default:
		return result, errors.New("诊断阶段不合法")
	}
	return result, nil
}

func diagnosticURLPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (s *WafHostDiagnosticService) localIngress(ctx context.Context, req request.WafHostDiagnosticReq, cfg diagnosticConfiguration, snap wafenginmodel.WebsiteDiagnosticSnapshot, visitor *url.URL, headers http.Header, listeners *wafenginmodel.SafeServerMap, originGuard func(string) error) resp.WebsiteDiagnosticCheck {
	skipped := func(code, message string) resp.WebsiteDiagnosticCheck {
		c := diagnosticCheck("local_ingress", "本机WAF入口", "skipped", code, message)
		c.Advice = append(c.Advice, diagnosticAdvice(code, "检查基础内容中的监听协议、端口与来源域名；本机检测仅连接本站已登记业务端口", "listen"))
		return c
	}
	if cfg.Host.START_STATUS != 0 || snap.MatchCode != cfg.Host.Code {
		return skipped("HOST_MISMATCH", "站点已关闭或当前URL未匹配所选网站，未向其他本机入口发送请求")
	}
	port, _ := strconv.Atoi(diagnosticURLPort(visitor))
	if port == global.GWAF_LOCAL_SERVER_PORT || listeners == nil {
		return skipped("LISTENER_UNAVAILABLE", "缺少可使用的本站业务监听")
	}
	var selected *utils.HostListen
	for _, l := range utils.ResolveHostListens(cfg.Host) {
		if l.Port == port && l.Protocol == visitor.Scheme {
			copy := l
			selected = &copy
			break
		}
	}
	if selected == nil {
		return skipped("LISTENER_MISMATCH", "访问协议或端口不属于所选网站监听；未猜测或扫描其他本机端口")
	}
	runtime, ok := listeners.Get(port)
	if !ok || runtime.Status != 0 || runtime.ServerType != selected.Protocol || runtime.Svr == nil {
		return skipped("LISTENER_UNAVAILABLE", "本站监听尚无可检测的运行记录；登记状态本身不证明绑定成功")
	}
	unverified, err := diagnosticOriginLoopCheck(ctx, snap.OriginPlans, originGuard)
	if err != nil {
		return skipped("ORIGIN_LOOP_OR_UNKNOWN", "回源目标指向本机业务监听；本次不触发入口回源，请先检查独立源站结果")
	}
	ip := "127.0.0.1"
	if selected.IPVersion == "ipv6" {
		ip = "::1"
	}
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	localGuard := func(actual string) error {
		if actual != address || port == global.GWAF_LOCAL_SERVER_PORT {
			return errors.New("本机入口仅允许所选业务监听")
		}
		return nil
	}
	r := wafdiagnose.Run(ctx, wafdiagnose.Target{URL: req.VisitorURL, Method: req.Method, Headers: headers, FixedAddress: address, DialGuard: localGuard})
	check := diagnosticProbeCheck("local_ingress", "本机WAF入口", "本站业务监听真实请求；正常经过认证、防护、缓存和访问日志", r)
	if len(unverified) > 0 && check.Status != "failed" {
		check.Status = "warning"
		check.Message += "；部分回源地址未完成解析核验：" + strings.Join(unverified, "、")
	}
	return check
}

// 解析全部回源计划的实际地址；确认命中受保护本机监听时返回错误，
// 解析失败的地址归入 unverified 由调用方标注，不因单个后端 DNS 抖动阻断整个入口检测
func diagnosticOriginLoopCheck(ctx context.Context, plans []wafenginmodel.WebsiteDiagnosticOriginPlan, guard func(string) error) ([]string, error) {
	if len(plans) > 100 {
		return nil, errors.New("回源目标过多")
	}
	var unverified []string
	for _, plan := range plans {
		if plan.Error != "" {
			return nil, errors.New("回源配置无效")
		}
		for _, address := range []string{plan.FixedAddress, plan.FallbackAddress} {
			if address == "" {
				continue
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				unverified = append(unverified, address)
				continue
			}
			for _, ip := range ips {
				if err := guard(net.JoinHostPort(ip.IP.String(), port)); err != nil {
					return nil, err
				}
			}
		}
	}
	return unverified, nil
}
