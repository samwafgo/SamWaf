package waf_service

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

const (
	tamperExtractTimeout = 10 * time.Second // 抓取超时
	tamperExtractMaxBody = 4 * 1024 * 1024  // 抓取正文上限 4MB
	tamperExtractMaxURLs = 300              // 返回候选上限
)

// DiscoveredURL 从页面提取到的受保护 URL 候选
type DiscoveredURL struct {
	Url  string `json:"url"`
	Type string `json:"type"` // js/css/html/img/other
}

// ExtractUrlsApi 抓取「当前站点后端」的一个页面，解析出同站静态资源引用供批量添加。
// 安全边界：只抓该站点已配置的后端（Remote_host:Remote_port，SamWaf 本就代理的目标），
// 不接受任意外部地址；用户填的 page_url 只取其 path，强制走本站后端，无新增对外请求出口、无 SSRF。
func (receiver *WafTamperRuleService) ExtractUrlsApi(req request.WafTamperRuleExtractReq) ([]DiscoveredURL, error) {
	if strings.TrimSpace(req.HostCode) == "" {
		return nil, errors.New("缺少站点标识")
	}
	var host model.Hosts
	global.GWAF_LOCAL_DB.Where("code=?", req.HostCode).First(&host)
	if host.Id == "" {
		return nil, errors.New("站点不存在")
	}
	if strings.TrimSpace(host.Remote_host) == "" {
		return nil, errors.New("该站点未配置后端地址，无法提取")
	}

	// 只取 path，忽略用户填的 host —— 强制走本站后端，杜绝任意地址抓取
	reqPath := extractPathOnly(req.PageUrl)
	// 选定抓取域名：只能是本站 host 或 BindMoreHost 之一，作为 Host 头与同站过滤基准
	siteHosts := buildSiteHosts(host)
	domain := pickExtractDomain(req.Domain, siteHosts, host.Host)

	// 后端抓取地址：镜像 wafworker 的 Remote_host+":"+Remote_port
	target := host.Remote_host + ":" + strconv.Itoa(host.Remote_port)
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	backendURL, err := url.Parse(target)
	if err != nil || backendURL.Host == "" {
		return nil, errors.New("后端地址无效")
	}
	backendURL.Path = reqPath
	backendURL.RawQuery = ""

	httpReq, err := http.NewRequest(http.MethodGet, backendURL.String(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Host = domain // 让后端按选定站点域名路由
	httpReq.Header.Set("User-Agent", "SamWaf-TamperExtractor")

	resp, err := buildBackendClient(host).Do(httpReq)
	if err != nil {
		return nil, errors.New("抓取后端页面失败:" + err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, tamperExtractMaxBody))
	if err != nil {
		return nil, errors.New("读取页面内容失败:" + err.Error())
	}

	// 归一化基准用「站点域名 + 请求路径」，这样 HTML 里写成站点绝对地址的引用也能被识别为同站
	scheme := "http"
	if host.Ssl == 1 {
		scheme = "https"
	}
	siteBase := &url.URL{Scheme: scheme, Host: domain, Path: reqPath}
	return extractTamperCandidates(body, siteBase, siteHosts), nil
}

// pickExtractDomain 选定抓取用域名：请求指定且属于本站(host/BindMoreHost)才用，否则回退主域名，杜绝任意 Host
func pickExtractDomain(reqDomain string, siteHosts map[string]bool, defaultHost string) string {
	d := strings.ToLower(strings.TrimSpace(reqDomain))
	if hh, _, err := net.SplitHostPort(d); err == nil {
		d = hh
	}
	if d != "" && siteHosts[d] {
		return d
	}
	return defaultHost
}

// extractPathOnly 从用户输入里只提取 path（默认 /），忽略 host/query/fragment
func extractPathOnly(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "/"
	}
	if u, err := url.Parse(s); err == nil && u.Path != "" {
		return ensureLeadingSlash(u.Path)
	}
	return ensureLeadingSlash(s)
}

func ensureLeadingSlash(p string) string {
	// 去掉可能带的 query/fragment
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// buildSiteHosts 站点自身可识别的域名集合（主域名 + 绑定多域名），用于同站过滤
func buildSiteHosts(host model.Hosts) map[string]bool {
	set := map[string]bool{}
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		set[h] = true
	}
	add(host.Host)
	for _, line := range strings.Split(host.BindMoreHost, "\n") {
		add(line)
	}
	return set
}

// buildBackendClient 构造只连本站后端的 http.Client：Remote_ip 覆盖拨号、后端 TLS 校验开关、超时、禁跟随重定向
func buildBackendClient(host model.Hosts) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: host.InsecureSkipVerify == 1},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	if ip := strings.TrimSpace(host.Remote_ip); ip != "" {
		port := strconv.Itoa(host.Remote_port)
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		}
	} else {
		tr.DialContext = dialer.DialContext
	}
	return &http.Client{
		Timeout:   tamperExtractTimeout,
		Transport: tr,
		// 不自动跟随重定向，避免被后端 3xx 带去其它地址
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// extractTamperCandidates 纯函数：解析 HTML，提取同站静态资源引用（去重、归一化为 path、限量）
func extractTamperCandidates(htmlContent []byte, siteBase *url.URL, siteHosts map[string]bool) []DiscoveredURL {
	z := html.NewTokenizer(bytes.NewReader(htmlContent))
	seen := map[string]bool{}
	out := make([]DiscoveredURL, 0, 16)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		tag := string(name)
		var attrKey string
		switch tag {
		case "script", "img":
			attrKey = "src"
		case "link", "a":
			attrKey = "href"
		default:
			continue
		}
		ref := readTagAttr(z, hasAttr, attrKey)
		p := normalizeTamperRef(ref, siteBase, siteHosts)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, DiscoveredURL{Url: p, Type: classifyTamperURL(p, tag)})
		if len(out) >= tamperExtractMaxURLs {
			break
		}
	}
	return out
}

// readTagAttr 从 tokenizer 当前标签里取指定属性值
func readTagAttr(z *html.Tokenizer, hasAttr bool, key string) string {
	if !hasAttr {
		return ""
	}
	for {
		k, v, more := z.TagAttr()
		if string(k) == key {
			return string(v)
		}
		if !more {
			return ""
		}
	}
}

// normalizeTamperRef 把引用归一化为「本站精确 path」，非同站/非法/带通配的返回空
func normalizeTamperRef(ref string, siteBase *url.URL, siteHosts map[string]bool) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return ""
	}
	low := strings.ToLower(ref)
	for _, skip := range []string{"data:", "javascript:", "mailto:", "tel:", "blob:", "about:"} {
		if strings.HasPrefix(low, skip) {
			return ""
		}
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := siteBase.ResolveReference(u)
	if h := strings.ToLower(resolved.Hostname()); h != "" && !siteHosts[h] {
		return "" // 第三方资源，无法保护
	}
	p := resolved.Path
	if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "*") {
		return ""
	}
	return p
}

// classifyTamperURL 按扩展名/标签给候选归类
func classifyTamperURL(path, tag string) string {
	lp := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lp, ".js"), strings.HasSuffix(lp, ".mjs"):
		return "js"
	case strings.HasSuffix(lp, ".css"):
		return "css"
	case strings.HasSuffix(lp, ".html"), strings.HasSuffix(lp, ".htm"):
		return "html"
	}
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp"} {
		if strings.HasSuffix(lp, ext) {
			return "img"
		}
	}
	switch tag {
	case "script":
		return "js"
	case "link":
		return "css"
	case "img":
		return "img"
	case "a":
		return "html"
	}
	return "other"
}

// sha256HexSvc 计算内容 sha256 十六进制（service 层本地实现，避免依赖 wafenginecore）
func sha256HexSvc(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// pushTamperReload 重新读取该站点规则并推送引擎热重载（与 api.NotifyWaf 等价）
func pushTamperReload(hostCode string) {
	var list []model.TamperRule
	global.GWAF_LOCAL_DB.Where("host_code = ?", hostCode).Find(&list)
	global.GWAF_CHAN_MSG <- spec.ChanCommonHost{
		HostCode: hostCode,
		Type:     enums.ChanTypeTamperRule,
		Content:  list,
	}
}

// fetchAndCaptureBaseline 后端自请求该规则 URL、抓取正文并写入基线（即时重新学习）。
// 只抓本站后端；不广告 br/zstd，Go 自动解 gzip，正文即“解压后内容”，与引擎哈希基准一致。
func fetchAndCaptureBaseline(host model.Hosts, rule model.TamperRule, cfg model.TamperConfig) {
	now := time.Now().Format("2006-01-02 15:04:05")
	setFail := func(msg string) {
		global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("id=?", rule.Id).Updates(map[string]interface{}{
			"BaselineStatus": 2, "BaselineMsg": msg, "LastLearnTime": now,
		})
	}
	target := host.Remote_host + ":" + strconv.Itoa(host.Remote_port)
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	bu, err := url.Parse(target)
	if err != nil || bu.Host == "" {
		setFail("后端地址无效，重新学习自抓失败")
		return
	}
	bu.Path = rule.Url
	bu.RawQuery = ""
	httpReq, err := http.NewRequest(http.MethodGet, bu.String(), nil)
	if err != nil {
		setFail("构造请求失败:" + err.Error())
		return
	}
	httpReq.Host = host.Host
	httpReq.Header.Set("User-Agent", "SamWaf-TamperRelearn")

	resp, err := buildBackendClient(host).Do(httpReq)
	if err != nil {
		setFail("重新学习自抓失败:" + err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		setFail(fmt.Sprintf("重新学习自抓返回状态码 %d，未学习", resp.StatusCode))
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, tamperExtractMaxBody))
	if err != nil || len(body) == 0 {
		setFail("重新学习读取正文失败或为空")
		return
	}
	maxKB := cfg.MaxSizeKB
	if maxKB <= 0 {
		maxKB = 1024
	}
	if len(body) > maxKB*1024 {
		setFail(fmt.Sprintf("正文 %d 字节超过上限 %d KB，未学习", len(body), maxKB))
		return
	}
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("id=?", rule.Id).Updates(map[string]interface{}{
		"BaselineHash":    sha256HexSvc(body),
		"BaselineContent": body,
		"ContentType":     resp.Header.Get("Content-Type"),
		"StatusCode":      resp.StatusCode,
		"ContentSize":     len(body),
		"BaselineStatus":  1,
		"BaselineMsg":     "重新学习已抓取",
		"LastLearnTime":   now,
	})
}

// backgroundRecapture 后台对指定规则(ids 空=该站点全部启用规则)自请求重新抓取基线，完成后热重载。
// 只抓本站后端、限并发、异步不阻塞接口；无后端(纯静态站点)则跳过，保持惰性下次访问再学。
func (receiver *WafTamperRuleService) backgroundRecapture(hostCode string, ids []string) {
	go func() {
		var host model.Hosts
		global.GWAF_LOCAL_DB.Where("code=?", hostCode).First(&host)
		if host.Id == "" || strings.TrimSpace(host.Remote_host) == "" {
			return
		}
		var rules []model.TamperRule
		db := global.GWAF_LOCAL_DB.Where("host_code=?", hostCode)
		if len(ids) > 0 {
			db = db.Where("id in ?", ids)
		}
		db.Find(&rules)
		cfg := model.ParseTamperConfig(host.TamperJSON)
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for i := range rules {
			if rules[i].IsEnable != 1 {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(rule model.TamperRule) {
				defer wg.Done()
				defer func() { <-sem }()
				fetchAndCaptureBaseline(host, rule, cfg)
			}(rules[i])
		}
		wg.Wait()
		pushTamperReload(hostCode)
	}()
}
