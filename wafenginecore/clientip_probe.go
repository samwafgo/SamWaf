package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafenginecore/clientip"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 真实IP来源诊断探针
//
// 背景：站点挂在 CDN/多层代理后面时，"真实IP来源"到底该配哪个头，只能看真实到达的请求头才能确定。
// 以前这信息只散落在访问日志详情里，排查得跳来跳去(issue #956)。这里在内存里常驻保留每个站点
// 最近几次请求的原始头，管理端在「其他配置 → 真实IP来源」处就能直接看。
//
// 热点路径成本：每请求一次 sync.Map 读 + 一次原子比较；同一站点每秒最多采样一次，
// 采样时才拷贝头。不落库、不进日志队列，进程重启即清空。
const (
	ipProbeMaxSamples   = 5                  // 每站保留最近几条
	ipProbeIntervalNano = int64(time.Second) // 同站采样最小间隔
	ipProbeMaxHosts     = 500                // 最多跟踪多少个站点(防止 hostCode 无限增长)
	ipProbeMaxHeaders   = 60                 // 单条样本最多记录多少个头
	ipProbeMaxValueLen  = 256                // 单个头值最长保留长度
	ipProbeSampleTTL    = 30 * time.Minute   // 样本过期时间(读取时丢弃)
)

// ipProbeSensitiveHeaders 一律脱敏的头(整体替换，不做部分保留)
var ipProbeSensitiveHeaders = map[string]struct{}{
	"cookie":              {},
	"set-cookie":          {},
	"authorization":       {},
	"proxy-authorization": {},
}

// ipProbeSensitiveKeywords 头名带这些关键字的一律脱敏(自定义鉴权头五花八门，按关键字兜底)
var ipProbeSensitiveKeywords = []string{"token", "secret", "password", "passwd", "credential", "api-key", "apikey", "auth", "session", "signature"}

// ipProbeKnownIPHeaders 常见的"客户端真实IP"候选头，命中的在界面上高亮，方便用户直接选用
var ipProbeKnownIPHeaders = map[string]struct{}{
	"x-forwarded-for":          {},
	"x-real-ip":                {},
	"x-client-ip":              {},
	"x-original-forwarded-for": {},
	"x-forwarded":              {},
	"forwarded":                {},
	"forwarded-for":            {},
	"proxy-client-ip":          {},
	"wl-proxy-client-ip":       {},
	"http-client-ip":           {},
	"true-client-ip":           {},
	"cf-connecting-ip":         {},
	"fastly-client-ip":         {},
	"eo-connecting-ip":         {},
	"ali-cdn-real-ip":          {},
	"ali-swift-real-ip":        {},
	"cdn-src-ip":               {},
	"remote-host":              {},
	"x-cluster-client-ip":      {},
}

// IPProbeHeader 一条头信息(已脱敏)
type IPProbeHeader struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	IsIPHeader bool   `json:"is_ip_header"` //是否属于常见真实IP候选头
	ParsedIP   string `json:"parsed_ip"`    //该头里第一个合法IP(没有则为空)
	Masked     bool   `json:"masked"`       //值是否被脱敏
}

// IPProbeSample 一次请求的IP来源快照
type IPProbeSample struct {
	Time       string          `json:"time"`
	UnixTime   int64           `json:"unix_time"`
	Host       string          `json:"host"`
	URL        string          `json:"url"`
	Method     string          `json:"method"`
	Proto      string          `json:"proto"`
	NetIP      string          `json:"net_ip"`      //网络层直连对端IP(即"上一跳")
	ResolvedIP string          `json:"resolved_ip"` //当前配置实际解析出的客户端IP
	Mode       string          `json:"mode"`        //采样时生效的真实IP来源模式
	Fallback   bool            `json:"fallback"`    //解析结果 == 网络层IP(说明没从头里取到)
	Headers    []IPProbeHeader `json:"headers"`
}

type ipProbeEntry struct {
	lastAt  int64 //上次采样时间(unix nano)，原子读写
	mu      sync.Mutex
	samples []IPProbeSample
}

var (
	ipProbeStore sync.Map // hostCode -> *ipProbeEntry
	ipProbeHosts int32    // 已跟踪站点数(近似值，用于封顶)
)

// recordIPProbe 记录一次IP来源采样。调用点在业务请求主流程，必须保持"未采样时几乎零成本"。
func recordIPProbe(host model.Hosts, r *http.Request, resolvedIP string) {
	// 默认关闭：不开探针时这里只花一次整型比较，业务请求不受任何影响
	if global.GCONFIG_IPPROBE_ENABLE != 1 {
		return
	}
	if host.Code == "" || r == nil {
		return
	}
	now := time.Now()
	nowNano := now.UnixNano()

	var entry *ipProbeEntry
	if v, ok := ipProbeStore.Load(host.Code); ok {
		entry = v.(*ipProbeEntry)
	} else {
		if atomic.LoadInt32(&ipProbeHosts) >= ipProbeMaxHosts {
			return
		}
		v, loaded := ipProbeStore.LoadOrStore(host.Code, &ipProbeEntry{})
		entry = v.(*ipProbeEntry)
		if !loaded {
			atomic.AddInt32(&ipProbeHosts, 1)
		}
	}

	last := atomic.LoadInt64(&entry.lastAt)
	if nowNano-last < ipProbeIntervalNano {
		return
	}
	// CAS 失败说明同一时刻已有别的请求在采样，直接放弃(采样尽力而为，不需要精确)
	if !atomic.CompareAndSwapInt64(&entry.lastAt, last, nowNano) {
		return
	}

	netIP := utils.GetSourceClientIP(r.RemoteAddr)
	sample := IPProbeSample{
		Time:       now.Format("2006-01-02 15:04:05"),
		UnixTime:   now.Unix(),
		Host:       r.Host,
		URL:        utils.TruncateString(r.RequestURI, 200),
		Method:     r.Method,
		Proto:      r.Proto,
		NetIP:      netIP,
		ResolvedIP: resolvedIP,
		Mode:       host.IPSourceMode,
		Fallback:   resolvedIP != "" && resolvedIP == netIP,
		Headers:    snapshotHeaders(r),
	}

	entry.mu.Lock()
	entry.samples = append(entry.samples, sample)
	if len(entry.samples) > ipProbeMaxSamples {
		entry.samples = entry.samples[len(entry.samples)-ipProbeMaxSamples:]
	}
	entry.mu.Unlock()
}

// snapshotHeaders 拷贝并脱敏请求头。按头名排序，保证界面展示稳定。
func snapshotHeaders(r *http.Request) []IPProbeHeader {
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > ipProbeMaxHeaders {
		names = names[:ipProbeMaxHeaders]
	}
	headers := make([]IPProbeHeader, 0, len(names))
	for _, name := range names {
		lower := strings.ToLower(name)
		value := strings.Join(r.Header.Values(name), ", ")
		item := IPProbeHeader{Name: name}
		if isSensitiveHeader(lower) {
			item.Value = "***"
			item.Masked = true
		} else {
			item.Value = utils.TruncateString(value, ipProbeMaxValueLen)
			_, item.IsIPHeader = ipProbeKnownIPHeaders[lower]
			item.ParsedIP = firstValidIPInValue(value)
		}
		headers = append(headers, item)
	}
	return headers
}

func isSensitiveHeader(lowerName string) bool {
	if _, ok := ipProbeSensitiveHeaders[lowerName]; ok {
		return true
	}
	for _, kw := range ipProbeSensitiveKeywords {
		if strings.Contains(lowerName, kw) {
			return true
		}
	}
	return false
}

// firstValidIPInValue 取头值里第一个合法IP(逗号分隔)，用于界面提示"这个头能取到什么IP"
func firstValidIPInValue(val string) string {
	for _, part := range strings.Split(val, ",") {
		ip := strings.TrimSpace(part)
		if utils.IsValidIPv4(ip) || utils.IsValidIPv6(ip) {
			return ip
		}
	}
	return ""
}

// ClearAllIPProbeSamples 清空所有站点的采样(关闭探针开关时调用，不留内存残留)
func ClearAllIPProbeSamples() {
	ipProbeStore.Range(func(key, value any) bool {
		ipProbeStore.Delete(key)
		return true
	})
	atomic.StoreInt32(&ipProbeHosts, 0)
}

// IPProbeEnabled 探针是否开启(管理端展示用)
func IPProbeEnabled() bool {
	return global.GCONFIG_IPPROBE_ENABLE == 1
}

// IPProbeMaxSamples 每站保留的样本条数上限(管理端展示用，避免前后端各写一份)
func IPProbeMaxSamples() int {
	return ipProbeMaxSamples
}

// GetIPProbeSamples 取某站点最近的采样(按时间倒序)，过期样本直接丢弃
func GetIPProbeSamples(hostCode string) []IPProbeSample {
	v, ok := ipProbeStore.Load(hostCode)
	if !ok {
		return nil
	}
	entry := v.(*ipProbeEntry)
	entry.mu.Lock()
	src := make([]IPProbeSample, len(entry.samples))
	copy(src, entry.samples)
	entry.mu.Unlock()

	deadline := time.Now().Add(-ipProbeSampleTTL).Unix()
	result := make([]IPProbeSample, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		if src[i].UnixTime < deadline {
			continue
		}
		result = append(result, src[i])
	}
	return result
}

// ClearIPProbeSamples 清空某站点的采样(界面"清空"按钮用，站点删除后也可释放)
func ClearIPProbeSamples(hostCode string) {
	if v, ok := ipProbeStore.Load(hostCode); ok {
		entry := v.(*ipProbeEntry)
		entry.mu.Lock()
		entry.samples = nil
		entry.mu.Unlock()
	}
}

// IPSourceEffectiveHeader 返回当前配置下实际生效的真实IP头名(空表示该模式不看头)
func IPSourceEffectiveHeader(host model.Hosts) string {
	header := strings.TrimSpace(host.IPRealHeader)
	switch host.IPSourceMode {
	case "header":
		return header
	case "xff_depth":
		if header == "" {
			return "X-Forwarded-For"
		}
		return header
	case "cdn_preset":
		if header == "" {
			return clientip.DefaultHeader(host.CDNProvider)
		}
		return header
	default:
		// nic 不看头；""(兼容模式)取全局配置头，由上层单独展示
		return ""
	}
}

// IsIPSourceTrustedPeer 判断网络层来源在当前配置下是否算"可信上一跳"。
// header/cdn_preset 模式下不可信就意味着头里的IP会被丢弃、回退网络层IP——这正是最常见的排查点。
func IsIPSourceTrustedPeer(host model.Hosts, netIP string) bool {
	if netIP == "" {
		return false
	}
	switch host.IPSourceMode {
	case "cdn_preset":
		if clientip.IsProviderIP(host.CDNProvider, netIP) {
			return true
		}
		return ipInCIDRList(netIP, host.IPTrustProxies)
	case "header", "xff_depth":
		if strings.TrimSpace(host.IPTrustProxies) == "" {
			return true //没配可信网段 = 不做来源校验
		}
		return ipInCIDRList(netIP, host.IPTrustProxies)
	default:
		return true
	}
}

// IPSourceProviderRangeCount 当前厂商已下载的回源段条数(cdn_preset 下为0说明来源校验必然失败)
func IPSourceProviderRangeCount(host model.Hosts) int {
	if host.IPSourceMode != "cdn_preset" || host.CDNProvider == "" {
		return 0
	}
	return clientip.GetProviderRanges(host.CDNProvider).Len()
}
