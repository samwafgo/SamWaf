package wafwebcache

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
)

// mib 统一配置中的 MB 换算：实际使用 1024×1024 字节，而非十进制 MB。
const mib = int64(1 << 20)

// settings 是一次配置解析后的只读预算，容量均为字节，时间均为 time.Duration。
// 总容量与单对象上限分开保存，避免再次把「允许单条大小」误当作「总占用上限」。
type settings struct {
	Dir                                            string
	L1Bytes, L2Bytes, L1ObjectBytes, L2ObjectBytes int64
	MinFreeBytes                                   int64
	HeatHits, MaxEntries                           int
	HeatWindow, Inactive, LockTimeout              time.Duration
}

// positiveMB 拒绝非有限数、非正数和溢出值；这些值使用有限默认预算，不表示无限制。
func positiveMB(v float64, fallback int64) int64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return fallback
	}
	if v > float64(math.MaxInt64/mib) {
		return fallback
	}
	return int64(v * float64(mib))
}

// normalize 为旧站点缺失的新字段补默认值，并把单对象上限收敛到对应层总容量内。
// 返回值只服务当前配置快照，不回写用户的 CacheJSON。
func normalize(c model.CacheConfig) settings {
	s := settings{Dir: c.CacheDir, L1Bytes: positiveMB(c.L1CapacityMB, 64*mib), L2Bytes: positiveMB(c.L2CapacityMB, 1024*mib), L1ObjectBytes: positiveMB(c.MaxMemorySizeMB, 4*mib), L2ObjectBytes: positiveMB(c.MaxFileSizeMB, 32*mib), HeatHits: c.HeatThreshold, MaxEntries: c.MaxEntries, HeatWindow: time.Duration(c.HeatWindowSeconds) * time.Second, Inactive: time.Duration(c.InactiveSeconds) * time.Second, LockTimeout: time.Duration(c.LockTimeoutSeconds) * time.Second}
	if s.Dir == "" {
		s.Dir = "./data/cache"
	}
	s.MinFreeBytes = positiveMB(c.MinFreeMB, 64*mib)
	if s.HeatHits <= 0 || s.HeatHits > 1000000 {
		s.HeatHits = 3
	}
	if s.MaxEntries <= 0 || s.MaxEntries > 1000000 {
		s.MaxEntries = 100000
	}
	if s.HeatWindow <= 0 || s.HeatWindow > 24*time.Hour {
		s.HeatWindow = 90 * time.Minute
	}
	if s.Inactive <= 0 {
		s.Inactive = 24 * time.Hour
	}
	if s.LockTimeout <= 0 || s.LockTimeout > time.Minute {
		s.LockTimeout = 5 * time.Second
	}
	if s.L1ObjectBytes > s.L1Bytes {
		s.L1ObjectBytes = s.L1Bytes
	}
	if s.L2ObjectBytes > s.L2Bytes {
		s.L2ObjectBytes = s.L2Bytes
	}
	return s
}

// hashFields 对每个 UTF-8 字段先写长度再写内容，避免不同字段边界拼成同一个输入。
func hashFields(fields ...string) string {
	h := sha256.New()
	for _, field := range fields {
		writeField(h, field)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeField 使用固定宽度大端长度编码，调用双方必须采用相同字段顺序。
func writeField(h hash.Hash, field string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(field)))
	h.Write(size[:])
	h.Write([]byte(field))
}

// policyRevision 将路由、缓存规则、站点及全局响应处理配置纳入内容命名空间。
// 配置改变后旧对象不可再命中；相同配置可在重启后复用 L2。只使用摘要作为键，配置原文不落入键名。
func policyRevision(host *wafenginmodel.HostSafe, cfg model.CacheConfig, globalHost ...*wafenginmodel.HostSafe) string {
	rules := append([]model.CacheRule(nil), host.CacheRule...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].Id < rules[j].Id
	})
	b, _ := json.Marshal(struct {
		Host   model.Hosts
		Target string
		Rules  []model.CacheRule
		Config model.CacheConfig
	}{host.Host, host.TargetHost, rules, cfg})
	content, _ := json.Marshal([]interface{}{host.LdpUrlLists, host.PathRules, host.TamperRules, host.BlockingPage, host.RuleData, host.RuleVersionSum})
	globalRevision := ""
	if len(globalHost) > 0 && globalHost[0] != nil {
		globalRevision = policyRevision(globalHost[0], model.CacheConfig{})
	}
	return hashFields(string(b), string(content), globalRevision)
}

// baseKey 隔离配置版本、协议、实际 Host 和完整查询串；HEAD 共享 GET 的表示。
// param_type 仅影响规则匹配，不能在此丢弃可能改变源站内容的查询参数。
func baseKey(r *http.Request, revision string) string {
	scheme := "http"
	if r.TLS != nil || r.URL.Scheme == "https" {
		scheme = "https"
	}
	return hashFields(revision, scheme, strings.ToLower(r.Host), "GET", r.URL.RequestURI())
}

// present 按不区分大小写的字段名检查「是否出现」，空值凭据头也会触发共享缓存绕过。
func present(h http.Header, name string) bool {
	for k := range h {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// values 收集同名字段的全部值，使重复 Cache-Control/Vary/条件请求头都参与判断。
func values(h http.Header, name string) []string {
	var result []string
	for k, v := range h {
		if strings.EqualFold(k, name) {
			result = append(result, v...)
		}
	}
	return result
}

// requestCacheable 只准入公共、无正文 GET/HEAD；凭据、连接升级和 Range 请求直接回源。
// 这里同时限制读缓存和填充，防止私有请求借用事先预热的匿名公共对象。
func requestCacheable(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Body != nil && r.Body != http.NoBody || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key", "Upgrade", "Range", "If-Range", "X-SamWaf-Access-User", "X-SamWaf-Access-Session"} {
		if present(r.Header, name) {
			return false
		}
	}
	for _, name := range []string{"Cache-Control", "Pragma"} {
		for _, v := range values(r.Header, name) {
			for _, part := range strings.Split(v, ",") {
				part = strings.ToLower(strings.TrimSpace(part))
				pieces := strings.SplitN(part, "=", 2)
				name := strings.TrimSpace(pieces[0])
				if name == "no-cache" || name == "no-store" || name == "max-age" && len(pieces) == 2 && strings.Trim(strings.TrimSpace(pieces[1]), "\"") == "0" {
					return false
				}
			}
		}
	}
	return true
}

// checkCacheRule 返回最高优先级匹配规则的 TTL 秒数，非正 TTL 明确禁止读写缓存。
func checkCacheRule(host *wafenginmodel.HostSafe, _ model.CacheConfig, r *http.Request) (int, error) {
	// HostSafe 已发布快照由并发请求共享，只扫描选优，不能原地排序其规则切片。
	best := -1
	for i, rule := range host.CacheRule {
		if !checkRequestMethod(r.Method, rule.RequestMethod) {
			continue
		}
		path := r.URL.RequestURI()
		if rule.ParamType == 1 {
			path = r.URL.Path
		}
		matched := false
		switch rule.RuleType {
		case 1:
			matched = checkSuffixMatch(path, rule.RuleContent)
		case 2:
			matched = checkDirectoryMatch(path, rule.RuleContent)
		case 3:
			matched = checkExactFileMatch(path, rule.RuleContent)
		}
		if matched && (best < 0 || rule.Priority > host.CacheRule[best].Priority) {
			best = i
		}
	}
	if best < 0 {
		return 0, errors.New("no matching cache rule")
	}
	if host.CacheRule[best].CacheTime <= 0 {
		return 0, errors.New("cache disabled by rule")
	}
	return host.CacheRule[best].CacheTime, nil
}

// checkRequestMethod 保留旧规则的分号分隔语法；空清单匹配所有方法，最终仍受公共请求准入约束。
func checkRequestMethod(method, methods string) bool {
	if methods == "" {
		return true
	}
	for _, item := range strings.Split(methods, ";") {
		if strings.TrimSpace(item) == method {
			return true
		}
	}
	return false
}

// checkSuffixMatch 在分号分隔的非空后缀中查找匹配项。
func checkSuffixMatch(path, list string) bool { return matchList(path, list, strings.HasSuffix) }

// checkDirectoryMatch 使用前缀语义，目录边界由规则中是否带末尾斜线决定。
func checkDirectoryMatch(path, list string) bool { return matchList(path, list, strings.HasPrefix) }

// checkExactFileMatch 对规则选定的路径或完整 URI 做精确匹配。
func checkExactFileMatch(path, list string) bool {
	return matchList(path, list, func(a, b string) bool { return a == b })
}

// matchList 统一处理空白、大小写和空项，保持原有缓存规则的比较语义。
func matchList(path, list string, match func(string, string) bool) bool {
	for _, item := range strings.Split(list, ";") {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" && match(strings.ToLower(path), item) {
			return true
		}
	}
	return false
}

// varyFields 规范化、去重并排序 Vary 字段；通配符或非法/过长清单拒绝入库。
// 排序保证字段声明顺序不同不会生成不同的同义变体键。
func varyFields(h http.Header) ([]string, bool) {
	set := map[string]bool{}
	for _, line := range values(h, "Vary") {
		for _, field := range strings.Split(line, ",") {
			field = http.CanonicalHeaderKey(strings.TrimSpace(field))
			if field == "" {
				continue
			}
			if field == "*" || len(field) > 128 {
				return nil, false
			}
			for _, c := range field {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
					return nil, false
				}
			}
			set[field] = true
		}
	}
	if len(set) > 32 {
		return nil, false
	}
	result := make([]string, 0, len(set))
	for field := range set {
		result = append(result, field)
	}
	sort.Strings(result)
	return result, true
}

// variantKey 在基础键之外绑定源站声明的全部 Vary 请求头值，避免编码或语言变体串用。
func variantKey(base string, vary []string, h http.Header) string {
	fields := []string{base}
	for _, field := range vary {
		fields = append(fields, field, strings.Join(values(h, field), "\x00"))
	}
	return hashFields(fields...)
}

// freshUntil 以站点规则为最长 TTL，再结合源站新鲜度头和 Age/Date 求绝对到期时间。
// private/no-cache/no-store/Set-Cookie 始终拒绝共享缓存；s-maxage 优先于 max-age，源站不能放大规则上限。
func freshUntil(h http.Header, ttl int, now time.Time) (time.Time, bool) {
	if ttl <= 0 || present(h, "Set-Cookie") {
		return time.Time{}, false
	}
	deadline := now.Add(time.Duration(ttl) * time.Second)
	var maxAge, sharedAge *int64
	for _, line := range values(h, "Cache-Control") {
		for _, directive := range strings.Split(line, ",") {
			parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name == "private" || name == "no-cache" || name == "no-store" {
				return time.Time{}, false
			}
			if name != "max-age" && name != "s-maxage" {
				continue
			}
			if len(parts) != 2 {
				return time.Time{}, false
			}
			n, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(parts[1]), "\""), 10, 32)
			if err != nil || n <= 0 {
				return time.Time{}, false
			}
			if name == "s-maxage" {
				if sharedAge == nil || n < *sharedAge {
					sharedAge = &n
				}
			} else if maxAge == nil || n < *maxAge {
				maxAge = &n
			}
		}
	}
	for _, p := range values(h, "Pragma") {
		if strings.Contains(strings.ToLower(p), "no-cache") {
			return time.Time{}, false
		}
	}
	age := int64(0)
	for _, raw := range values(h, "Age") {
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
		if err != nil || n < 0 {
			return time.Time{}, false
		}
		if n > age {
			age = n
		}
	}
	if date, err := http.ParseTime(h.Get("Date")); err == nil {
		if apparent := int64(now.Sub(date) / time.Second); apparent > age {
			age = apparent
		}
	}
	if sharedAge != nil {
		maxAge = sharedAge
	}
	if maxAge != nil {
		d := now.Add(time.Duration(*maxAge-age) * time.Second)
		if d.Before(deadline) {
			deadline = d
		}
	} else if raw := h.Get("Expires"); raw != "" {
		d, err := http.ParseTime(raw)
		if err != nil {
			return time.Time{}, false
		}
		if d.Before(deadline) {
			deadline = d
		}
	}
	if raw := h.Get("X-Accel-Expires"); raw != "" {
		absolute := strings.HasPrefix(raw, "@")
		n, err := strconv.ParseInt(strings.TrimPrefix(raw, "@"), 10, 32)
		if err != nil || n <= 0 {
			return time.Time{}, false
		}
		d := now.Add(time.Duration(n) * time.Second)
		if absolute {
			d = time.Unix(n, 0)
		}
		if d.Before(deadline) {
			deadline = d
		}
	}
	return deadline, deadline.After(now)
}

// cacheHeaders 复制响应头后移除连接相关字段、逐跳扩展和保留诊断头。
// 副本与源站响应分离，后续写 Age/X-Cache 时不会修改共享缓存快照。
func cacheHeaders(src http.Header) http.Header {
	h := make(http.Header, len(src))
	for key, vs := range src {
		canonical := http.CanonicalHeaderKey(key)
		h[canonical] = append(h[canonical], vs...)
	}
	for _, line := range values(h, "Connection") {
		for _, name := range strings.Split(line, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Trailer", "Upgrade", "Proxy-Authenticate", "Proxy-Authorization", "X-Cache", "X-Cache-Layer", "X-Accel-Expires"} {
		h.Del(name)
	}
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-tier-") {
			h.Del(name)
		}
	}
	return h
}
