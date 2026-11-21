// Package wafwebcache 提供独立的 L1 热缓存和 L2 磁盘响应缓存。
// 网页正文不进入控制台 CacheStore，避免正文容量淘汰影响令牌、封禁和防重放状态。
package wafwebcache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils/filelease"
)

// viewKey 使用不可变 HostSafe 快照身份和站点配置复用解析结果；热更新会发布新的快照。
type viewKey struct {
	host       *wafenginmodel.HostSafe
	globalHost *wafenginmodel.HostSafe
	config     model.CacheConfig
}

// cacheView 固定一次请求所用的配置指纹和预算；used 仅用于注册表回收，不是内容 TTL。
type cacheView struct {
	disk            *diskCache
	settings        settings
	revision, scope string
	used            time.Time
}

// registry 的锁只保护视图/存储注册关系；后台管理先复制列表再释放锁，不能持锁执行磁盘 I/O。
// 视图有数量及空闲时间上限，回收视图不删除持久 L2 文件。
var registry = struct {
	sync.Mutex
	views   map[viewKey]*cacheView
	stores  map[string]*diskCache
	started bool
}{views: map[viewKey]*cacheView{}, stores: map[string]*diskCache{}}

// heat 只影响本 Worker 的选层，正文身份和授权始终使用独立校验。
var heat heatCounter

// 原子计数按实际服务来源/回源尝试记录；originReads 包含条件再验证，绕过请求另计。
var l1Hits, l2Hits, originReads, bypasses, revalidations atomic.Uint64

// viewFor 复用只读策略视图，并让同一站点不同配置版本共用 L2 容量管理器。
// 内容键包含 revision，使旧文件可以留待回收，但不能被新配置继续命中。
func viewFor(host *wafenginmodel.HostSafe, cfg model.CacheConfig, globalHost ...*wafenginmodel.HostSafe) *cacheView {
	var shared *wafenginmodel.HostSafe
	if len(globalHost) > 0 {
		shared = globalHost[0]
	}
	key := viewKey{host: host, globalHost: shared, config: cfg}
	registry.Lock()
	defer registry.Unlock()
	if v := registry.views[key]; v != nil {
		v.used = time.Now()
		return v
	}
	s := normalize(cfg)
	root, _ := filepath.Abs(filepath.Join(s.Dir, "v2", hashFields(host.Host.Code)))
	d := registry.stores[root]
	if d == nil {
		d = newDiskCache(root)
		registry.stores[root] = d
	}
	v := &cacheView{disk: d, settings: s, revision: policyRevision(host, cfg, shared), scope: root, used: time.Now()}
	if len(registry.views) >= 256 {
		var oldest viewKey
		var when time.Time
		for k, x := range registry.views {
			if when.IsZero() || x.used.Before(when) {
				oldest, when = k, x.used
			}
		}
		delete(registry.views, oldest)
	}
	registry.views[key] = v
	if !registry.started {
		registry.started = true
		go maintainCaches()
	}
	return v
}

// maintainCaches 定期淘汰空闲视图并管理活跃 L2，不在注册表锁内等待磁盘租约。
func maintainCaches() {
	for range time.NewTicker(10 * time.Second).C {
		registry.Lock()
		active := map[*diskCache]settings{}
		for k, v := range registry.views {
			if time.Since(v.used) > time.Hour {
				delete(registry.views, k)
			} else {
				active[v.disk] = v.settings
			}
		}
		for root, d := range registry.stores {
			if _, ok := active[d]; !ok {
				delete(registry.stores, root)
			}
		}
		registry.Unlock()
		for d, s := range active {
			d.maintain(s)
		}
	}
}

// requestStateKey 是包私有 Context 键，避免和应用的字符串 Context 键发生碰撞。
type requestStateKey struct{}

// requestState 随一次代理请求传递，串联查找、填充锁、源站条件请求和响应提交。
// 代理复制 Request 时必须保留 Context，否则响应阶段无法识别其填充/再验证状态。
type requestState struct {
	view          *cacheView
	base          string
	ttl           int
	hot           bool
	lease         *filelease.Lease
	stale         *diskEntry
	staleFile     *os.File
	staleOffset   int64
	validating    bool        // 已注入缓存自身的校验器，不能把客户端自己的 304 冒当作验证成功。
	bypassed      bool        // 请求准入或填充锁等待失败，响应仅允许返回 BYPASS 诊断。
	revalidated   bool        // 供延迟执行的 PrepareResponse 保留 REVALIDATED，不能重新覆盖成 MISS。
	clientHeaders http.Header // 注入源站校验器前的客户端头，用于 Vary 身份和客户端条件响应。
}

// stateFor 从代理请求上下文取回本次缓存状态；非缓存请求返回 nil。
func stateFor(r *http.Request) *requestState {
	if r == nil {
		return nil
	}
	s, _ := r.Context().Value(requestStateKey{}).(*requestState)
	return s
}

// FinishRequest 在代理消费完响应体之后统一释放填充租约和旧正文句柄。
// ServeHTTP 必须 defer 它以覆盖错误和取消；取消等待 Context 不会自动释放已经获得的文件租约。
func FinishRequest(r *http.Request) {
	if s := stateFor(r); s != nil {
		if s.lease != nil {
			s.lease.Release()
		}
		if s.staleFile != nil {
			s.staleFile.Close()
		}
	}
}

// responseFor 从只读元数据构造独立响应头，并叠加源站年龄和缓存驻留时间。
// HEAD/客户端条件 304 立即关闭正文句柄，只有普通 GET 把正文所有权交给响应消费者。
func responseFor(m metadata, body io.ReadCloser, r *http.Request, h http.Header, status, layer string) *http.Response {
	headers := m.Header.Clone()
	headers.Set("Content-Length", strconv.FormatInt(m.Size, 10))
	age := int64(time.Since(time.Unix(0, m.Stored)) / time.Second)
	if original, err := strconv.ParseInt(headers.Get("Age"), 10, 64); err == nil && original > 0 {
		age += original
	}
	if age < 0 {
		age = 0
	}
	headers.Set("Age", strconv.FormatInt(age, 10))
	headers.Set("X-Cache", status)
	headers.Set("X-Cache-Layer", layer)
	resp := &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: headers, Body: body, ContentLength: m.Size, Request: r}
	if notModified(headers, h) {
		body.Close()
		resp.Body = http.NoBody
		resp.StatusCode = 304
		resp.Status = "304 Not Modified"
		resp.ContentLength = 0
		resp.Header.Del("Content-Length")
	} else if r.Method == http.MethodHead {
		body.Close()
		resp.Body = http.NoBody
	}
	return resp
}

// notModified 对新鲜的 GET/HEAD 表示检查客户端条件；If-None-Match 优先于日期条件。
// 它不执行源站再验证，只决定本次可以返回 304 还是必须返回已选定的正文。
func notModified(response, request http.Header) bool {
	if present(request, "If-None-Match") {
		etag := strings.TrimPrefix(strings.TrimSpace(response.Get("ETag")), "W/")
		for _, line := range values(request, "If-None-Match") {
			for _, tag := range strings.Split(line, ",") {
				tag = strings.TrimSpace(tag)
				if tag == "*" || etag != "" && strings.TrimPrefix(tag, "W/") == etag {
					return true
				}
			}
		}
		return false
	}
	if since, err := http.ParseTime(request.Get("If-Modified-Since")); err == nil {
		if last, err := http.ParseTime(response.Get("Last-Modified")); err == nil && !last.After(since) {
			return true
		}
	}
	return false
}

// lookup 按热度先查 L1 或直接查 L2；只有 L2 新鲜命中才可晋升，且沿用原绝对到期。
// 过期命中返回旧记录和句柄给调用者再验证，未命中/损坏不会返回可服务的响应。
func lookup(s *requestState, r *http.Request) (*http.Response, *diskEntry, *os.File, int64) {
	if s.hot {
		if m, b, ok := processMemory.get(s.base, r.Header, time.Now()); ok {
			l1Hits.Add(1)
			return responseFor(m, io.NopCloser(bytes.NewReader(b)), r, s.clientHeaders, "HIT", "l1"), nil, nil, 0
		}
	}
	e, f, offset := s.view.disk.lookup(s.base, r.Header)
	if e == nil {
		return nil, nil, nil, 0
	}
	if e.meta.Expires <= time.Now().UnixNano() {
		return nil, e, f, offset
	}
	body := io.ReadCloser(&sectionBody{Reader: io.NewSectionReader(f, offset, e.meta.Size), file: f})
	if s.hot && fitsL1(e.meta, s.view.settings) {
		data, err := io.ReadAll(io.LimitReader(body, s.view.settings.L1ObjectBytes+1))
		body.Close()
		if err != nil || int64(len(data)) != e.meta.Size {
			return nil, nil, nil, 0
		}
		processMemory.put(s.view.scope, s.view.settings.L1Bytes, e.meta, data)
		body = io.NopCloser(bytes.NewReader(data))
	}
	l2Hits.Add(1)
	return responseFor(e.meta, body, r, s.clientHeaders, "HIT", "l2"), nil, nil, 0
}

// LoadWebDataFormCache 保留旧入口签名，每个请求调用一次，仅准入公共、无正文 GET/HEAD。
// 未命中时把策略和填充所有权留在 Context，响应阶段据此提交；调用者最终必须执行 FinishRequest。
// w 保留兼容参数，诊断头统一在响应阶段生成，避免代理复制响应头时出现重复字段。
func LoadWebDataFormCache(w http.ResponseWriter, r *http.Request, host *wafenginmodel.HostSafe, cfg model.CacheConfig, _ *innerbean.WebLog, globalHost ...*wafenginmodel.HostSafe) *http.Response {
	if cfg.IsEnableCache != 1 {
		return nil
	}
	*r = *r.WithContext(context.WithValue(r.Context(), requestStateKey{}, &requestState{bypassed: true}))
	location := strings.ToLower(strings.TrimSpace(cfg.CacheLocation))
	if location != "" && location != "tiered" && location != "memory" && location != "file" && location != "all" {
		bypasses.Add(1)
		return nil
	}
	if !requestCacheable(r) || host.Host.IsEnableHttpAuthBase == 1 || host.Host.IsEnableResponseBuffering == 0 {
		bypasses.Add(1)
		return nil
	}
	ttl, err := checkCacheRule(host, cfg, r)
	if err != nil {
		bypasses.Add(1)
		return nil
	}
	v := viewFor(host, cfg, globalHost...)
	base := baseKey(r, v.revision)
	s := &requestState{view: v, base: base, ttl: ttl, hot: heat.hit(base, v.settings.HeatHits, v.settings.HeatWindow, time.Now()), clientHeaders: r.Header.Clone()}
	*r = *r.WithContext(context.WithValue(r.Context(), requestStateKey{}, s))
	if resp, _, f, _ := lookup(s, r); resp != nil {
		return resp
	} else if f != nil {
		f.Close()
	}
	if r.Method == http.MethodHead {
		s.bypassed = true
		bypasses.Add(1)
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), v.settings.LockTimeout)
	// 使用 4096 个有界跨进程锁槽；碰撞只让不同对象的填充串行，不影响正文键的隔离。
	lease, err := filelease.AcquireExclusive(ctx, filepath.Join(v.disk.root, ".locks", base[:3]+".lock"))
	cancel()
	if err != nil {
		s.bypassed = true
		bypasses.Add(1)
		return nil
	}
	s.lease = lease
	// 等待期间其他 Writer 可能已经提交，拿到填充所有权后必须再次查缓存。
	resp, stale, f, offset := lookup(s, r)
	if resp != nil {
		lease.Release()
		return resp
	}
	s.stale, s.staleFile, s.staleOffset = stale, f, offset
	if stale != nil {
		// 向真实源站发送旧对象自己的校验器，原客户端条件保存在 clientHeaders 中。
		if etag := stale.meta.Header.Get("ETag"); etag != "" {
			s.validating = true
			r.Header.Set("If-None-Match", etag)
			r.Header.Del("If-Modified-Since")
		} else if modified := stale.meta.Header.Get("Last-Modified"); modified != "" {
			s.validating = true
			r.Header.Set("If-Modified-Since", modified)
			r.Header.Del("If-None-Match")
		}
	}
	originReads.Add(1)
	return nil
}

// metadataFor 保存经过准入的响应头、Vary 身份和绝对到期，拒绝无法隔离的 Vary 声明。
// 源站 Date 推导出的实际年龄也写入 Age，不能在 L2/L1 命中后向下游伪装成新对象。
func metadataFor(resp *http.Response, s *requestState, expires time.Time) (metadata, bool) {
	vary, ok := varyFields(resp.Header)
	if !ok {
		return metadata{}, false
	}
	now := time.Now()
	m := metadata{Base: s.base, Header: cacheHeaders(resp.Header), Vary: vary, Size: resp.ContentLength, Stored: now.UnixNano(), Expires: expires.UnixNano(), Lifetime: int64(expires.Sub(now) / time.Second)}
	age := int64(0)
	if a, err := strconv.ParseInt(m.Header.Get("Age"), 10, 64); err == nil && a > age {
		age = a
	}
	if date, err := http.ParseTime(m.Header.Get("Date")); err == nil {
		if apparent := int64(now.Sub(date) / time.Second); apparent > age {
			age = apparent
		}
	}
	m.Header.Set("Age", strconv.FormatInt(age, 10))
	m.Key = variantKey(s.base, vary, s.clientHeaders)
	return m, true
}

// PrepareResponse 清除源站提供的保留诊断头，再根据可信请求状态生成唯一的缓存来源标识。
// 响应处理入口使用 defer：它最后执行，必须通过 revalidated 保留再验证路径生成的状态。
func PrepareResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	s := stateFor(resp.Request)
	if s == nil {
		return
	}
	for name := range resp.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-tier-") || strings.EqualFold(name, "X-Cache") || strings.EqualFold(name, "X-Cache-Layer") {
			delete(resp.Header, name)
		}
	}
	if s.revalidated {
		resp.Header.Set("X-Cache", "REVALIDATED")
		resp.Header.Set("X-Cache-Layer", "l2")
	} else if s.bypassed || s.lease == nil {
		resp.Header.Set("X-Cache", "BYPASS")
		resp.Header.Set("X-Cache-Layer", "off")
	} else {
		resp.Header.Set("X-Cache", "MISS")
		resp.Header.Set("X-Cache-Layer", "origin")
	}
}

// StoreWebDataCache 对获得填充所有权的响应安装流式 Writer，不进行全量 DumpResponse。
// 仅完整、已知长度的公共 200 可以入库；304 只能验证本请求注入过的旧对象校验器。
func StoreWebDataCache(resp *http.Response, _ *wafenginmodel.HostSafe, _ model.CacheConfig, _ *innerbean.WebLog) {
	PrepareResponse(resp)
	s := stateFor(resp.Request)
	if s == nil || s.lease == nil {
		return
	}
	resp.Header.Set("X-Cache", "MISS")
	resp.Header.Set("X-Cache-Layer", "origin")
	if resp.StatusCode == http.StatusNotModified && s.validating && s.stale != nil && s.staleFile != nil {
		revalidate(resp, s)
		return
	}
	if s.staleFile != nil {
		// 源站已返回新表示，旧句柄不再需要；先关闭，避免 Windows 阻止后续原子替换。
		s.staleFile.Close()
		s.staleFile = nil
	}
	if resp.StatusCode != http.StatusOK || resp.Body == nil || resp.Body == http.NoBody || resp.ContentLength < 0 || present(resp.Header, "Content-Range") {
		return
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") || strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/stream+json") {
		return
	}
	expires, ok := freshUntil(resp.Header, s.ttl, time.Now())
	if !ok {
		s.view.disk.purge(resp.Request.Context(), s.base)
		return
	}
	m, ok := metadataFor(resp, s, expires)
	if !ok {
		s.view.disk.purge(resp.Request.Context(), s.base)
		return
	}
	ctx, cancel := context.WithTimeout(resp.Request.Context(), s.view.settings.LockTimeout)
	defer cancel()
	writer, err := s.view.disk.begin(ctx, m, s.view.settings)
	if err != nil {
		// 缓存空间/磁盘失败只取消填充，不能吞掉原本可正常返回的源站响应。
		return
	}
	resp.Body = &fillBody{origin: resp.Body, write: writer, settings: s.view.settings, scope: s.view.scope, hot: s.hot && fitsL1(m, s.view.settings), ctx: resp.Request.Context()}
}

// revalidate 将真实源站的 304 与已验证旧正文合并，按新策略决定是否续期。
// 新增私有策略时允许完成本次已确认的表示，但关闭正文后失效旧缓存，不再供后续共享读取。
func revalidate(resp *http.Response, s *requestState) {
	old := s.stale.meta
	merged := old.Header.Clone()
	for key, vs := range resp.Header {
		if !strings.EqualFold(key, "Content-Length") {
			merged[http.CanonicalHeaderKey(key)] = append([]string(nil), vs...)
		}
	}
	// 304 未携带新鲜度字段时，不能把旧的绝对 Expires/Age 再解释为新响应的期限。
	if !present(resp.Header, "Date") {
		merged.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}
	if !present(resp.Header, "Age") {
		merged.Del("Age")
	}
	if !present(resp.Header, "Expires") {
		merged.Del("Expires")
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	copyResp := *resp
	copyResp.Header = merged
	copyResp.ContentLength = old.Size
	expires, cacheable := freshUntil(merged, s.ttl, time.Now())
	resultFile, resultOffset := s.staleFile, s.staleOffset
	if cacheable {
		m, ok := metadataFor(&copyResp, s, expires)
		if !ok {
			cacheable = false
		}
		if ok {
			ctx, cancel := context.WithTimeout(resp.Request.Context(), s.view.settings.LockTimeout)
			writer, err := s.view.disk.begin(ctx, m, s.view.settings)
			cancel()
			if err == nil {
				var hot bytes.Buffer
				var dst io.Writer = writer.file
				if s.hot && fitsL1(m, s.view.settings) {
					dst = io.MultiWriter(dst, &hot)
				}
				n, err := io.Copy(dst, io.NewSectionReader(s.staleFile, s.staleOffset, old.Size))
				if err == nil && n == old.Size {
					// Windows 不允许替换仍被读取的文件；流式复制完成后关闭旧句柄，提交后再打开。
					s.staleFile.Close()
					s.staleFile = nil
					resultFile = nil
				}
				writer.finish(err == nil && n == old.Size)
				if writer.committed && int64(hot.Len()) == old.Size {
					processMemory.put(s.view.scope, s.view.settings.L1Bytes, m, hot.Bytes())
				}
				if resultFile == nil {
					if f, err := os.Open(s.stale.path); err == nil {
						if _, off, err := readMetadata(f); err == nil {
							resultFile, resultOffset = f, off
						} else {
							f.Close()
						}
					}
				}
			}
		}
	}
	if resultFile == nil {
		// 无法取得已验证正文时明确报网关错误，不能返回一个没有对应正文的伪成功 200。
		resp.StatusCode = 502
		resp.Status = "502 Bad Gateway"
		resp.Header = make(http.Header)
		resp.Body = io.NopCloser(strings.NewReader("cached representation unavailable during revalidation"))
		resp.ContentLength = -1
		return
	}
	old.Header = merged
	old.Stored = time.Now().UnixNano()
	var body io.ReadCloser = &sectionBody{Reader: io.NewSectionReader(resultFile, resultOffset, old.Size), file: resultFile}
	if !cacheable {
		processMemory.purge(s.base)
		body = &afterCloseBody{ReadCloser: body, after: func() { s.view.disk.purge(context.Background(), s.base) }}
	}
	replacement := responseFor(old, body, resp.Request, s.clientHeaders, "REVALIDATED", "l2")
	*resp = *replacement
	s.revalidated = true
	revalidations.Add(1)
}

// afterCloseBody 把清理延后到文件读句柄关闭之后，避免私有化的 304 在 Windows 下删除失败。
type afterCloseBody struct {
	io.ReadCloser
	once  sync.Once
	after func()
}

// Close 先释放底层正文，再至多执行一次失效回调。
func (b *afterCloseBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.after); return err }

// Snapshot 返回来源计数和当前 Worker 已加载索引的容量，不扫描磁盘，不输出键、URL 或正文。
// L2 在重启懒加载阶段可能尚未建立完整索引，因此该计量不能当作文件系统总使用量。
func Snapshot() map[string]int64 {
	used, entries := processMemory.usage()
	result := map[string]int64{"l1_hits": int64(l1Hits.Load()), "l2_hits": int64(l2Hits.Load()), "origin_reads": int64(originReads.Load()), "bypasses": int64(bypasses.Load()), "revalidated": int64(revalidations.Load()), "l1_bytes": used, "l1_entries": int64(entries)}
	registry.Lock()
	stores := make([]*diskCache, 0, len(registry.stores))
	for _, d := range registry.stores {
		stores = append(stores, d)
	}
	registry.Unlock()
	for _, d := range stores {
		d.mu.Lock()
		result["l2_bytes"] += d.used
		result["l2_reserved_bytes"] += d.temps
		result["l2_entries"] += int64(len(d.entries))
		d.mu.Unlock()
	}
	return result
}

// CleanExpiredCache 兼容清理旧的「键.到期秒数.cache」文件，再触发新 L2 的容量/inactive 管理。
// 不把旧格式作为 v2 正文读取，也不简单删除所有 v2 过期正文，以保留条件再验证所需的副本。
func CleanExpiredCache(dir string) {
	if dir == "" {
		return
	}
	_ = filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(path, ".cache") {
			return nil
		}
		parts := strings.Split(filepath.Base(path), ".")
		if len(parts) >= 3 {
			if expiry, err := strconv.ParseInt(parts[len(parts)-2], 10, 64); err == nil && expiry <= time.Now().Unix() {
				_ = os.Remove(path)
			}
		}
		return nil
	})
	registry.Lock()
	active := map[*diskCache]settings{}
	for _, v := range registry.views {
		active[v.disk] = v.settings
	}
	registry.Unlock()
	for d, s := range active {
		d.maintain(s)
	}
}
