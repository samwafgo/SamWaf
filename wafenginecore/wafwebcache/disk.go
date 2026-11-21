package wafwebcache

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"SamWaf/utils/filelease"
	"github.com/shirou/gopsutil/v4/disk"
)

// L2 文件布局：8 字节版本标识 + 4 字节大端 JSON 长度 + 元数据 JSON + 原始正文。
// 新格式只在 v2 目录读取，不能将旧格式或 Nginx 的私有缓存文件视为本模块对象。
const diskMagic = "SWC2\r\n\x00\x01"

// maxMetadataSize 限制读取磁盘头时的分配，防止损坏长度字段造成大内存申请。
const maxMetadataSize = 64 * 1024

// metadata 保存响应表示及其绝对到期时间；晋升 L1 时整体沿用，不重新计算 TTL。
type metadata struct {
	Base     string      `json:"base"`
	Key      string      `json:"key"`
	Header   http.Header `json:"header"`
	Vary     []string    `json:"vary"`
	Size     int64       `json:"size"`     // 正文预期字节数，不包含文件头。
	Stored   int64       `json:"stored"`   // 写入时间，Unix 纳秒，用于计算响应年龄。
	Expires  int64       `json:"expires"`  // 绝对到期时间，Unix 纳秒，决定是否可以直接命中。
	Lifetime int64       `json:"lifetime"` // 写入时剩余有效秒数，仅记录，不用于晋升续期。
}

// headerSize 估算响应头的字节开销，供 L1 配额计量；磁盘大小使用实际 JSON 长度。
func (m metadata) headerSize() int {
	n := 0
	for k, vs := range m.Header {
		n += len(k)
		for _, v := range vs {
			n += len(v) + 4
		}
	}
	return n
}

// diskEntry 是进程内 L2 索引，bytes 包含完整文件大小，lastUsed 与内容到期独立。
type diskEntry struct {
	meta     metadata
	path     string
	bytes    int64
	lastUsed time.Time
}

// diskCache 在单站点目录内管理已提交文件和临时文件的空间预算。
// entries/byBase/计数由 mu 保护；修改磁盘时先拿跨进程文件租约，再拿 mu，保持统一锁顺序。
// 索引可按对象懒加载，loaded=false 时必须在下一次容量准入前重建完整索引。
type diskCache struct {
	mu          sync.Mutex
	root        string
	entries     map[string]*diskEntry
	byBase      map[string]map[string]*diskEntry
	used, temps int64  // 已提交文件字节与已预留临时文件字节，二者共同占用 L2 总配额。
	pending     int    // 尚未发布的填充数，用于限制并发准入。
	stamp       string // 本进程观察到的 generation，其他 Worker 发布后会改变它。
	loaded      bool   // 是否持有该 generation 下完整、可用于容量决策的索引。
	lastSweep   time.Time
	lastScan    time.Time
}

// newDiskCache 只建立索引容器，不立即扫描或创建目录，避免站点视图初始化触发大量 I/O。
func newDiskCache(root string) *diskCache {
	return &diskCache{root: root, entries: map[string]*diskEntry{}, byBase: map[string]map[string]*diskEntry{}}
}

// validDigest 校验文件元数据中的 SHA256 编码，阻止损坏内容被当作路径/索引身份使用。
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// readMetadata 有界读取文件头，并核对实际文件长度与正文声明长度。
// 返回正文偏移；保留文件句柄给调用者读取或再验证，不替调用者关闭。
func readMetadata(f *os.File) (metadata, int64, error) {
	var head [12]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return metadata{}, 0, err
	}
	if string(head[:8]) != diskMagic {
		return metadata{}, 0, errors.New("unsupported cache format")
	}
	n := binary.BigEndian.Uint32(head[8:])
	if n == 0 || n > maxMetadataSize {
		return metadata{}, 0, errors.New("invalid cache metadata length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(f, b); err != nil {
		return metadata{}, 0, err
	}
	var m metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return m, 0, err
	}
	if !validDigest(m.Base) || !validDigest(m.Key) || m.Header == nil || m.Size < 0 || m.Stored <= 0 || m.Expires <= m.Stored {
		return m, 0, errors.New("invalid cache metadata")
	}
	st, err := f.Stat()
	if err != nil {
		return m, 0, err
	}
	offset := int64(12 + n)
	if !st.Mode().IsRegular() || st.Size() != offset+m.Size {
		return m, 0, errors.New("incomplete cache object")
	}
	return m, offset, nil
}

// add 更新两个索引和已用字节数，同键替换先撤销旧计量；调用者持有 d.mu。
func (d *diskCache) add(e *diskEntry) {
	if old := d.entries[e.meta.Key]; old != nil {
		d.forget(old)
	}
	d.entries[e.meta.Key] = e
	if d.byBase[e.meta.Base] == nil {
		d.byBase[e.meta.Base] = map[string]*diskEntry{}
	}
	d.byBase[e.meta.Base][e.meta.Key] = e
	d.used += e.bytes
}

// forget 只撤销进程内索引，不删除文件；用于替换记录及读取到文件已不存在的情况。
// 调用者必须持有 d.mu，磁盘删除失败时不能用它假装空间已释放。
func (d *diskCache) forget(e *diskEntry) {
	delete(d.entries, e.meta.Key)
	delete(d.byBase[e.meta.Base], e.meta.Key)
	if len(d.byBase[e.meta.Base]) == 0 {
		delete(d.byBase, e.meta.Base)
	}
	d.used -= e.bytes
}

// remove 在物理删除成功或文件确实不存在后才释放配额，并失效本 Worker 的 L1 变体。
// Windows 读句柄可能阻止删除，失败时保留计量；调用者持有 d.mu。
func (d *diskCache) remove(e *diskEntry) bool {
	if err := os.Remove(e.path); err != nil && !os.IsNotExist(err) {
		return false
	}
	d.forget(e)
	processMemory.purge(e.meta.Base)
	return true
}

// stampValue 读取仅承载变更通知的 generation，不包含缓存键或正文。
func (d *diskCache) stampValue() string {
	b, _ := os.ReadFile(filepath.Join(d.root, ".generation"))
	return string(b)
}

// bump 在持有磁盘租约和 d.mu 时发布索引变化；它不是正文身份或内容新鲜度凭据。
func (d *diskCache) bump() {
	d.stamp = fmt.Sprintf("%d", time.Now().UnixNano())
	_ = os.WriteFile(filepath.Join(d.root, ".generation"), []byte(d.stamp), 0600)
}

// reload 重建完整索引和临时预留计量；generation 未变且索引完整时可以跳过扫描。
// 调用者持有 d.mu；容量准入/管理还持有磁盘租约，避免不同 Worker 同时据旧预算写入。
func (d *diskCache) reload() error {
	stamp := d.stampValue()
	if d.loaded && stamp == d.stamp {
		return nil
	}
	d.entries = map[string]*diskEntry{}
	d.byBase = map[string]map[string]*diskEntry{}
	d.used = 0
	d.temps = 0
	d.pending = 0
	err := filepath.WalkDir(d.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if strings.HasSuffix(path, ".tmp") {
			// 未提交文件也占预算；只清理长期无写入的遗留文件，正常填充不会被当成已提交对象。
			if time.Since(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			} else {
				d.temps += info.Size()
				d.pending++
			}
			return nil
		}
		if !strings.HasSuffix(path, ".cache") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		m, _, err := readMetadata(f)
		f.Close()
		if err != nil || filepath.Base(path) != m.Key+".cache" {
			_ = os.Remove(path)
			return nil
		}
		d.add(&diskEntry{meta: m, path: path, bytes: info.Size(), lastUsed: info.ModTime()})
		return nil
	})
	if os.IsNotExist(err) {
		err = nil
	}
	d.stamp = stamp
	d.loaded = err == nil
	d.lastScan = time.Now()
	return err
}

// withLease 统一封装跨进程租约 → 进程互斥锁 → 索引刷新 → 磁盘变更的顺序。
// 等待受 ctx 约束；fn 运行期间不能再次进入同一 diskCache 的加锁方法。
func (d *diskCache) withLease(ctx context.Context, fn func() error) error {
	lease, err := filelease.AcquireExclusive(ctx, filepath.Join(d.root, ".cache.lock"))
	if err != nil {
		return err
	}
	defer lease.Release()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.reload(); err != nil {
		return err
	}
	return fn()
}

// lookup 查找匹配 Vary 的文件，并把独立读句柄及正文偏移交给调用者关闭。
// 过期条目也可返回给条件再验证路径，不能由调用者直接当成新鲜 HIT。
func (d *diskCache) lookup(base string, h http.Header) (*diskEntry, *os.File, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.loaded || d.stampValue() != d.stamp {
		// 重启或其他 Worker 发布后，只在读路径加载当前基础键目录。
		// 此时索引仍标记为不完整，写入准入及后台管理会再进行全目录扫描。
		for _, e := range d.byBase[base] {
			d.forget(e)
		}
		dir := filepath.Join(d.root, base[:2], base)
		files, _ := os.ReadDir(dir)
		for _, entry := range files {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".cache") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			m, _, err := readMetadata(f)
			info, statErr := f.Stat()
			f.Close()
			if err == nil && statErr == nil && m.Base == base && entry.Name() == m.Key+".cache" {
				d.add(&diskEntry{meta: m, path: path, bytes: info.Size(), lastUsed: info.ModTime()})
			}
		}
		d.loaded = false
	}
	for _, e := range d.byBase[base] {
		if e.meta.Key != variantKey(base, e.meta.Vary, h) {
			continue
		}
		f, err := os.Open(e.path)
		if err != nil {
			d.forget(e)
			continue
		}
		m, off, err := readMetadata(f)
		if err != nil || m.Base != base || m.Key != e.meta.Key {
			f.Close()
			if err := os.Remove(e.path); err == nil || os.IsNotExist(err) {
				d.forget(e)
			}
			continue
		}
		now := time.Now()
		if now.Sub(e.lastUsed) > 10*time.Second {
			_ = os.Chtimes(e.path, now, now)
		}
		e.lastUsed = now
		copy := *e
		copy.meta = m
		return &copy, f, off
	}
	return nil, nil, 0
}

// trim 为 need 字节腾出空间，同时执行 inactive 和条目数限制；调用者持有 d.mu。
// replaceKey 允许已有对象原子替换时复用其索引名额，临时文件字节仍需真实预留。
func (d *diskCache) trim(s settings, need int64, replaceKey string) error {
	limit := s.MaxEntries
	if need > 0 {
		limit--
	}
	count := func() int {
		n := len(d.entries) + d.pending
		if replaceKey != "" && d.entries[replaceKey] != nil {
			n--
		}
		return n
	}
	entries := make([]*diskEntry, 0, len(d.entries))
	for _, e := range d.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].lastUsed.Before(entries[j].lastUsed) })
	for _, e := range entries {
		if d.used+d.temps+need <= s.L2Bytes && count() <= limit && time.Since(e.lastUsed) < s.Inactive {
			break
		}
		d.remove(e)
	}
	if d.used+d.temps+need > s.L2Bytes || count() > limit {
		return errors.New("L2 capacity exhausted")
	}
	return nil
}

// diskWrite 持有一次已计入配额的临时填充，只有 finish 才能发布为可读取对象。
// once 使 EOF、读取失败和 Close 的重复收尾不会重复扣减预留或重复重命名。
type diskWrite struct {
	store      *diskCache
	file       *os.File
	tmp, final string
	meta       metadata
	size       int64
	once       sync.Once
	committed  bool
}

// begin 校验完整文件上限与磁盘剩余空间，在租约内预留头部和正文的全部逻辑大小。
// 返回时正文尚未写入；调用者必须最终 finish，失败或未读完必须回滚。
func (d *diskCache) begin(ctx context.Context, m metadata, s settings) (*diskWrite, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > maxMetadataSize {
		return nil, errors.New("cache headers too large")
	}
	size := int64(12+len(b)) + m.Size
	if size > s.L2ObjectBytes || size > s.L2Bytes || m.Expires <= time.Now().UnixNano() {
		return nil, errors.New("cache object exceeds L2 limit")
	}
	var result *diskWrite
	err = d.withLease(ctx, func() error {
		if usage, err := disk.Usage(d.root); err != nil || usage.Free < uint64(size+s.MinFreeBytes) {
			return errors.New("insufficient free space for cache reservation")
		}
		if err := d.trim(s, size, m.Key); err != nil {
			return err
		}
		dir := filepath.Join(d.root, m.Base[:2], m.Base)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		f, err := os.CreateTemp(dir, "fill-*.tmp")
		if err != nil {
			return err
		}
		fail := func(err error) error { f.Close(); os.Remove(f.Name()); return err }
		// Truncate 让预留对其他 Worker 可见；文件仍为 .tmp，填零区域不能被作为正文命中。
		if err = f.Truncate(size); err != nil {
			return fail(err)
		}
		var head [12]byte
		copy(head[:8], diskMagic)
		binary.BigEndian.PutUint32(head[8:], uint32(len(b)))
		if _, err = f.Write(head[:]); err != nil {
			return fail(err)
		}
		if _, err = f.Write(b); err != nil {
			return fail(err)
		}
		d.temps += size
		d.pending++
		d.bump()
		result = &diskWrite{store: d, file: f, tmp: f.Name(), final: filepath.Join(dir, m.Key+".cache"), meta: m, size: size}
		return nil
	})
	return result, err
}

// finish 对成功的完整填充执行 Sync、关闭句柄和同目录原子替换，其他情况删除临时文件。
// commit=true 仅表达调用者已读完，最终还须检查 committed；到期或 I/O 失败仍会拒绝发布。
func (w *diskWrite) finish(commit bool) {
	w.once.Do(func() {
		if commit {
			if err := w.file.Sync(); err != nil {
				commit = false
			}
		}
		if err := w.file.Close(); err != nil {
			commit = false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := w.store.withLease(ctx, func() error {
			w.store.temps -= w.size
			w.store.pending--
			if w.store.pending < 0 {
				w.store.pending = 0
			}
			if w.store.temps < 0 {
				w.store.temps = 0
			}
			if commit && w.meta.Expires > time.Now().UnixNano() {
				if err := os.Rename(w.tmp, w.final); err != nil {
					os.Remove(w.tmp)
					w.store.bump()
					return err
				}
				w.store.add(&diskEntry{meta: w.meta, path: w.final, bytes: w.size, lastUsed: time.Now()})
				w.committed = true
			} else {
				_ = os.Remove(w.tmp)
			}
			w.store.bump()
			return nil
		})
		if err != nil {
			_ = os.Remove(w.tmp)
			// 租约超时等异常可能未执行扣减，强制下次重建，避免留下永久的「幽灵预留」。
			w.store.mu.Lock()
			w.store.loaded = false
			w.store.mu.Unlock()
		}
	})
}

// sectionBody 将文件的正文区间包装成响应体，并把文件句柄生命周期交给 Close。
type sectionBody struct {
	io.Reader
	file *os.File
}

// Close 释放 L2 读句柄；HEAD、客户端条件 304 和正常正文返回都必须走此路径。
func (b *sectionBody) Close() error { return b.file.Close() }

// fillBody 在代理消费源站正文时同步填充临时文件，不提前抽干整个响应。
// 只有热对象才保留有界 L1 缓冲；发布仍要求精确长度、正常 EOF 且请求未取消。
type fillBody struct {
	origin           io.ReadCloser
	write            *diskWrite
	settings         settings
	scope            string
	hot              bool
	n                int64
	buffer           bytes.Buffer
	failed, complete bool
	ctx              context.Context
}

// Read 透传源站数据和错误，同时记录实际字节数；缓存失败不阻止原响应继续返回。
// EOF 时先提交 L2，确认 committed 后才准入 L1，不能让不完整响应留下热副本。
func (b *fillBody) Read(p []byte) (int, error) {
	n, err := b.origin.Read(p)
	if n > 0 {
		b.n += int64(n)
		if b.n > b.write.meta.Size {
			b.failed = true
		}
		if !b.failed {
			if _, e := b.write.file.Write(p[:n]); e != nil {
				b.failed = true
			}
		}
		if b.hot && b.n <= b.settings.L1ObjectBytes {
			b.buffer.Write(p[:n])
		} else {
			b.hot = false
			b.buffer.Reset()
		}
	}
	if err != nil {
		b.complete = err == io.EOF && b.n == b.write.meta.Size && !b.failed && b.ctx.Err() == nil
		b.write.finish(b.complete)
		if b.write.committed && b.hot {
			processMemory.put(b.scope, b.settings.L1Bytes, b.write.meta, b.buffer.Bytes())
		}
		b.hot = false
	}
	return n, err
}

// Close 回滚未完成填充并关闭源站响应体，覆盖客户端提前断开和代理取消等退出路径。
func (b *fillBody) Close() error { b.write.finish(b.complete); return b.origin.Close() }

// purge 在有界租约等待内移除基础键的 L2 变体，并始终撤销本 Worker 的 L1 副本。
func (d *diskCache) purge(ctx context.Context, base string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = d.withLease(ctx, func() error {
		for _, e := range d.byBase[base] {
			d.remove(e)
		}
		d.bump()
		return nil
	})
	processMemory.purge(base)
}

// maintain 执行容量/inactive 回收；有遗留预留时定期完整扫描，回收死 Writer 的临时文件。
// 内容 TTL 过期不等于立即删文件，保留的正文仍可用于后续真实源站条件再验证。
func (d *diskCache) maintain(s settings) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = d.withLease(ctx, func() error {
		if d.temps > 0 && time.Since(d.lastScan) > time.Minute {
			d.loaded = false
			if err := d.reload(); err != nil {
				return err
			}
		}
		_ = d.trim(s, 0, "")
		d.bump()
		d.lastSweep = time.Now()
		return nil
	})
}
