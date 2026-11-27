//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"SamWaf/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// 两种字节序的对象随应用发布；生成入口为 bpf/generate.sh，无运行时 C 编译依赖。
//
//go:embed bpf/input_bpfel.o
var inputBPFLE []byte

//go:embed bpf/input_bpfeb.o
var inputBPFBE []byte

const bpfMaxGroups = 64
const bpfMaxRules = 262144
const bpfMaxTotalRules = 1048576

// bpfRuleKey 与 input.c 保持布局一致。地址族/端口固定占 64 位前缀，防止跨协议族匹配。
type bpfRuleKey struct {
	Prefix   uint32
	Family   uint32
	Port     [2]byte
	Reserved uint16
	Address  [16]byte
}

// bpfRuleValue 的期限为当前启动周期内的 BOOTTIME 纳秒，0 表示永久。
type bpfRuleValue struct {
	Expires  uint64
	Prefix   uint32
	Reserved uint32
}

// bpfGroup 按来源保存目标地址及 Unix 秒期限；端口为空表示所有入站协议。
// 不同来源独立成表，删除一个订阅不能撤销其他来源仍有效的封禁。
type bpfGroup struct {
	Slot      uint32            `json:"slot"`
	Ports     []int             `json:"ports,omitempty"`
	Entries   map[string]int64  `json:"entries"`
	Deadlines map[string]uint64 `json:"boot_deadlines,omitempty"` // 同一启动周期内重建不会因墙上时钟跳变而续期。
}

// bpfState 是可重放的控制账本；内核表和链接只保存在本实例的 bpffs 子目录中。
type bpfState struct {
	Version int                  `json:"version"`
	BootID  string               `json:"boot_id"`
	Groups  map[string]*bpfGroup `json:"groups"`
}

// bpfBackend 持有本实例/网络命名空间的内核对象。mu 加文件锁共同串行化多 Worker 控制操作。
type bpfBackend struct {
	mu                    sync.Mutex
	dir, pins             string
	collection            *ebpf.Collection
	groups, active, drops *ebpf.Map
}

// 后端按网络命名空间与实例目录分开缓存，测试/容器/多实例不会相互覆盖。
var bpfBackends = struct {
	sync.Mutex
	items map[string]*bpfBackend
}{items: map[string]*bpfBackend{}}

// bpfPaths 将可持久化账本与只能存放 BPF 对象的 bpffs 目录分开。
func bpfPaths() (string, string, error) {
	dir := os.Getenv("SAMWAF_BPF_STATE_DIR")
	if dir == "" {
		dir = filepath.Join(utils.GetCurrentDir(), "data", "ebpf")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(dir + "\x00" + ns))
	root := os.Getenv("SAMWAF_BPF_PIN_ROOT")
	if root == "" {
		root = "/sys/fs/bpf/samwaf"
	}
	return dir, filepath.Join(root, hex.EncodeToString(sum[:12])), nil
}

// bpfLock 使用进程间 flock，不依赖可被请求流量续期的 TTL 租约；等待有明确上限。
func bpfLock(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("invalid eBPF state directory")
	}
	fd, err := unix.Open(filepath.Join(dir, "control.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "eBPF control lock")
	deadline := time.Now().Add(30 * time.Second)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("eBPF control lock: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// bpfUnlock 关闭文件描述符同时释放 flock，异常进程退出也不会留下永久锁。
func bpfUnlock(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }

// getBPFBackend 首次载入内核程序和两条 LOCAL_IN 链接；不接管已有 XDP/TC 或其他防火墙。
func getBPFBackend() (*bpfBackend, error) {
	dir, pins, err := bpfPaths()
	if err != nil {
		return nil, err
	}
	bpfBackends.Lock()
	defer bpfBackends.Unlock()
	if b := bpfBackends.items[pins]; b != nil {
		return b, nil
	}
	lock, err := bpfLock(dir)
	if err != nil {
		return nil, err
	}
	defer bpfUnlock(lock)
	if err = os.MkdirAll(pins, 0700); err != nil {
		return nil, fmt.Errorf("eBPF bpffs directory: %w", err)
	}
	var stat unix.Statfs_t
	if err = unix.Statfs(pins, &stat); err != nil || uint64(stat.Type) != uint64(unix.BPF_FS_MAGIC) {
		return nil, errors.New("eBPF requires mounted bpffs; mount /sys/fs/bpf before starting the service")
	}
	object := inputBPFLE
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		object = inputBPFBE
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, err
	}
	// ELF 中槽 0 的初始化只表达内层模板；重开共享外层表时不能用空模板覆盖有效名单。
	spec.Maps["ban_groups"].Contents = nil
	replacements := map[string]*ebpf.Map{}
	defer func() {
		for _, m := range replacements {
			m.Close()
		}
	}()
	for _, name := range []string{"ban_groups", "active_groups", "drop_count"} {
		m, e := ebpf.LoadPinnedMap(filepath.Join(pins, name), nil)
		if e == nil {
			replacements[name] = m
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		return nil, fmt.Errorf("eBPF load (Linux 6.6+, BTF, CAP_BPF and CAP_NET_ADMIN required): %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			coll.Close()
		}
	}()
	for _, name := range []string{"ban_groups", "active_groups", "drop_count"} {
		if replacements[name] == nil {
			if err = coll.Maps[name].Pin(filepath.Join(pins, name)); err != nil {
				return nil, err
			}
		}
	}
	program := coll.Programs["samwaf_input"]
	info, err := program.Info()
	if err != nil {
		return nil, err
	}
	// 只重开本实例显式 pin 的程序；按全局 Program ID 枚举会额外要求 CAP_SYS_ADMIN。
	programPath := filepath.Join(pins, "program_input")
	pinned, err := ebpf.LoadPinnedProgram(programPath, nil)
	var ownedID ebpf.ProgramID
	attachProgram := program
	if err == nil {
		attachProgram = pinned
		defer pinned.Close()
		previous, err := pinned.Info()
		if err != nil {
			return nil, err
		}
		if previous.Tag != info.Tag {
			return nil, errors.New("existing SamWAF eBPF program differs; perform a controlled dataplane upgrade")
		}
		ownedID, _ = previous.ID()
	} else if errors.Is(err, os.ErrNotExist) {
		if err = program.Pin(programPath); err != nil {
			return nil, err
		}
		ownedID, _ = info.ID()
	} else {
		return nil, err
	}
	var created []link.Link
	defer func() {
		if !ok {
			for _, l := range created {
				_ = l.Unpin()
				_ = l.Close()
			}
		}
	}()
	for _, family := range []uint32{unix.AF_INET, unix.AF_INET6} {
		path := filepath.Join(pins, fmt.Sprintf("input%d", family))
		l, e := link.LoadPinnedLink(path, nil)
		if e == nil {
			li, e := l.Info()
			if e != nil {
				l.Close()
				return nil, e
			}
			l.Close()
			nf := li.Netfilter()
			if ownedID == 0 || li.Program != ownedID || nf == nil || nf.Pf != family || nf.Hooknum != 1 || nf.Priority != -75 || nf.Flags&1 == 0 {
				return nil, errors.New("SamWAF eBPF link/program ownership mismatch; perform a controlled dataplane recovery")
			}
			continue
		}
		if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		// UAPI 的 DEFRAG 位是 1；显式开启重组，确保端口规则正确处理 IP 分片。
		l, e = link.AttachNetfilter(link.NetfilterOptions{Program: attachProgram, ProtocolFamily: family, HookNumber: 1, Priority: -75, NetfilterFlags: link.NetfilterAttachFlags(1)})
		if e != nil {
			return nil, fmt.Errorf("attach eBPF LOCAL_IN family %d: %w", family, e)
		}
		if e = l.Pin(path); e != nil {
			l.Close()
			return nil, e
		}
		created = append(created, l)
	}
	b := &bpfBackend{dir: dir, pins: pins, collection: coll, groups: coll.Maps["ban_groups"], active: coll.Maps["active_groups"], drops: coll.Maps["drop_count"]}
	state, err := b.readState("state.json")
	if err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	// 内核对象不跨重启保存，按绝对期限恢复账本，不把旧 BOOTTIME 数值带到新启动周期。
	if state.BootID != strings.TrimSpace(string(boot)) || len(replacements) != 3 {
		if state.BootID != strings.TrimSpace(string(boot)) {
			for _, g := range state.Groups {
				g.Deadlines = nil
			}
		}
		state.BootID = strings.TrimSpace(string(boot))
		if err = b.publishAll(state); err != nil {
			return nil, err
		}
		if err = b.writeState("state.json", state); err != nil {
			return nil, err
		}
	}
	if err = b.recoverPending(); err != nil {
		return nil, err
	}
	for _, l := range created {
		l.Close()
	}
	ok = true
	bpfBackends.items[pins] = b
	return b, nil
}

// readState 拒绝损坏的账本，不能把解析失败当作空名单覆盖内核。
func (b *bpfBackend) readState(name string) (*bpfState, error) {
	s := &bpfState{Version: 1, Groups: map[string]*bpfGroup{}}
	data, err := os.ReadFile(filepath.Join(b.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		if name != "state.json" {
			return nil, err
		}
		if b.active != nil {
			var mask uint64
			if err := b.active.Lookup(uint32(0), &mask); err != nil {
				return nil, err
			}
			if mask != 0 {
				return nil, errors.New("eBPF ledger missing while kernel bans are active; restore the verified state backup")
			}
		}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	if s.Version != 1 || s.Groups == nil || len(s.Groups) > bpfMaxGroups {
		return nil, errors.New("invalid eBPF state schema")
	}
	seen := map[uint32]bool{}
	for name, g := range s.Groups {
		if validateSetName(name) != nil || g == nil || g.Slot >= bpfMaxGroups || seen[g.Slot] || g.Entries == nil {
			return nil, errors.New("invalid eBPF group ledger")
		}
		seen[g.Slot] = true
	}
	return s, nil
}

// writeState 先完整落盘并同步，再同目录替换；账本包含来源 IP，文件权限固定为 0600。
func (b *bpfBackend) writeState(name string, s *bpfState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(b.dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	if err = os.Rename(f.Name(), filepath.Join(b.dir, name)); err != nil {
		return err
	}
	d, err := os.Open(b.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// recoverPending 重放已经持久化但尚未完成的操作，恢复后才允许下一次控制变更。
func (b *bpfBackend) recoverPending() error {
	if _, err := os.Stat(filepath.Join(b.dir, "pending.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	s, err := b.readState("pending.json")
	if err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if s.BootID != strings.TrimSpace(string(boot)) {
		s.BootID = strings.TrimSpace(string(boot))
		for _, g := range s.Groups {
			g.Deadlines = nil
		}
	}
	if err = b.publishAll(s); err != nil {
		return err
	}
	if err = b.writeState("state.json", s); err != nil {
		return err
	}
	return os.Remove(filepath.Join(b.dir, "pending.json"))
}

// makeRuleKey 统一规范化 IPv4/IPv6/CIDR，拒绝全地址空间封禁及带 zone 的地址。
func makeRuleKey(raw string, port int) (bpfRuleKey, string, error) {
	var key bpfRuleKey
	raw = strings.TrimSpace(raw)
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		a, e := netip.ParseAddr(raw)
		if e != nil || a.Zone() != "" {
			return key, "", fmt.Errorf("invalid ban IP %q", raw)
		}
		a = a.Unmap()
		prefix = netip.PrefixFrom(a, a.BitLen())
	}
	if prefix.Addr().Is4In6() {
		return key, "", errors.New("use canonical IPv4 prefixes instead of mapped IPv6")
	}
	prefix = prefix.Masked()
	if prefix.Bits() == 0 || port < 0 || port > 65535 {
		return key, "", errors.New("whole-address-space ban or invalid port is forbidden")
	}
	key.Prefix = 64 + uint32(prefix.Bits())
	if prefix.Addr().Is4() {
		key.Family = 4
		a := prefix.Addr().As4()
		copy(key.Address[:], a[:])
	} else {
		key.Family = 6
		key.Address = prefix.Addr().As16()
	}
	binary.BigEndian.PutUint16(key.Port[:], uint16(port))
	canonical := prefix.String()
	if prefix.Bits() == prefix.Addr().BitLen() {
		canonical = prefix.Addr().String()
	}
	return key, canonical, nil
}

// groupRules 将绝对期限转换为内核 BOOTTIME；到期项不重新获得 TTL，重复规范键取覆盖时间更长者。
func groupRules(g *bpfGroup) (map[bpfRuleKey]bpfRuleValue, error) {
	ports := g.Ports
	if len(ports) == 0 {
		ports = []int{0}
	}
	weight := len(ports)
	if len(g.Ports) > 0 {
		weight++
	}
	if len(g.Entries)*weight > bpfMaxRules {
		return nil, errors.New("eBPF group capacity exceeded")
	}
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return nil, err
	}
	now := time.Now()
	bootNS := uint64(boot.Nano())
	if g.Deadlines == nil {
		g.Deadlines = map[string]uint64{}
	}
	rules := map[bpfRuleKey]bpfRuleValue{}
	for raw, expiry := range g.Entries {
		if expiry < 0 {
			return nil, errors.New("negative ban expiry")
		}
		if expiry > 0 && expiry <= now.Unix() && g.Deadlines[raw] == 0 {
			continue
		}
		var until uint64
		if expiry > 0 {
			var exists bool
			until, exists = g.Deadlines[raw]
			if !exists {
				remaining := time.Unix(expiry, 0).Sub(now)
				if remaining <= 0 {
					continue
				}
				until = bootNS + uint64(remaining)
				g.Deadlines[raw] = until
			}
			if until <= bootNS {
				continue
			}
		}
		for _, port := range ports {
			key, _, err := makeRuleKey(raw, port)
			if err != nil {
				return nil, err
			}
			v := bpfRuleValue{Expires: until, Prefix: key.Prefix}
			if old, ok := rules[key]; ok && (old.Expires == 0 || (until != 0 && old.Expires > until)) {
				continue
			}
			rules[key] = v
		}
		// 受限来源另有一个标记，只在分片/扩展头无法完整解析时拒绝该已封来源。
		// 普通 UDP/ICMP 不受 TCP 端口规则影响；不能用难解析报文绕过端口封禁。
		if len(g.Ports) > 0 {
			key, _, err := makeRuleKey(raw, 0)
			if err != nil {
				return nil, err
			}
			key.Family |= 256
			rules[key] = bpfRuleValue{Expires: until, Prefix: key.Prefix}
		}
	}
	// 子前缀继承所有覆盖它的有效祖先期限，0（永久）优先。账本仍保留各自原始期限，
	// 撤销祖先时重建本来源，就不会给子条目错误续期；数据包只需一次 LPM 查询。
	for key, value := range rules {
		parent := key
		for parent.Prefix > 64 {
			parent.Prefix--
			bit := parent.Prefix - 64
			parent.Address[bit/8] &= ^byte(1 << (7 - bit%8))
			if ancestor, ok := rules[parent]; ok && (ancestor.Expires == 0 || value.Expires != 0 && ancestor.Expires > value.Expires) {
				value.Expires = ancestor.Expires
			}
			if value.Expires == 0 {
				break
			}
		}
		rules[key] = value
	}
	return rules, nil
}

// publishGroup 先构建完整新表，只有所有更新成功才替换外层 map 指针；旧表由内核 RCU 释放。
func (b *bpfBackend) publishGroup(g *bpfGroup) error {
	rules, err := groupRules(g)
	if err != nil {
		return err
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "samwaf_rules", Type: ebpf.LPMTrie, KeySize: 28, ValueSize: 16, MaxEntries: bpfMaxRules, Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		return err
	}
	defer m.Close()
	keys := make([]bpfRuleKey, 0, len(rules))
	values := make([]bpfRuleValue, 0, len(rules))
	for k, v := range rules {
		keys = append(keys, k)
		values = append(values, v)
	}
	if len(keys) > 0 {
		if _, err = m.BatchUpdate(keys, values, nil); err != nil {
			// 部分内核不支持 LPM batch；新表尚未发布，逐条重试仍不会暴露半表。
			for i := range keys {
				if err = m.Update(keys[i], values[i], ebpf.UpdateAny); err != nil {
					return err
				}
			}
		}
	}
	return b.groups.Update(g.Slot, m, ebpf.UpdateAny)
}

// publishAll 用于启动/故障重放；总容量先验证，任何非法账本都不允许清空有效位图。
func (b *bpfBackend) publishAll(s *bpfState) error {
	total := 0
	for _, g := range s.Groups {
		n := len(g.Ports)
		if n == 0 {
			n = 1
		} else {
			n++ // 端口组另有一个难解析报文的来源标记。
		}
		total += len(g.Entries) * n
	}
	if total > bpfMaxTotalRules {
		return errors.New("eBPF aggregate capacity exceeded")
	}
	var mask uint64
	for _, g := range s.Groups {
		if err := b.publishGroup(g); err != nil {
			return err
		}
		if len(g.Entries) > 0 {
			mask |= uint64(1) << g.Slot
		}
	}
	return b.active.Update(uint32(0), mask, ebpf.UpdateAny)
}

// transact 先持久化意图，再发布一个来源的新表，最后提交账本；失败保留可重放意图且返回错误。
func (b *bpfBackend) transact(name string, change func(*bpfGroup) error) error {
	if err := validateSetName(name); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	lock, err := bpfLock(b.dir)
	if err != nil {
		return err
	}
	defer bpfUnlock(lock)
	if err = b.recoverPending(); err != nil {
		return err
	}
	s, err := b.readState("state.json")
	if err != nil {
		return err
	}
	g := s.Groups[name]
	if g == nil {
		used := map[uint32]bool{}
		for _, x := range s.Groups {
			used[x.Slot] = true
		}
		var slot uint32
		for slot < bpfMaxGroups && used[slot] {
			slot++
		}
		if slot == bpfMaxGroups {
			return errors.New("eBPF source group limit reached")
		}
		g = &bpfGroup{Slot: slot, Entries: map[string]int64{}}
		s.Groups[name] = g
	}
	previous := make(map[string]int64, len(g.Entries))
	for ip, expiry := range g.Entries {
		previous[ip] = expiry
	}
	if err = change(g); err != nil {
		return err
	}
	for ip, expiry := range g.Entries {
		if old, exists := previous[ip]; !exists || old != expiry {
			delete(g.Deadlines, ip)
		}
	}
	for ip := range g.Deadlines {
		if _, exists := g.Entries[ip]; !exists {
			delete(g.Deadlines, ip)
		}
	}
	now := time.Now().Unix()
	var boot unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return err
	}
	for raw, expiry := range g.Entries {
		if !entryAlive(g, raw, expiry, now, uint64(boot.Nano())) {
			delete(g.Entries, raw)
			delete(g.Deadlines, raw)
		}
	}
	if _, err = groupRules(g); err != nil {
		return err
	}
	total := 0
	for _, x := range s.Groups {
		n := len(x.Ports)
		if n == 0 {
			n = 1
		} else {
			n++
		}
		total += len(x.Entries) * n
	}
	if total > bpfMaxTotalRules {
		return errors.New("eBPF aggregate capacity exceeded")
	}
	if err = b.writeState("pending.json", s); err != nil {
		return err
	}
	if err = b.publishGroup(g); err != nil {
		return err
	}
	var mask uint64
	for _, x := range s.Groups {
		if len(x.Entries) > 0 {
			mask |= uint64(1) << x.Slot
		}
	}
	if err = b.active.Update(uint32(0), mask, ebpf.UpdateAny); err != nil {
		return err
	}
	if err = b.writeState("state.json", s); err != nil {
		return err
	}
	return os.Remove(filepath.Join(b.dir, "pending.json"))
}

// readGroup 在锁内读取已提交账本，查询失败不会伪装成空集合。
func (b *bpfBackend) readGroup(name string) (*bpfGroup, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	lock, err := bpfLock(b.dir)
	if err != nil {
		return nil, err
	}
	defer bpfUnlock(lock)
	if err = b.recoverPending(); err != nil {
		return nil, err
	}
	s, err := b.readState("state.json")
	if err != nil {
		return nil, err
	}
	g := s.Groups[name]
	if g == nil {
		g = &bpfGroup{Entries: map[string]int64{}}
	}
	return g, nil
}

// validateSetName 限定本应用账本键，名称从不拼接为内核命令或文件路径。
func validateSetName(name string) error {
	if len(name) == 0 || len(name) > 128 {
		return errors.New("invalid eBPF group name")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return errors.New("invalid eBPF group name")
		}
	}
	return nil
}

// normalizePorts 对端口范围严格校验，不能把错误的受限范围退化为整机封禁。
func normalizePorts(ports []int) ([]int, error) {
	seen := map[int]bool{}
	result := []int{}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, errors.New("invalid eBPF TCP port")
		}
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	sort.Ints(result)
	if len(result) > 64 {
		return nil, errors.New("at most 64 TCP ports per eBPF group")
	}
	return result, nil
}

// destroyGroup 先关闭本来源的有效位，再释放 map 引用；不会清空其他来源或留下不可复用的槽位。
func (b *bpfBackend) destroyGroup(name string) error {
	if err := validateSetName(name); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	lock, err := bpfLock(b.dir)
	if err != nil {
		return err
	}
	defer bpfUnlock(lock)
	if err = b.recoverPending(); err != nil {
		return err
	}
	s, err := b.readState("state.json")
	if err != nil {
		return err
	}
	group := s.Groups[name]
	if group == nil {
		return nil
	}
	delete(s.Groups, name)
	if err = b.writeState("pending.json", s); err != nil {
		return err
	}
	var active uint64
	for _, g := range s.Groups {
		if len(g.Entries) > 0 {
			active |= uint64(1) << g.Slot
		}
	}
	if err = b.active.Update(uint32(0), active, ebpf.UpdateAny); err != nil {
		return err
	}
	if err = b.groups.Delete(group.Slot); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if err = b.writeState("state.json", s); err != nil {
		return err
	}
	return os.Remove(filepath.Join(b.dir, "pending.json"))
}

// entryAlive 优先使用同一启动周期的固定 BOOTTIME 期限，重启恢复前才依赖绝对时间。
func entryAlive(g *bpfGroup, ip string, expiry, wall int64, boot uint64) bool {
	if expiry == 0 {
		return true
	}
	if deadline := g.Deadlines[ip]; deadline != 0 {
		return deadline > boot
	}
	return expiry > wall
}
