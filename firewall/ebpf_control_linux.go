//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// BPFStatusData 只报告本实例内核对象和丢包计数，不输出来源地址、数据库或认证材料。
type BPFStatusData struct {
	Backend        string `json:"backend"`
	Loaded         bool   `json:"loaded"`
	Hook           string `json:"hook"`
	ActiveSources  int    `json:"published_sources"` // 位图中启用的来源表数，内核另外逐条判断期限。
	DroppedPackets uint64 `json:"dropped_packets"`
	ProgramTag     string `json:"program_tag,omitempty"`
}

// BPFStatus 只重开已存在的 pin，不创建程序、空表或链接，维护查询不会启用防火墙。
func BPFStatus() (BPFStatusData, error) {
	status := BPFStatusData{Backend: "ebpf", Hook: "LOCAL_IN"}
	_, pins, err := bpfPaths()
	if err != nil {
		return status, err
	}
	p, err := ebpf.LoadPinnedProgram(filepath.Join(pins, "program_input"), nil)
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	defer p.Close()
	info, err := p.Info()
	if err != nil {
		return status, err
	}
	if info.Name != "samwaf_input" {
		return status, errors.New("unexpected eBPF program ownership")
	}
	for _, family := range []int{2, 10} {
		l, err := link.LoadPinnedLink(filepath.Join(pins, fmt.Sprintf("input%d", family)), nil)
		if err != nil {
			return status, err
		}
		details, err := l.Info()
		l.Close()
		if err != nil {
			return status, err
		}
		nf := details.Netfilter()
		id, _ := info.ID()
		if details.Program != id || nf == nil || nf.Hooknum != 1 || nf.Pf != uint32(family) || nf.Priority != -75 {
			return status, errors.New("unexpected eBPF link ownership or scope")
		}
	}
	active, err := ebpf.LoadPinnedMap(filepath.Join(pins, "active_groups"), nil)
	if err != nil {
		return status, err
	}
	defer active.Close()
	var mask uint64
	if err = active.Lookup(uint32(0), &mask); err != nil {
		return status, err
	}
	status.ActiveSources = bits.OnesCount64(mask)
	drops, err := ebpf.LoadPinnedMap(filepath.Join(pins, "drop_count"), nil)
	if err != nil {
		return status, err
	}
	defer drops.Close()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return status, err
	}
	values := make([]uint64, cpus)
	if err = drops.Lookup(uint32(0), &values); err != nil {
		return status, err
	}
	for _, value := range values {
		status.DroppedPackets += value
	}
	status.Loaded = true
	status.ProgramTag = info.Tag
	return status, nil
}

// DetachBPF 是停服回退入口：只摘本实例两条链接及固定 pin，不触碰其他网络命名空间/安全产品。
// 本地策略账本继续保留，恢复新二进制时可重放；有来源表时必须显式 force。
func DetachBPF(force bool) error {
	dir, pins, err := bpfPaths()
	if err != nil {
		return err
	}
	if _, err = os.Stat(pins); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	lock, err := bpfLock(dir)
	if err != nil {
		return err
	}
	defer bpfUnlock(lock)
	// 在与所有控制操作相同的锁内重新检查，避免检查后又有新封禁而被无 force 撤销。
	status, err := BPFStatus()
	if err != nil {
		return err
	}
	if !status.Loaded {
		return nil
	}
	if status.ActiveSources > 0 && !force {
		return errors.New("已发布来源表仍存在，请先停服；确认回退后使用 --force")
	}
	for _, family := range []int{2, 10} {
		l, err := link.LoadPinnedLink(filepath.Join(pins, fmt.Sprintf("input%d", family)), nil)
		if err != nil {
			return err
		}
		if err = l.Unpin(); err != nil {
			l.Close()
			return err
		}
		if err = l.Close(); err != nil {
			return err
		}
	}
	for _, name := range []string{"program_input", "ban_groups", "active_groups", "drop_count"} {
		if err = os.Remove(filepath.Join(pins, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(pins)
}
