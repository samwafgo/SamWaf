//go:build linux

package firewall

import (
	"golang.org/x/sys/unix"
	"time"
)

// SupportsIPSet 是旧跨平台能力接口，Linux 的集合实际由 eBPF LPM maps 提供。
func (fw *FireWallEngine) SupportsIPSet() bool { return fw.CheckAvailable() == nil }

// supportsIPSet 供公共能力缓存使用，不再探测外部 ipset 可执行文件。
func (fw *FireWallEngine) supportsIPSet() error { return fw.checkAvailable() }

// EnsureIPSet 建立空的来源账本。空组不会参与数据包查询。
func (fw *FireWallEngine) EnsureIPSet(name string) error {
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact(name, func(g *bpfGroup) error { return nil })
}

// IPSetUpToDate 规范化后比较完整集合，不能仅比较条目数判定内容相同。
func (fw *FireWallEngine) IPSetUpToDate(name string, ips []string) bool {
	b, err := getBPFBackend()
	if err != nil {
		return false
	}
	g, err := b.readGroup(name)
	if err != nil {
		return false
	}
	want := map[string]bool{}
	for _, ip := range ips {
		_, canonical, e := makeRuleKey(ip, 0)
		if e != nil {
			return false
		}
		want[canonical] = true
	}
	now := time.Now().Unix()
	count := 0
	for ip, expiry := range g.Entries {
		if expiry != 0 && expiry <= now {
			continue
		}
		if !want[ip] {
			return false
		}
		count++
	}
	return count == len(want)
}

// RestoreIPSet 全量替换单个来源；其他来源和端口范围原样保留。
func (fw *FireWallEngine) RestoreIPSet(name string, ips []string) error {
	entries := map[string]int64{}
	for _, ip := range ips {
		_, canonical, err := makeRuleKey(ip, 0)
		if err != nil {
			return err
		}
		entries[canonical] = 0
	}
	return fw.RestoreTimedIPSet(name, entries)
}

// RestoreTimedIPSet 将账本中的绝对期限一起恢复，避免机器重启把临时封禁变成永久封禁。
func (fw *FireWallEngine) RestoreTimedIPSet(name string, entries map[string]int64) error {
	canonical := map[string]int64{}
	for ip, expiry := range entries {
		_, key, err := makeRuleKey(ip, 0)
		if err != nil {
			return err
		}
		if old, exists := canonical[key]; !exists || expiry == 0 || old != 0 && expiry > old {
			canonical[key] = expiry
		}
	}
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact(name, func(g *bpfGroup) error { g.Entries = canonical; return nil })
}

// SupportsIncrementalIPSet 表示调用者可提交增删；只重建该来源表，不重建其他大订阅组。
func (fw *FireWallEngine) SupportsIncrementalIPSet() bool { return true }

// AddToIPSet 保留其他条目及已有期限，不通过重复添加延长封禁。
func (fw *FireWallEngine) AddToIPSet(name string, ips []string) error {
	entries := map[string]int64{}
	for _, ip := range ips {
		entries[ip] = 0
	}
	return fw.AddTimedToIPSet(name, entries)
}

// AddTimedToIPSet 在同一控制事务中添加带期限的来源记录。
func (fw *FireWallEngine) AddTimedToIPSet(name string, entries map[string]int64) error {
	canonical := map[string]int64{}
	for ip, expiry := range entries {
		_, key, err := makeRuleKey(ip, 0)
		if err != nil {
			return err
		}
		canonical[key] = expiry
	}
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact(name, func(g *bpfGroup) error {
		now := time.Now().Unix()
		for ip, expiry := range canonical {
			old, ok := g.Entries[ip]
			if !ok || old > 0 && old <= now {
				g.Entries[ip] = expiry
			}
		}
		return nil
	})
}

// DelFromIPSet 先校验整个增量，再从本来源删除，不能误删其他来源的相同 IP。
func (fw *FireWallEngine) DelFromIPSet(name string, ips []string) error {
	canonical := []string{}
	for _, ip := range ips {
		_, key, err := makeRuleKey(ip, 0)
		if err != nil {
			return err
		}
		canonical = append(canonical, key)
	}
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact(name, func(g *bpfGroup) error {
		for _, ip := range canonical {
			delete(g.Entries, ip)
		}
		return nil
	})
}

// SupportsPortScopedSet 报告 TCP 目标端口限制能力，IPv4/IPv6 使用同一语义。
func (fw *FireWallEngine) SupportsPortScopedSet() bool { return true }

// ApplyIPSetPortScope 原子更新来源表，已有封禁立即按新端口范围执行。
func (fw *FireWallEngine) ApplyIPSetPortScope(name string, ports []int) error {
	normal, err := normalizePorts(ports)
	if err != nil {
		return err
	}
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact(name, func(g *bpfGroup) error { g.Ports = normal; return nil })
}

// FlushIPSet 清空来源，保留其稳定槽位和端口策略。
func (fw *FireWallEngine) FlushIPSet(name string) error {
	return fw.RestoreTimedIPSet(name, map[string]int64{})
}

// DestroyIPSet 关闭来源位图后释放其表与槽位；所有控制操作在锁内按名称重新解析槽位。
func (fw *FireWallEngine) DestroyIPSet(name string) error {
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.destroyGroup(name)
}

// ChangeTimedIPSet 在同一个来源表交换中完成增删，调用者不会观察到中间的半份状态。
func (fw *FireWallEngine) ChangeTimedIPSet(name string, add map[string]int64, del []string) error {
	canonical := map[string]int64{}
	removed := []string{}
	for ip, expiry := range add {
		_, key, err := makeRuleKey(ip, 0)
		if err != nil {
			return err
		}
		canonical[key] = expiry
	}
	for _, ip := range del {
		_, key, err := makeRuleKey(ip, 0)
		if err != nil {
			return err
		}
		removed = append(removed, key)
	}
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact(name, func(g *bpfGroup) error {
		now := time.Now().Unix()
		var boot unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
			return err
		}
		for ip, expiry := range canonical {
			old, exists := g.Entries[ip]
			if !exists || !entryAlive(g, ip, old, now, uint64(boot.Nano())) {
				g.Entries[ip] = expiry
			}
		}
		for _, ip := range removed {
			delete(g.Entries, ip)
		}
		return nil
	})
}

// ReadTimedIPSet 返回本来源仍有效的控制账本，供主机防护跨 Worker 去重与状态展示。
func (fw *FireWallEngine) ReadTimedIPSet(name string) (map[string]int64, error) {
	b, err := getBPFBackend()
	if err != nil {
		return nil, err
	}
	group, err := b.readGroup(name)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	var boot unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return nil, err
	}
	result := map[string]int64{}
	for ip, expiry := range group.Entries {
		if !entryAlive(group, ip, expiry, now, uint64(boot.Nano())) {
			continue
		}
		result[ip] = expiry
	}
	return result, nil
}
