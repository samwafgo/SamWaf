//go:build darwin

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// 说明：macOS 用 pf table 承载批量封禁——每个逻辑集合(setName，对应订阅渠道)映射为一张 pf table，
// `pfctl -t <table> -T replace -f -` 可从 stdin 全量替换表内容，天然等价 ipset 的原子重建。
// 需要在 /etc/pf.conf 中为每张 table 配 `block in quick from <table>` 规则(参见 SetupPFRule 提示)。

// SupportsIPSet 报告是否可用批量封禁(macOS 下等价于 pf 可用，带 30s 缓存)
func (fw *FireWallEngine) SupportsIPSet() bool {
	return cachedSupportsIPSet(fw) == nil
}

// IPSetUpToDate 报告 pf table 内容是否已经就是这份 ip 列表(尽力而为)。
// 用 `pfctl -t <table> -T show` 数一下条目数与期望比对；表不存在/pf 不可用都返回 false。
// 只比条数不比内容，理由同 Linux 实现：误判的后果只是多做一次 `pfctl -T replace`(原子且幂等)。
func (fw *FireWallEngine) IPSetUpToDate(setName string, ips []string) bool {
	if !fw.SupportsIPSet() {
		return false
	}
	out, err := exec.Command("pfctl", "-t", pfTableName(setName), "-T", "show").CombinedOutput()
	if err != nil {
		return false
	}
	got := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			got++
		}
	}
	want := 0
	for _, raw := range ips {
		if strings.TrimSpace(raw) != "" {
			want++
		}
	}
	return got == want
}

// supportsIPSet macOS 下等同 checkAvailable(pfctl 存在且 pf 启用)
func (fw *FireWallEngine) supportsIPSet() error {
	return fw.checkAvailable()
}

// pfTableName 由集合名派生 pf table 名(pf table 名较宽松，直接用 setName)
func pfTableName(setName string) string { return setName }

// EnsureIPSet macOS 通过 replace 空表即可初始化，空实现
func (fw *FireWallEngine) EnsureIPSet(setName string) error { return nil }

// RestoreIPSet 用 pfctl -T replace -f - 从 stdin 全量替换 pf table 内容(原子)
func (fw *FireWallEngine) RestoreIPSet(setName string, ips []string) error {
	table := pfTableName(setName)
	var b strings.Builder
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		b.WriteString(ip)
		b.WriteByte('\n')
	}
	cmd := exec.Command("pfctl", "-t", table, "-T", "replace", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl replace 表 %s 失败: %v, 输出: %s", table, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SupportsIncrementalIPSet macOS 支持：pfctl -T add/delete 原生就是增量操作
func (fw *FireWallEngine) SupportsIncrementalIPSet() bool { return true }

// SupportsPortScopedSet macOS 不支持端口级封禁。
// pf 的匹配规则写在 /etc/pf.conf 里(见 SetupPFRule 的提示)，由用户手工维护，
// 我们只往 table 里灌地址、不去改用户的规则文件。想限端口请用户自己在 pf.conf 的
// block 规则上加 `port {22, 3389}`。
func (fw *FireWallEngine) SupportsPortScopedSet() bool { return false }

// ApplyIPSetPortScope macOS 空实现，调用方应先判 SupportsPortScopedSet 并提示用户
func (fw *FireWallEngine) ApplyIPSetPortScope(setName string, tcpPorts []int) error { return nil }

// AddToIPSet 向 pf table 增量添加
func (fw *FireWallEngine) AddToIPSet(setName string, ips []string) error {
	return fw.incrementalPFTable(setName, ips, "add")
}

// DelFromIPSet 从 pf table 增量删除
func (fw *FireWallEngine) DelFromIPSet(setName string, ips []string) error {
	return fw.incrementalPFTable(setName, ips, "delete")
}

// incrementalPFTable 走 stdin 批量传入，避免 IP 数量多时超出命令行长度
func (fw *FireWallEngine) incrementalPFTable(setName string, ips []string, op string) error {
	if len(ips) == 0 {
		return nil
	}
	var b strings.Builder
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		b.WriteString(ip)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return nil
	}
	table := pfTableName(setName)
	cmd := exec.Command("pfctl", "-t", table, "-T", op, "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %s 表 %s 失败: %v, 输出: %s", op, table, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// FlushIPSet 清空 pf table
func (fw *FireWallEngine) FlushIPSet(setName string) error {
	cmd := exec.Command("pfctl", "-t", pfTableName(setName), "-T", "flush")
	_, _ = cmd.CombinedOutput()
	return nil
}

// DestroyIPSet 清空并移除 pf table
func (fw *FireWallEngine) DestroyIPSet(setName string) error {
	table := pfTableName(setName)
	// 先清空
	flush := exec.Command("pfctl", "-t", table, "-T", "flush")
	_, _ = flush.CombinedOutput()
	// 再销毁表定义
	kill := exec.Command("pfctl", "-t", table, "-T", "kill")
	_, _ = kill.CombinedOutput()
	return nil
}
