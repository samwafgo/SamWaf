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
