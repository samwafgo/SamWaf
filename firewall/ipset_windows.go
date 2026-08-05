//go:build windows

package firewall

import (
	"SamWaf/common/zlog"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// 说明：Windows 无 ipset 概念，但 netsh 单条规则的 remoteip= 支持逗号分隔多个 IP/CIDR。
// 为承载"上万~十万条威胁情报 IP"，这里把一个逻辑集合(setName，对应一个订阅渠道)拆成
// 多条分片规则 SamWAF_Set_<setName>_<seq>，每条聚合若干 IP(按命令行长度上限分片)，
// 而不是每 IP 一条规则(上万条会拖垮 Windows 防火墙 UI 与匹配)。

const (
	// setRulePrefix 订阅集合分片规则名前缀(区别于逐条封禁的 RULE_PREFIX)
	setRulePrefix = "SamWAF_Set_"
	// maxRemoteIPChars 单条规则 remoteip= 值的字符上限(留足命令行余量)
	maxRemoteIPChars = 3000
	// maxShardScan DestroyIPSet 时扫描删除分片规则的序号上限(兜底防死循环)。
	// 单分片 maxRemoteIPChars=3000 字符 ≈ 200 条 IP，4096 个分片 ≈ 80 万条，远超实际订阅规模。
	maxShardScan = 4096
	// destroyMissStreak 连续多少个序号"未命中"就认为分片已删完
	destroyMissStreak = 3
	// destroyBudget DestroyIPSet 整体时间预算，超了就放弃剩余扫描(防止拖住调用方持有的锁)
	destroyBudget = 30 * time.Second
	// netshCmdTimeout 单条 netsh 命令的超时，防个别调用挂死
	netshCmdTimeout = 5 * time.Second
)

// SupportsIPSet 报告当前环境是否可用批量封禁(Windows 下等价于系统防火墙可用，带 30s 缓存)
func (fw *FireWallEngine) SupportsIPSet() bool {
	return cachedSupportsIPSet(fw) == nil
}

// supportsIPSet Windows 下等同 checkAvailable(netsh 存在且防火墙启用)
func (fw *FireWallEngine) supportsIPSet() error {
	return fw.checkAvailable()
}

// setShardRuleName 生成某集合第 seq 个分片的规则名
func setShardRuleName(setName string, seq int) string {
	return fmt.Sprintf("%s%s_%d", setRulePrefix, setName, seq)
}

// EnsureIPSet Windows 无需预建集合，空实现(规则在 RestoreIPSet 时创建)
func (fw *FireWallEngine) EnsureIPSet(setName string) error { return nil }

// RestoreIPSet 全量重建：先删旧分片规则，再按长度分片重建为若干 netsh block 规则
func (fw *FireWallEngine) RestoreIPSet(setName string, ips []string) error {
	// 先清旧
	if err := fw.DestroyIPSet(setName); err != nil {
		// 清理失败不致命，继续重建(可能只是原本没有规则)
		fmt.Printf("[WARN] 清理旧分片规则失败(继续): %v\n", err)
	}
	shards := shardIPsByLen(ips, maxRemoteIPChars)
	for seq, shard := range shards {
		if shard == "" {
			continue
		}
		ruleName := setShardRuleName(setName, seq)
		args := []string{"advfirewall", "firewall", "add", "rule",
			"name=" + ruleName, "dir=in", "action=block", "remoteip=" + shard}
		cmd := exec.Command("netsh", args...)
		if err, output := fw.executeCommand(cmd); err != nil {
			return fmt.Errorf("添加分片规则 %s 失败: %v, 输出: %s", ruleName, err, output)
		}
	}
	return nil
}

// FlushIPSet Windows 下等同销毁全部分片规则
func (fw *FireWallEngine) FlushIPSet(setName string) error {
	return fw.DestroyIPSet(setName)
}

// DestroyIPSet 逐序号删除该集合的所有分片规则，直到连续若干个序号都删不动为止。
//
// 停止条件刻意不再依赖 netsh 的本地化提示文案：老实现只认英文
// "No rules match the specified criteria" 和简中"没有与指定标准相匹配的规则"，
// 一旦 netsh 输出别的内容(非中英文系统、非管理员运行时的"请求的操作需要提升"、
// 防火墙服务异常等)，break 就永远不会触发，会 fork 二十万次 netsh 空转数小时，
// 并把调用方持有的同步锁一起焊死。现在改为：**任何一次"没有删成功"都算未命中**，
// 连续 destroyMissStreak 次未命中即停，另加整体时间预算兜底。宁可少删，绝不空转。
func (fw *FireWallEngine) DestroyIPSet(setName string) error {
	// 系统防火墙不可用时一次 fork 都不做(netsh 缺失 / 防火墙未启用)
	if !fw.SupportsIPSet() {
		return nil
	}

	start := time.Now()
	deleted, miss := 0, 0
	for seq := 0; seq < maxShardScan; seq++ {
		if time.Since(start) > destroyBudget {
			zlog.Warn("清理防火墙分片规则超出时间预算，已提前结束",
				"set", setName, "scanned", seq, "deleted", deleted,
				"elapsed", time.Since(start).Round(time.Millisecond).String())
			break
		}
		if fw.deleteShardRule(setName, seq) {
			deleted++
			miss = 0
			continue
		}
		miss++
		if miss >= destroyMissStreak {
			break
		}
	}
	if deleted > 0 {
		zlog.Debug("清理防火墙分片规则完成", "set", setName, "deleted", deleted,
			"elapsed", time.Since(start).Round(time.Millisecond).String())
	}
	return nil
}

// deleteShardRule 删除单个分片规则，返回是否确实删掉了。
// 只有 netsh 明确报告删除成功才算命中；出错、超时、输出看不懂一律当作"没有这个分片"。
func (fw *FireWallEngine) deleteShardRule(setName string, seq int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), netshCmdTimeout)
	defer cancel()

	ruleName := setShardRuleName(setName, seq)
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	err, output := fw.executeCommand(cmd)
	if err != nil {
		return false
	}
	// 已知的"没有这条规则"文案优先判定：部分环境下 netsh 会在该提示后仍打印"确定。"
	if strings.Contains(output, "No rules match the specified criteria") ||
		strings.Contains(output, "没有与指定标准相匹配的规则") {
		return false
	}
	return strings.Contains(output, "已删除") || strings.Contains(output, "Deleted")
}

// shardIPsByLen 把 IP/CIDR 列表按逗号拼接、累计长度不超过 maxLen 切分为多个分片字符串
func shardIPsByLen(ips []string, maxLen int) []string {
	var shards []string
	var cur strings.Builder
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		// +1 预留逗号
		if cur.Len() > 0 && cur.Len()+1+len(ip) > maxLen {
			shards = append(shards, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(',')
		}
		cur.WriteString(ip)
	}
	if cur.Len() > 0 {
		shards = append(shards, cur.String())
	}
	return shards
}
