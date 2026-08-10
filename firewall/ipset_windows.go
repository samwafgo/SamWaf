//go:build windows

package firewall

import (
	"SamWaf/common/wafexec"
	"SamWaf/common/zlog"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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
	// netshListTimeout 枚举全部防火墙规则的超时(实测数百条规则约 0.5s)
	netshListTimeout = 30 * time.Second
	// destroyMaxRounds 清理时"枚举→删除"最多重复几轮(多出的轮次用于确认真的删干净了)
	destroyMaxRounds = 3
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

// SupportsIncrementalIPSet Windows 不支持增量。
//
// 分片规则模型里，一个逻辑集合被拆成若干条 netsh 规则，每条的 remoteip= 是一长串逗号
// 分隔的地址。要"删掉其中一个 IP"就得知道它在哪个分片、把那条规则整个重写，还得处理
// 删空后的分片回收——复杂度和出错面都远超收益。调用方应改用"去抖后全量 RestoreIPSet"。
func (fw *FireWallEngine) SupportsIncrementalIPSet() bool { return false }

// AddToIPSet Windows 不支持增量，调用方必须先判 SupportsIncrementalIPSet
func (fw *FireWallEngine) AddToIPSet(setName string, ips []string) error {
	return errIncrementalUnsupported
}

// DelFromIPSet Windows 不支持增量，调用方必须先判 SupportsIncrementalIPSet
func (fw *FireWallEngine) DelFromIPSet(setName string, ips []string) error {
	return errIncrementalUnsupported
}

var errIncrementalUnsupported = fmt.Errorf("当前系统(Windows)的防火墙不支持集合增量增删，请改用全量重建")

// SupportsPortScopedSet Windows 支持：netsh 规则本来就能带 localport
func (fw *FireWallEngine) SupportsPortScopedSet() bool { return true }

// portScope 记录各集合的端口范围。Windows 没有"独立的引用规则"可改，
// 端口是写在分片规则自身上的，所以只能记下来、在下次 RestoreIPSet 重建时带上。
var portScope sync.Map // setName -> string(逗号分隔端口)

// ApplyIPSetPortScope 设置集合的封禁端口范围。
//
// Windows 下**只记录不重建**：端口写在分片规则自身上，而这个包是无状态的，
// 手里没有当前该封哪些 IP。要让新范围立刻作用到已生效的封禁，
// 必须由持有集合镜像的调用方(wafhostguard.BanExecutor)在调完本方法后
// 再触发一次全量 RestoreIPSet —— 见 BanExecutor.ApplyPortScope。
func (fw *FireWallEngine) ApplyIPSetPortScope(setName string, tcpPorts []int) error {
	spec := formatPortList(tcpPorts)
	if spec == "" {
		portScope.Delete(setName)
	} else {
		portScope.Store(setName, spec)
	}
	return nil
}

// formatPortList netsh 的 localport 接受逗号分隔列表
func formatPortList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			parts = append(parts, strconv.Itoa(p))
		}
	}
	return strings.Join(parts, ",")
}

// RestoreIPSet 全量重建：先删旧分片规则，再按长度分片重建为若干 netsh block 规则
func (fw *FireWallEngine) RestoreIPSet(setName string, ips []string) error {
	// 先清旧。clean=true 表示已枚举确认无残留，下面就不必逐分片再删一次。
	clean, err := fw.destroyIPSetVerified(setName)
	if err != nil {
		// 清理失败不致命，继续重建(可能只是原本没有规则)，但要按"未确认干净"处理
		zlog.Warn("清理旧分片规则失败，重建时逐分片兜底删除", "set", setName, "error", err.Error())
		clean = false
	}
	shards := shardIPsByLen(ips, maxRemoteIPChars)
	for seq, shard := range shards {
		if shard == "" {
			continue
		}
		ruleName := setShardRuleName(setName, seq)
		// 没能确认清空时，add 前先按名字删一次：netsh 的 add 是**追加**不是替换，
		// Windows 允许同名规则并存，不删就会叠成两份、三份……
		if !clean {
			fw.deleteRuleByName(ruleName)
		}
		args := []string{"advfirewall", "firewall", "add", "rule",
			"name=" + ruleName, "dir=in", "action=block", "remoteip=" + shard}
		// 设置过端口范围就只封那几个端口(主机防爆破的"仅SSH/RDP端口"模式)，
		// 误封时业务端口不受影响
		if spec, ok := portScope.Load(setName); ok {
			if s, _ := spec.(string); s != "" {
				args = append(args, "protocol=TCP", "localport="+s)
			}
		}
		cmd := exec.Command("netsh", args...)
		err, output := fw.executeCommand(cmd)
		invalidateRuleDump() // 不论成败都作废：失败也可能已经写进去了一部分
		if err != nil {
			// 半截落地：前面 seq 的分片已经写进防火墙了。这里如实报错，
			// 由调用方标记为落地失败并保持 landed_sha 不变，下一轮同步/对账会覆盖式重建。
			return fmt.Errorf("添加分片规则 %s 失败(已写入 %d/%d 个分片): %v, 输出: %s",
				ruleName, seq, len(shards), err, output)
		}
	}
	return nil
}

// FlushIPSet Windows 下等同销毁全部分片规则
func (fw *FireWallEngine) FlushIPSet(setName string) error {
	return fw.DestroyIPSet(setName)
}

// DestroyIPSet 删除该集合的全部分片规则。
//
// 实现是"先枚举系统里实际存在的分片规则名，再逐个删"，而不是按序号 0,1,2… 试探着删。
// 按序号试探有两个致命弱点，线上已实测到重复规则堆积(同一分片名多达 7 份)：
//
//  1. **判不准"删没删掉"**。netsh 的成功/失败只能靠输出文案或退出码判断，而两者都不可靠：
//     非管理员运行时输出的是"请求的操作需要提升(作为管理员运行)。"且退出码为 1，
//     既不是英文 "No rules match the specified criteria" 也不是简中"没有与指定标准相匹配的规则"。
//     老实现据此 break，条件永远不满足 → 空转；改成"删不掉就当没有"后又会反过来提前收工 →
//     一条没删干净，紧接着 RestoreIPSet 整层 add 上去，于是全段均匀多一份。
//  2. **怕空洞**。序号一旦不连续(并发的 destroy/add 交错就会造成)，试探法会停在空洞处，
//     空洞以上的分片永远扫不到，每轮重建都在上面继续叠。
//
// 枚举法对这两点免疫：看到什么删什么，与语言、退出码、序号连续性都无关；
// 而且 `netsh delete rule name=X` 一次会删掉该名字下的**所有**副本，因此能顺带清掉存量重复。
func (fw *FireWallEngine) DestroyIPSet(setName string) error {
	_, err := fw.destroyIPSetVerified(setName)
	return err
}

// destroyIPSetVerified 同 DestroyIPSet，额外返回 clean —— 是否**枚举确认过**已无残留。
// 调用方(RestoreIPSet)据此决定要不要在每个分片 add 前再补一次删除：
// 确认干净时那步纯属浪费(几十条分片就是几十次多余的 netsh)，没确认时它是唯一的兜底。
func (fw *FireWallEngine) destroyIPSetVerified(setName string) (bool, error) {
	// 系统防火墙不可用时一次 fork 都不做(netsh 缺失 / 防火墙未启用)
	if !fw.SupportsIPSet() {
		return true, nil
	}

	start := time.Now()
	deleted := 0
	clean := false
	prevRemain := -1
	for round := 0; round < destroyMaxRounds; round++ {
		names, err := fw.listShardRuleNames(setName, true) // 清理必须看实时状态，不走缓存
		if err != nil {
			zlog.Warn("枚举防火墙分片规则失败，回退按序号清理", "set", setName, "error", err.Error())
			return false, fw.destroyByScan(setName, start, deleted)
		}
		if len(names) == 0 {
			clean = true // 枚举确认已无残留
			break
		}
		if round > 0 {
			// 上一轮删过还剩，说明有并发写入或删除未生效，值得记一笔
			zlog.Warn("清理防火墙分片规则后仍有残留，继续重试", "set", setName,
				"remain", len(names), "round", round+1)
			// 一条都没减少 = 删除动作根本不生效(最常见是没有管理员权限)。
			// 再重试只是白白多花几十秒并占着调用方的锁，直接收工。
			if len(names) >= prevRemain {
				zlog.Warn("清理防火墙分片规则无进展，停止重试(通常是缺少管理员权限)",
					"set", setName, "remain", len(names))
				break
			}
		}
		prevRemain = len(names)
		for _, name := range names {
			fw.deleteRuleByName(name)
			deleted++
			if time.Since(start) > destroyBudget {
				zlog.Warn("清理防火墙分片规则超出时间预算，已提前结束",
					"set", setName, "deleted", deleted,
					"elapsed", time.Since(start).Round(time.Millisecond).String())
				return false, nil
			}
		}
	}
	if !clean {
		zlog.Warn("清理防火墙分片规则未能确认清空(已达最大轮次)", "set", setName, "deleted", deleted)
	}
	if deleted > 0 {
		zlog.Info("清理防火墙分片规则完成", "set", setName, "deleted", deleted,
			"elapsed", time.Since(start).Round(time.Millisecond).String())
	}
	return clean, nil
}

// listShardRuleNames 枚举系统防火墙中属于该集合的全部分片规则名(去重)。
//
// 刻意直接在 netsh 的**原始字节**上找 ASCII 规则名，不解码、不按行解析、不认任何本地化标签：
// 规则名本身全是 ASCII，而"规则名称:"这类标签在不同语言/代码页下完全不同。
//
// fresh=true 强制重新枚举(清理循环必须看实时状态)；false 允许复用短 TTL 快照
// (落地对账要连着核对多个渠道，每个渠道各枚举一次全量规则太浪费)。
func (fw *FireWallEngine) listShardRuleNames(setName string, fresh bool) ([]string, error) {
	out, err := dumpFirewallRules(fresh)
	if err != nil {
		return nil, err
	}
	return extractShardRuleNames(out, setName), nil
}

// ---- 全量规则枚举的短 TTL 缓存 ----
//
// `netsh show rule name=all` 实测约 0.5s。清理时要看实时状态所以强制刷新；
// 而落地对账会连续核对每个渠道，共用一次枚举结果即可，否则 N 个渠道就是 N×0.5s。
// 任何增删规则的动作都会主动作废缓存，避免读到过期状态。
var (
	ruleDumpMu     sync.Mutex
	ruleDumpAt     time.Time
	ruleDumpCache  []byte
	ruleDumpCached bool
)

// ruleDumpTTL 缓存有效期，取小值：只为覆盖"一轮对账里的连续多次调用"
const ruleDumpTTL = 3 * time.Second

// dumpFirewallRules 取全部防火墙规则的原始字节；fresh=true 时绕过缓存
func dumpFirewallRules(fresh bool) ([]byte, error) {
	ruleDumpMu.Lock()
	defer ruleDumpMu.Unlock()

	if !fresh && ruleDumpCached && time.Since(ruleDumpAt) < ruleDumpTTL {
		return ruleDumpCache, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), netshListTimeout)
	defer cancel()
	cmd := wafexec.FixStdin(exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all"))
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		ruleDumpCached = false
		return nil, fmt.Errorf("枚举防火墙规则失败: %v", err)
	}
	ruleDumpCache, ruleDumpAt, ruleDumpCached = out, time.Now(), true
	return out, nil
}

// invalidateRuleDump 规则被增删后作废缓存
func invalidateRuleDump() {
	ruleDumpMu.Lock()
	ruleDumpCached = false
	ruleDumpMu.Unlock()
}

// extractShardRuleNames 从 netsh 输出的原始字节里挑出属于该集合的分片规则名(去重、保持出现顺序)
func extractShardRuleNames(out []byte, setName string) []string {
	names, _ := scanShardRuleNames(out, setName)
	return names
}

// scanShardRuleNames 同上，额外返回**出现次数**(含同名副本)。
// distinct 与 instances 不相等就说明系统里存在同名重复规则。
func scanShardRuleNames(out []byte, setName string) (names []string, instances int) {
	want := []byte(setShardRulePrefix(setName))
	if len(want) == 0 {
		return nil, 0
	}
	seen := make(map[string]struct{})
	names = make([]string, 0, 8)
	for pos := 0; pos+len(want) <= len(out); {
		idx := bytes.Index(out[pos:], want)
		if idx < 0 {
			break
		}
		begin := pos + idx
		end := begin + len(want)
		for end < len(out) && isRuleNameByte(out[end]) {
			end++
		}
		if name := string(out[begin:end]); isShardRuleName(name, setName) {
			instances++
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
		pos = begin + len(want)
	}
	return names, instances
}

// IPSetUpToDate 报告系统防火墙里的分片规则是否已经就是这份 ip 列表(尽力而为)。
//
// Windows 的 netsh 规则是**持久化**的，进程重启、机器重启后都还在。启动重放若无脑
// destroy+add 一遍，几十个分片就是上百次 netsh 调用、动辄几十秒，还会长时间占住
// 调用方的同步锁——用户这段时间点"立即同步"只会看到"等待超时已跳过"。
//
// 判定条件是"分片规则条数与去重后名字数都等于本次应有的分片数"：数量对得上，
// 且没有同名重复(有重复恰恰是必须重建来清理的情况)。
// 不比对内容——那要把每条规则的 remoteip= 拉出来比，代价远超收益；
// 内容真变了的话 sha 会变，同步流程本身会做全量重建。
func (fw *FireWallEngine) IPSetUpToDate(setName string, ips []string) bool {
	if !fw.SupportsIPSet() {
		return false
	}
	expect := len(shardIPsByLen(ips, maxRemoteIPChars))
	if expect == 0 {
		return false
	}
	// 允许复用短 TTL 快照：落地对账会连着核对每个渠道，共用一次枚举即可
	out, err := dumpFirewallRules(false)
	if err != nil {
		return false
	}
	names, instances := scanShardRuleNames(out, setName)
	return len(names) == expect && instances == expect
}

// setShardRulePrefix 该集合所有分片规则名的公共前缀(末尾带下划线，避免匹配到 <setName>2 这类别的集合)
func setShardRulePrefix(setName string) string {
	return setRulePrefix + setName + "_"
}

// isRuleNameByte 规则名允许的字符(与 setShardRuleName 生成的字符集一致)
func isRuleNameByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isShardRuleName 校验名字确实是"本集合的第 N 个分片"：前缀之后必须是纯数字。
// 这样 SamWAF_Set_<set>_x_0(另一个集合)不会被误删。
func isShardRuleName(name, setName string) bool {
	suffix := strings.TrimPrefix(name, setShardRulePrefix(setName))
	if suffix == "" || suffix == name {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return false
		}
	}
	return true
}

// deleteRuleByName 按名字删规则。netsh 会一次删掉该名字下的所有副本，因此不需要循环删。
// 结果不做判定：这里唯一可靠的"是否删干净"来源是下一轮枚举。
func (fw *FireWallEngine) deleteRuleByName(ruleName string) {
	ctx, cancel := context.WithTimeout(context.Background(), netshCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	fw.executeCommand(cmd)
	invalidateRuleDump()
}

// destroyByScan 枚举不可用时的兜底：仍按序号试探删除，连续 destroyMissStreak 次未命中即停。
// 明知不够可靠(见 DestroyIPSet 注释)，但总好过完全不清理。
func (fw *FireWallEngine) destroyByScan(setName string, start time.Time, deleted int) error {
	miss := 0
	for seq := 0; seq < maxShardScan; seq++ {
		if time.Since(start) > destroyBudget {
			zlog.Warn("按序号清理防火墙分片规则超出时间预算，已提前结束",
				"set", setName, "scanned", seq, "deleted", deleted)
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
		zlog.Info("按序号清理防火墙分片规则完成", "set", setName, "deleted", deleted,
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
