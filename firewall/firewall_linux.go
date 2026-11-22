//go:build linux

package firewall

import (
	"fmt"
	"sort"
	"time"
)

// Linux 系统封禁全部通过内嵌 eBPF 执行；保留现有跨平台调用接口。
type Charset string

const (
	UTF8    Charset = "UTF-8"
	GB18030 Charset = "GB18030"
)
const (
	ACTION_ALLOW  = "allow"
	ACTION_BLOCK  = "block"
	ACTION_BYPASS = "bypass"
)
const (
	PROTOCOL_ANY   = "any"
	PROTOCOL_TCP   = "TCP"
	PROTOCOL_UDP   = "UDP"
	DIRECTION_IN   = "in"
	DIRECTION_OUT  = "out"
	DIRECTION_BOTH = "both"
)

// FireWallEngine 是 eBPF 控制入口，不在 HTTP 请求热路径执行 BPF 系统调用。
type FireWallEngine struct{}

// IPBlockInfo 保留系统封禁查询接口的数据模型。
type IPBlockInfo struct {
	IP, Reason          string
	BlockTime           time.Time
	Protocol, Direction string
}

// IsFirewallEnabled 只报告本实例的 eBPF 后端是否可初始化，不推断其他防火墙规则状态。
func (fw *FireWallEngine) IsFirewallEnabled() bool { return fw.CheckAvailable() == nil }

// checkAvailable 加载/验证本实例对象；失败明确报错，不能静默退回旧系统命令。
func (fw *FireWallEngine) checkAvailable() error { _, err := getBPFBackend(); return err }

// AddRule 延续旧 Linux 入站封禁语义；allow/bypass 不能伪装成成功操作。
func (fw *FireWallEngine) AddRule(ruleName, ip, action, protocol, port string) error {
	if action != ACTION_BLOCK {
		return fmt.Errorf("eBPF AddRule only supports inbound block")
	}
	return fw.BlockIP(ip, ruleName)
}

// EditRule 没有按序号编辑的接口，调用者必须使用显式 IP 增删。
func (fw *FireWallEngine) EditRule(number int, rule string) error {
	return fmt.Errorf("edit rule by number is unsupported")
}

// DeleteRule 旧 Linux API 将参数视为 IP，而不是外部防火墙规则名。
func (fw *FireWallEngine) DeleteRule(ip string) (bool, error) {
	err := fw.UnblockIP(ip)
	return err == nil, err
}

// IsRuleExists 查询本应用的手工来源，不枚举或修改其他服务的策略。
func (fw *FireWallEngine) IsRuleExists(ip string) (bool, error) { return fw.IsIPBlocked(ip) }

// BlockIP 手工永久封禁；重复添加是幂等操作，便于启动重放。
func (fw *FireWallEngine) BlockIP(ip, reason string) error {
	return fw.BlockIPWithExpiry(ip, reason, 0)
}

// BlockIPWithExpiry 把绝对期限带入内核，控制进程暂停时封禁也能按时结束。
func (fw *FireWallEngine) BlockIPWithExpiry(ip, reason string, expiry int64) error {
	_, canonical, err := makeRuleKey(ip, 0)
	if err != nil {
		return err
	}
	if expiry < 0 {
		return fmt.Errorf("negative ban expiry")
	}
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact("manual", func(g *bpfGroup) error { g.Entries[canonical] = expiry; return nil })
}

// UnblockIP 幂等撤销手工来源，不影响同 IP 在订阅/主机防护来源中的有效封禁。
func (fw *FireWallEngine) UnblockIP(ip string) error {
	_, canonical, err := makeRuleKey(ip, 0)
	if err != nil {
		return err
	}
	b, err := getBPFBackend()
	if err != nil {
		return err
	}
	return b.transact("manual", func(g *bpfGroup) error { delete(g.Entries, canonical); return nil })
}

// IsIPBlocked 检查手工来源中的精确条目及其到期时间，查询错误必须返回给上层。
func (fw *FireWallEngine) IsIPBlocked(ip string) (bool, error) {
	_, canonical, err := makeRuleKey(ip, 0)
	if err != nil {
		return false, err
	}
	b, err := getBPFBackend()
	if err != nil {
		return false, err
	}
	g, err := b.readGroup("manual")
	if err != nil {
		return false, err
	}
	expiry, ok := g.Entries[canonical]
	return ok && (expiry == 0 || expiry > time.Now().Unix()), nil
}

// BlockIPList 在一个来源事务里批量添加，校验失败不发布半份名单。
func (fw *FireWallEngine) BlockIPList(ips []string) (int, []string, error) {
	if err := fw.AddToIPSet("manual", ips); err != nil {
		return 0, append([]string(nil), ips...), err
	}
	return len(ips), nil, nil
}

// UnblockIPList 批量撤销手工来源，同样不影响其他来源。
func (fw *FireWallEngine) UnblockIPList(ips []string) (int, []string, error) {
	if err := fw.DelFromIPSet("manual", ips); err != nil {
		return 0, append([]string(nil), ips...), err
	}
	return len(ips), nil, nil
}

// GetBlockedIPList 从本应用账本枚举仍有效的手工记录。
func (fw *FireWallEngine) GetBlockedIPList() ([]string, error) {
	b, err := getBPFBackend()
	if err != nil {
		return nil, err
	}
	g, err := b.readGroup("manual")
	if err != nil {
		return nil, err
	}
	result := []string{}
	now := time.Now().Unix()
	for ip, expiry := range g.Entries {
		if expiry == 0 || expiry > now {
			result = append(result, ip)
		}
	}
	sort.Strings(result)
	return result, nil
}

// ClearAllBlockedIPs 仅清理本应用手工组，不清空整机其他安全产品的规则。
func (fw *FireWallEngine) ClearAllBlockedIPs() (int, error) {
	ips, err := fw.GetBlockedIPList()
	if err != nil {
		return 0, err
	}
	if err = fw.FlushIPSet("manual"); err != nil {
		return 0, err
	}
	return len(ips), nil
}

// SyncTimedBlocks 按数据库完整重建手工来源，用于启动重放与显式同步。
func (fw *FireWallEngine) SyncTimedBlocks(entries map[string]int64) error {
	return fw.RestoreTimedIPSet("manual", entries)
}
