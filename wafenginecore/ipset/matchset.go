// Package ipset 提供一个纯内存、零第三方依赖的 IP 匹配集合 MatchSet，
// 用于替换 WAF 应用层黑/白名单原先的"线性数组 + 每请求重解析 CIDR"判定（O(N)），
// 使上万~十万条威胁情报 IP 也能在请求热路径做常数级判定：
//   - 单 IP 走 map，精确匹配 O(1)
//   - CIDR 走二进制前缀树 cidrTrie，查询 O(前缀深度) 常数级，且只在构建时解析一次
//   - 通配符若掩码连续（如 10.10.*.*）降级为 CIDR 走前缀树；不连续（如 10.*.1.*）走线性表
//   - 闭区间精确分解为 CIDR（IPv4 ≤ 62 条）后同样走前缀树
//
// 支持的语法见 pattern.go。注意：本包的 MatchSet 是"进程内内存匹配结构"，
// 与操作系统层面的 ipset(内核)无关，仅共用了"集合"这一概念命名。
package ipset

import (
	"encoding/binary"
	"net"
	"strings"
)

// maskPattern 是掩码不连续、无法降级为 CIDR 的通配符（如 10.*.1.*）。
// 这类模式只能逐条做 (ip & mask) == value 比较，因此单独放线性表。
// 正常配置里数量极少；数量失控时由上层根据 Stats 告警。
type maskPattern struct {
	value [16]byte
	mask  [16]byte
	width int // 4 或 16，只比较前 width 个字节
}

// Stats 记录集合的构成，便于上层观测「用户写了什么、有多少被丢弃」。
type Stats struct {
	Exact    int // 单 IP
	CIDR     int // CIDR 网段
	Wildcard int // 通配符
	Range    int // 闭区间
	Dropped  int // 解析失败被丢弃
}

// MatchSet 是一个只读的 IP 匹配集合。构建（BuildMatchSet）完成后不再修改，
// 配合引擎 RCU 语义在请求热路径无锁读；热更新通过整体替换指针完成。
type MatchSet struct {
	exact4 map[uint32]struct{}   // 单 IPv4 精确集合
	exact6 map[[16]byte]struct{} // 单 IPv6 精确集合
	cidr4  *cidrTrie             // IPv4 CIDR 前缀树（含连续掩码通配符、区间分解结果）
	cidr6  *cidrTrie             // IPv6 CIDR 前缀树
	wild4  []maskPattern         // IPv4 不连续掩码通配符
	wild6  []maskPattern         // IPv6 不连续掩码通配符
	count  int                   // 成功收录的条目数
	stats  Stats
}

// BuildMatchSet 由字符串列表构建 MatchSet，元素可为单 IP / CIDR / 通配符 / 区间，v4/v6 混合。
// 非法条目自动跳过（计入 Stats().Dropped）。十万级构建在后台任务完成，
// 不应在请求热路径调用。
func BuildMatchSet(items []string) *MatchSet {
	m := &MatchSet{
		exact4: make(map[uint32]struct{}),
		exact6: make(map[[16]byte]struct{}),
		cidr4:  newCIDRTrie(),
		cidr6:  newCIDRTrie(),
	}
	for _, raw := range items {
		m.Add(raw)
	}
	return m
}

// Add 向集合加入一个 IP 模式（单 IP / CIDR / 通配符 / 区间），成功返回 true，非法格式返回 false。
// 仅用于构建阶段（BuildMatchSet 内部或后台任务），非并发安全。
//
// 这里用宽容解析（ParsePatternLenient）：集合的数据来自已落库内容，
// 历史版本没有写入校验，起止颠倒的区间应当按用户本意生效而不是静默失效。
func (m *MatchSet) Add(raw string) bool {
	p, err := ParsePatternLenient(raw)
	if err != nil {
		m.stats.Dropped++
		return false
	}
	switch p.Kind {
	case KindSingle:
		if p.Width == 4 {
			m.exact4[binary.BigEndian.Uint32(p.Value)] = struct{}{}
		} else {
			var key [16]byte
			copy(key[:], p.Value)
			m.exact6[key] = struct{}{}
		}
		m.stats.Exact++
	case KindCIDR:
		m.insertPrefix(p.Width, p.Value, p.Prefix)
		m.stats.CIDR++
	case KindWildcard:
		if p.Prefix >= 0 {
			// 掩码左起连续 → 与等价 CIDR 落进同一棵前缀树同一节点（10.*.*.* ≡ 10.0.0.0/8）
			m.insertPrefix(p.Width, p.Value, p.Prefix)
		} else {
			var wp maskPattern
			copy(wp.value[:], p.Value)
			copy(wp.mask[:], p.Mask)
			wp.width = p.Width
			if p.Width == 4 {
				m.wild4 = append(m.wild4, wp)
			} else {
				m.wild6 = append(m.wild6, wp)
			}
		}
		m.stats.Wildcard++
	case KindRange:
		for _, pe := range rangeToPrefixes(p.Value, p.End) {
			m.insertPrefix(p.Width, pe.Net, pe.Bits)
		}
		m.stats.Range++
	default:
		m.stats.Dropped++
		return false
	}
	m.count++
	return true
}

func (m *MatchSet) insertPrefix(width int, netBytes []byte, bits int) {
	if width == 4 {
		m.cidr4.insert(netBytes, bits)
	} else {
		m.cidr6.insert(netBytes, bits)
	}
}

// Contains 判定 ip 是否命中集合（精确命中、被某 CIDR 覆盖、或命中不连续掩码通配符）。
// nil 接收者/nil ip 均安全返回 false，便于调用方省略 nil 判空。
//
// 判定顺序按代价递增短路：exact map(O(1)) → 前缀树(O(前缀深度)) → 通配符线性表。
// v4 与 v6 严格隔离，不会互相命中。
//
// ⚠️ 维护提醒：三个分支都必须是「命中即 return true」，最后才 return，
// 不能把某一层写成 `return m.cidr4.contains(...)` 直接收口——那样后面的通配符
// 线性表永远不会被检查到（TestMatchSetContainsOrderNotShortCircuited 钉死此点）。
func (m *MatchSet) Contains(ip net.IP) bool {
	if m == nil || ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if len(m.exact4) > 0 {
			if _, ok := m.exact4[binary.BigEndian.Uint32(v4)]; ok {
				return true
			}
		}
		if m.cidr4.contains(v4, 32) {
			return true
		}
		return matchWildcards(m.wild4, v4)
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	if len(m.exact6) > 0 {
		var key [16]byte
		copy(key[:], v6)
		if _, ok := m.exact6[key]; ok {
			return true
		}
	}
	if m.cidr6.contains(v6, 128) {
		return true
	}
	return matchWildcards(m.wild6, v6)
}

func matchWildcards(list []maskPattern, b []byte) bool {
	for i := range list {
		w := &list[i]
		hit := true
		for j := 0; j < w.width; j++ {
			if b[j]&w.mask[j] != w.value[j] {
				hit = false
				break
			}
		}
		if hit {
			return true
		}
	}
	return false
}

// ContainsStr 是 Contains 的字符串便捷版，内部做一次 net.ParseIP。
func (m *MatchSet) ContainsStr(ipStr string) bool {
	if m == nil {
		return false
	}
	return m.Contains(net.ParseIP(strings.TrimSpace(ipStr)))
}

// Len 返回成功收录的条目数。nil 安全。
func (m *MatchSet) Len() int {
	if m == nil {
		return 0
	}
	return m.count
}

// Stats 返回集合构成统计（各类型条数与丢弃数）。nil 安全。
func (m *MatchSet) Stats() Stats {
	if m == nil {
		return Stats{}
	}
	return m.stats
}

// WildcardLen 返回走线性匹配的通配符条数。上层可据此告警：
// 数量过大说明用户应改用 CIDR 表达，否则每次未命中都要线性扫完。
func (m *MatchSet) WildcardLen() int {
	if m == nil {
		return 0
	}
	return len(m.wild4) + len(m.wild6)
}

// HasWildcard 集合内是否含通配符或区间。系统防火墙(iptables/netsh)不认这些语法，
// 上层据此判断能否把集合下发到系统层。nil 安全。
func (m *MatchSet) HasWildcard() bool {
	if m == nil {
		return false
	}
	return m.stats.Wildcard > 0 || m.stats.Range > 0
}
