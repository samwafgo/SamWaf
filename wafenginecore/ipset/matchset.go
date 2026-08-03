// Package ipset 提供一个纯内存、零第三方依赖的 IP/CIDR 匹配集合 MatchSet，
// 用于替换 WAF 应用层黑/白名单原先的"线性数组 + 每请求重解析 CIDR"判定（O(N)），
// 使上万~十万条威胁情报 IP 也能在请求热路径做常数级判定：
//   - 单 IP 走 map，精确匹配 O(1)
//   - CIDR 走二进制前缀树 cidrTrie，查询 O(前缀深度) 常数级，且只在构建时解析一次
//
// 注意：本包的 MatchSet 是"进程内内存匹配结构"，与操作系统层面的 ipset(内核)无关，
// 仅共用了"集合"这一概念命名。
package ipset

import (
	"encoding/binary"
	"net"
	"strings"
)

// MatchSet 是一个只读的 IP/CIDR 匹配集合。构建（BuildMatchSet）完成后不再修改，
// 配合引擎 RCU 语义在请求热路径无锁读；热更新通过整体替换指针完成。
type MatchSet struct {
	exact4 map[uint32]struct{}   // 单 IPv4 精确集合
	exact6 map[[16]byte]struct{} // 单 IPv6 精确集合
	cidr4  *cidrTrie             // IPv4 CIDR 前缀树
	cidr6  *cidrTrie             // IPv6 CIDR 前缀树
	count  int                   // 成功收录的条目数（单 IP + CIDR）
}

// BuildMatchSet 由字符串列表构建 MatchSet，元素可为单 IP 或 CIDR，v4/v6 混合。
// 非法条目自动跳过（返回的 count 只统计成功收录的）。十万级构建在后台任务完成，
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

// Add 向集合加入一个单 IP 或 CIDR，成功返回 true，非法格式返回 false。
// 仅用于构建阶段（BuildMatchSet 内部或后台任务），非并发安全。
func (m *MatchSet) Add(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return false
		}
		ones, bits := ipNet.Mask.Size()
		if bits == 32 {
			m.cidr4.insert(ipNet.IP.To4(), ones)
		} else {
			m.cidr6.insert(ipNet.IP.To16(), ones)
		}
		m.count++
		return true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		m.exact4[binary.BigEndian.Uint32(v4)] = struct{}{}
	} else if v6 := ip.To16(); v6 != nil {
		var key [16]byte
		copy(key[:], v6)
		m.exact6[key] = struct{}{}
	} else {
		return false
	}
	m.count++
	return true
}

// Contains 判定 ip 是否命中集合（精确或被某 CIDR 覆盖）。nil 接收者/nil ip 均安全返回 false，
// 便于调用方省略 nil 判空。
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
		return m.cidr4.contains(v4, 32)
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
	return m.cidr6.contains(v6, 128)
}

// ContainsStr 是 Contains 的字符串便捷版，内部做一次 net.ParseIP。
func (m *MatchSet) ContainsStr(ipStr string) bool {
	if m == nil {
		return false
	}
	return m.Contains(net.ParseIP(strings.TrimSpace(ipStr)))
}

// Len 返回成功收录的条目数（单 IP + CIDR）。nil 安全。
func (m *MatchSet) Len() int {
	if m == nil {
		return 0
	}
	return m.count
}
