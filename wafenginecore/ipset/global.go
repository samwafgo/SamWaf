package ipset

import (
	"net"
	"strings"
	"sync/atomic"
)

const (
	// ThreatIPRulePrefix 威胁情报拦截的统一规则前缀；带渠道名时拼为「威胁情报IP:<渠道名>」。
	ThreatIPRulePrefix = "威胁情报IP"
	// threatIPChannelMaxRunes 标签里单渠道名的最大字符数，确保整串远小于 ip_tags.ip_tag(255) 并在界面可读。
	threatIPChannelMaxRunes = 48
)

// ThreatChannelMatcher 单个启用渠道在内存中的只读编译快照（已应用误报排除名单）。
// 按渠道 Code 升序存放在 ThreatIndex.Channels 中，供引擎拦截溯源与 IP 策略命中查询共享。
type ThreatChannelMatcher struct {
	Code       string    // 渠道短码（稳定排序键）
	Name       string    // 渠道显示名
	LandTarget string    // 落地层：waf | system | both
	Set        *MatchSet // 过滤误报排除名单后的有效集（可为 nil）
}

// ThreatIndex 威胁情报运行态内存索引，构建完成后即只读，通过 atomic.Pointer 做 RCU 整体替换：
//   - WAFUnion 仅包含落地层含 waf(waf/both) 的启用渠道并集，供请求热路径 O(1) 快速否定；
//   - Channels 包含全部启用渠道（含仅 system 层），供命中后定位来源渠道与 IP 策略命中查询复用。
type ThreatIndex struct {
	WAFUnion *MatchSet
	Channels []ThreatChannelMatcher
}

// globalThreatIndex 放进 ipset 这个叶子包，供 wafenginecore(判定读)、service(同步写与查询读) 共用，避免 import cycle。
var globalThreatIndex atomic.Pointer[ThreatIndex]

// SetGlobalThreatIndex 发布新的威胁情报运行态索引（传 nil 表示清空）。由订阅服务调用。
func SetGlobalThreatIndex(idx *ThreatIndex) {
	globalThreatIndex.Store(idx)
}

// GetGlobalThreatIndex 读取当前威胁情报运行态索引（可能为 nil）。
func GetGlobalThreatIndex() *ThreatIndex {
	return globalThreatIndex.Load()
}

// SetGlobalThreatMatcher 发布仅含 WAF 并集的简化索引（传 nil 表示清空），保留向后兼容与单测构造。
func SetGlobalThreatMatcher(m *MatchSet) {
	if m == nil {
		globalThreatIndex.Store(nil)
		return
	}
	globalThreatIndex.Store(&ThreatIndex{WAFUnion: m})
}

// GetGlobalThreatMatcher 读取当前 WAF 层威胁情报并集（可能为 nil）。
func GetGlobalThreatMatcher() *MatchSet {
	idx := globalThreatIndex.Load()
	if idx == nil {
		return nil
	}
	return idx.WAFUnion
}

// MatchWAF 判定 ip 是否命中 WAF 应用层威胁情报，并返回命中的启用渠道列表（按 Code 升序）。
// 99.9%+ 未命中请求仅走一次 WAFUnion.Contains 即刻返回，零额外遍历开销。
func (idx *ThreatIndex) MatchWAF(ip net.IP) (bool, []ThreatChannelMatcher) {
	if idx == nil || ip == nil || idx.WAFUnion == nil || !idx.WAFUnion.Contains(ip) {
		return false, nil
	}
	if len(idx.Channels) == 0 {
		return true, nil
	}
	var hits []ThreatChannelMatcher
	for _, ch := range idx.Channels {
		if ch.LandTarget != "waf" && ch.LandTarget != "both" {
			continue
		}
		if ch.Set != nil && ch.Set.Contains(ip) {
			hits = append(hits, ch)
		}
	}
	return true, hits
}

// SanitizeThreatChannelLabel 把渠道名清洗为安全的标签后缀：
// 去掉控制字符、逗号（防拆裂通知 ExcludeRules 与 GROUP_CONCAT）与 attackTagBadChars/SQL注释符，
// 优先使用渠道显示名 Name，空则回退短码 Code，并按字符数上限截断。
func SanitizeThreatChannelLabel(name, code string) string {
	if cleaned := cleanThreatChannelText(name); cleaned != "" {
		return cleaned
	}
	return cleanThreatChannelText(code)
}

func cleanThreatChannelText(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// 与 waf_ip_tag_log.go 的 IsValidAttackTagExcludeItem 保持同口径，保证产出的 tag 可被排除或删除
	for _, bad := range []string{"--", "/*", "*/", "#"} {
		s = strings.ReplaceAll(s, bad, "")
	}
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		switch r {
		case ',', '，', '\'', '"', '`', ';', '\\':
			continue
		}
		if r == ' ' || r == '\t' {
			if lastSpace {
				continue
			}
			lastSpace = true
			b.WriteByte(' ')
			continue
		}
		lastSpace = false
		b.WriteRune(r)
	}
	cleaned := strings.TrimSpace(b.String())
	if cleaned == "" {
		return ""
	}
	runes := []rune(cleaned)
	if len(runes) > threatIPChannelMaxRunes {
		cleaned = strings.TrimSpace(string(runes[:threatIPChannelMaxRunes]))
	}
	return cleaned
}

// FormatThreatIPRule 根据命中的渠道列表生成日志 RULE / ip_tag 标题。
// 遵循「首命中单渠道」口径（channels 已按 Code 升序）：保持 ip_tags 维度稳定不产生组合膨胀，
// 全量多渠道命中明细由「IP策略命中查询」完整展示。无可用渠道标识时回退为「威胁情报IP」。
func FormatThreatIPRule(channels []ThreatChannelMatcher) string {
	for _, ch := range channels {
		if label := SanitizeThreatChannelLabel(ch.Name, ch.Code); label != "" {
			return ThreatIPRulePrefix + ":" + label
		}
	}
	return ThreatIPRulePrefix
}
