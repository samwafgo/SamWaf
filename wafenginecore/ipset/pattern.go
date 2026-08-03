package ipset

// pattern.go 是 SamWaf 全局唯一的「IP 模式」解析器，黑/白名单、IP 组、自定义规则共用同一套语法，
// 保证用户在任何入口写下的 IP 表达式语义完全一致。
//
// 支持的语法：
//
//	1.2.3.4                        单 IP（v4/v6）
//	1.2.3.0/24                     CIDR 网段（v4/v6）
//	10.10.*.*                      IPv4 通配符，按八位组，* 可出现在任意位置（10.*.1.* 合法）
//	2001:db8:*:*:*:*:*:*           IPv6 通配符，按 hextet，必须写满 8 段且不能与 :: 混用
//	1.2.3.4-1.2.3.99               闭区间（v4/v6，两端必须同族）
//
// 解析结果 Pattern 是一次性产物：构建期解析一次，热路径只做字节比较，不重复解析字符串。
//
// 安全提醒：本包只负责「语法是否合法」，不负责「语义是否安全」。
// 例如 *.*.*.* 语法合法（等价 0.0.0.0/0），但写进白名单等于全站不设防，
// 该拒绝由写入侧的校验函数负责（见 IsCatchAllWildcard）。

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// PatternKind 模式类型
type PatternKind uint8

const (
	KindInvalid  PatternKind = iota
	KindSingle               // 单 IP
	KindCIDR                 // CIDR 网段
	KindWildcard             // 通配符
	KindRange                // 闭区间
)

// ErrRangeReversed 区间起止顺序颠倒。单列出来是为了让「读取已落库数据」的路径
// 能够自动交换后重试（存量脏数据不静默失效），而写入校验路径仍然严格报错。
var ErrRangeReversed = errors.New("IP区间的起始地址大于结束地址")

// Pattern 是一次解析完成的 IP 模式。构建期产出，热路径只读，不再触碰字符串。
//
// 字段长度约定：Value/Mask/End 长度统一等于 Width（4 或 16）。
//
//	KindSingle   Value=地址，Mask=全 1，Prefix=Width*8
//	KindCIDR     Value=网络地址（已按掩码归零），Mask=掩码，Prefix=掩码位数
//	KindWildcard Value=已按掩码归零的取值，Mask=通配掩码（可能不连续），
//	             Prefix=掩码为「左起连续 1」时的位数，不可降级为 CIDR 时为 -1
//	KindRange    Value=区间起点，End=区间终点（含），Mask=nil，Prefix=-1
type Pattern struct {
	Kind   PatternKind
	Width  int
	Value  []byte
	Mask   []byte
	End    []byte
	Prefix int
	Raw    string
}

// ParsePattern 严格解析一个 IP 模式。用于「写入校验」路径（API 入参、组条目录入）。
//
// 分派顺序（进入某分支后不再回退）：含 '-' → 区间；含 '*' → 通配；含 '/' → CIDR；否则单 IP。
func ParsePattern(raw string) (Pattern, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Pattern{}, errors.New("IP不能为空")
	}
	switch {
	case strings.Contains(s, "-"):
		return parseRange(s)
	case strings.Contains(s, "*"):
		return parseWildcard(s)
	case strings.Contains(s, "/"):
		return parseCIDR(s)
	default:
		return parseSingle(s)
	}
}

// ParsePatternLenient 与 ParsePattern 相同，但对「区间起止顺序颠倒」自动交换后重试。
//
// 用于「读取已落库数据」的场景（构建匹配集、规则求值）：这些数据可能是历史版本写入的，
// 当时没有格式校验。宽容解析保证它们继续按用户本意生效，而不是静默失效。
// 写入路径请用严格的 ParsePattern。
func ParsePatternLenient(raw string) (Pattern, error) {
	p, err := ParsePattern(raw)
	if err == nil || !errors.Is(err, ErrRangeReversed) {
		return p, err
	}
	parts := strings.SplitN(strings.TrimSpace(raw), "-", 2)
	return ParsePattern(strings.TrimSpace(parts[1]) + "-" + strings.TrimSpace(parts[0]))
}

// IsValidPattern 校验一个 IP 模式是否合法，返回 (是否合法, 不合法时的中文原因)。
// 供 utils / API 层复用，语义与 ParsePattern 一致（严格）。
func IsValidPattern(raw string) (bool, string) {
	if _, err := ParsePattern(raw); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// IsCatchAllWildcard 判断一个模式是否会「匹配该协议族的所有地址」，且写法不够显眼。
//
// 覆盖两种写法：
//   - 全通配：*.*.*.*、8 段全 * 的 IPv6
//   - 全空间区间：0.0.0.0-255.255.255.255、::-ffff:...:ffff
//
// 这类模式语法合法（等价 0.0.0.0/0 与 ::/0），但极易误写——白名单写成 *.*.*.*
// 等于全站不设防，黑名单写成它等于封禁所有人。写入侧应当拒绝并提示用户改写成
// 显式的 0.0.0.0/0，让「我确实要匹配全部」这个意图在配置里一眼可见。
//
// 显式的 0.0.0.0/0 / ::/0 不在此列：用户那样写就是明确表达了全匹配。
func IsCatchAllWildcard(raw string) bool {
	p, err := ParsePattern(raw)
	if err != nil {
		return false
	}
	switch p.Kind {
	case KindWildcard:
		return p.Prefix == 0
	case KindRange:
		// 起点全 0 且终点全 F，即覆盖整个地址空间
		for _, b := range p.Value {
			if b != 0x00 {
				return false
			}
		}
		for _, b := range p.End {
			if b != 0xff {
				return false
			}
		}
		return true
	}
	return false
}

// Match 判定 ip 是否命中本模式。nil ip 安全返回 false。
// v4 与 v6 严格隔离：v4 模式不会命中 v6 地址，反之亦然。
func (p Pattern) Match(ip net.IP) bool {
	if ip == nil || p.Kind == KindInvalid {
		return false
	}
	var b []byte
	if v4 := ip.To4(); v4 != nil {
		if p.Width != 4 {
			return false
		}
		b = v4
	} else {
		v6 := ip.To16()
		if v6 == nil || p.Width != 16 {
			return false
		}
		b = v6
	}
	switch p.Kind {
	case KindSingle:
		return bytes.Equal(b, p.Value)
	case KindCIDR, KindWildcard:
		for i := 0; i < p.Width; i++ {
			if b[i]&p.Mask[i] != p.Value[i] {
				return false
			}
		}
		return true
	case KindRange:
		return bytes.Compare(b, p.Value) >= 0 && bytes.Compare(b, p.End) <= 0
	}
	return false
}

// ---------- 分支解析 ----------

func parseSingle(s string) (Pattern, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return Pattern{}, fmt.Errorf("不是合法的IP地址: %s", s)
	}
	value, width := normalizeIP(ip)
	mask := make([]byte, width)
	for i := range mask {
		mask[i] = 0xff
	}
	return Pattern{Kind: KindSingle, Width: width, Value: value, Mask: mask, Prefix: width * 8, Raw: s}, nil
}

func parseCIDR(s string) (Pattern, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return Pattern{}, fmt.Errorf("不是合法的CIDR网段: %s", s)
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return Pattern{}, fmt.Errorf("CIDR掩码不规范: %s", s)
	}
	// 宽度沿用与历史实现一致的判定（按掩码位宽而非地址形态），
	// 保证 ::ffff:1.2.3.0/120 这类 v4-mapped 写法的归属不发生变化。
	width := bits / 8
	var value []byte
	if width == 4 {
		v4 := ipNet.IP.To4()
		if v4 == nil {
			return Pattern{}, fmt.Errorf("不是合法的CIDR网段: %s", s)
		}
		value = append([]byte(nil), v4...)
	} else {
		value = append([]byte(nil), ipNet.IP.To16()...)
	}
	mask := make([]byte, width)
	copy(mask, ipNet.Mask)
	return Pattern{Kind: KindCIDR, Width: width, Value: value, Mask: mask, Prefix: ones, Raw: s}, nil
}

func parseRange(s string) (Pattern, error) {
	parts := strings.SplitN(s, "-", 2)
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	if strings.ContainsAny(left, "*/") || strings.ContainsAny(right, "*/") {
		return Pattern{}, fmt.Errorf("IP区间的两端必须是单个IP，不能带通配符或掩码: %s", s)
	}
	ipA := net.ParseIP(left)
	ipB := net.ParseIP(right)
	if ipA == nil || ipB == nil {
		return Pattern{}, fmt.Errorf("IP区间格式应为 起始IP-结束IP: %s", s)
	}
	startVal, startWidth := normalizeIP(ipA)
	endVal, endWidth := normalizeIP(ipB)
	if startWidth != endWidth {
		return Pattern{}, fmt.Errorf("IP区间的起止地址必须同为IPv4或同为IPv6: %s", s)
	}
	switch bytes.Compare(startVal, endVal) {
	case 1:
		return Pattern{}, fmt.Errorf("%w: %s", ErrRangeReversed, s)
	case 0:
		// 起止相同，退化为单 IP，避免走区间分解的开销
		mask := make([]byte, startWidth)
		for i := range mask {
			mask[i] = 0xff
		}
		return Pattern{Kind: KindSingle, Width: startWidth, Value: startVal, Mask: mask, Prefix: startWidth * 8, Raw: s}, nil
	}
	return Pattern{Kind: KindRange, Width: startWidth, Value: startVal, End: endVal, Prefix: -1, Raw: s}, nil
}

func parseWildcard(s string) (Pattern, error) {
	if strings.Contains(s, "/") {
		return Pattern{}, fmt.Errorf("通配符不能与掩码 / 混用，请二选一: %s", s)
	}
	if strings.Contains(s, ":") {
		return parseWildcardV6(s)
	}
	return parseWildcardV4(s)
}

func parseWildcardV4(s string) (Pattern, error) {
	segs := strings.Split(s, ".")
	if len(segs) != 4 {
		return Pattern{}, fmt.Errorf("IPv4通配符必须是4段，如 10.10.*.*: %s", s)
	}
	value := make([]byte, 4)
	mask := make([]byte, 4)
	for i, seg := range segs {
		if seg == "*" {
			continue // value/mask 保持 0，代表该段任意
		}
		if strings.Contains(seg, "*") {
			return Pattern{}, fmt.Errorf("IPv4通配符只支持整段通配（如 10.10.*.*），不支持段内部分通配: %s", s)
		}
		if len(seg) > 1 && seg[0] == '0' {
			return Pattern{}, fmt.Errorf("IPv4通配符的数字段不允许前导零: %s", s)
		}
		v, err := strconv.ParseUint(seg, 10, 8)
		if err != nil {
			return Pattern{}, fmt.Errorf("IPv4通配符的每段必须是 * 或 0-255 的数字: %s", s)
		}
		value[i] = byte(v)
		mask[i] = 0xff
	}
	return Pattern{Kind: KindWildcard, Width: 4, Value: value, Mask: mask, Prefix: maskPrefixLen(mask), Raw: s}, nil
}

func parseWildcardV6(s string) (Pattern, error) {
	// :: 压缩与 * 混用会产生歧义（:: 省略的段数未知，无法确定 * 的位置），一律拒绝
	if strings.Contains(s, "::") {
		return Pattern{}, fmt.Errorf("IPv6通配符不能与 :: 压缩混用，必须写满8段: %s", s)
	}
	segs := strings.Split(s, ":")
	if len(segs) != 8 {
		return Pattern{}, fmt.Errorf("IPv6通配符必须写满8段，如 2001:db8:*:*:*:*:*:*: %s", s)
	}
	value := make([]byte, 16)
	mask := make([]byte, 16)
	for i, seg := range segs {
		if seg == "*" {
			continue
		}
		if strings.Contains(seg, "*") {
			return Pattern{}, fmt.Errorf("IPv6通配符只支持整段通配，不支持段内部分通配: %s", s)
		}
		if strings.Contains(seg, ".") {
			return Pattern{}, fmt.Errorf("IPv6通配符不支持内嵌IPv4写法: %s", s)
		}
		if len(seg) == 0 || len(seg) > 4 {
			return Pattern{}, fmt.Errorf("IPv6通配符的每段必须是 * 或 1-4 位十六进制: %s", s)
		}
		v, err := strconv.ParseUint(seg, 16, 16)
		if err != nil {
			return Pattern{}, fmt.Errorf("IPv6通配符的每段必须是 * 或 1-4 位十六进制: %s", s)
		}
		value[i*2] = byte(v >> 8)
		value[i*2+1] = byte(v)
		mask[i*2] = 0xff
		mask[i*2+1] = 0xff
	}
	return Pattern{Kind: KindWildcard, Width: 16, Value: value, Mask: mask, Prefix: maskPrefixLen(mask), Raw: s}, nil
}

// ---------- 工具 ----------

// normalizeIP 把 net.IP 归一成「4 字节 v4」或「16 字节 v6」，并返回宽度。
func normalizeIP(ip net.IP) ([]byte, int) {
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...), 4
	}
	return append([]byte(nil), ip.To16()...), 16
}

// maskPrefixLen 若掩码是「左起连续 1」则返回 1 的位数（可降级为 CIDR 走前缀树快路径），
// 否则返回 -1（如 10.*.1.* 的掩码 ff00ff00 不连续，只能走线性匹配）。
func maskPrefixLen(mask []byte) int {
	prefix := 0
	seenZero := false
	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			if (b>>uint(i))&1 == 1 {
				if seenZero {
					return -1
				}
				prefix++
			} else {
				seenZero = true
			}
		}
	}
	return prefix
}

// ---------- 解析缓存（供规则引擎热路径使用）----------

// 规则文本里的 pattern 是静态的、集合有界，缓存命中率接近 100%。
// 上限用于挡住「规则里拿用户输入当 pattern」这类误用导致的无界增长。
const patternCacheMax = 4096

var (
	patternCache  sync.Map // string -> Pattern（Kind==KindInvalid 表示该串解析失败，同样缓存以避免反复解析）
	patternCacheN atomic.Int64
)

func lookupPattern(raw string) Pattern {
	if v, ok := patternCache.Load(raw); ok {
		return v.(Pattern)
	}
	p, err := ParsePatternLenient(raw)
	if err != nil {
		p = Pattern{Kind: KindInvalid, Raw: raw}
	}
	if patternCacheN.Load() < patternCacheMax {
		if _, loaded := patternCache.LoadOrStore(raw, p); !loaded {
			patternCacheN.Add(1)
		}
	}
	return p
}

// MatchPatternCached 带解析缓存的单次匹配，供规则引擎（每请求求值）使用。
func MatchPatternCached(ip net.IP, raw string) bool {
	return lookupPattern(strings.TrimSpace(raw)).Match(ip)
}

// MatchPatternStrCached 是 MatchPatternCached 的字符串便捷版。
func MatchPatternStrCached(ipStr, raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	return lookupPattern(strings.TrimSpace(raw)).Match(ip)
}
