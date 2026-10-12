package accessgate

import "strings"

// pathmatch.go 是「按路径开启」类功能的通用路径模式匹配器。
//
// 与 MatchPathPrefix（纯前缀白名单）的区别：这里的条目允许写 `*` 通配符，
// 供「网站密码访问」的 include/exclude 路径清单使用。两个函数并存、语义各自独立：
// Access 白名单保持纯前缀行为不变，本文件不回头影响它。

const (
	// pathPatternMaxEntries / pathPatternMaxLen 限制单站点清单的规模。
	// 匹配发生在每个受保护请求的热路径上，清单无上限等于让用户自己决定引擎的开销。
	pathPatternMaxEntries = 50
	pathPatternMaxLen     = 256
)

// BuildPathPatterns 把用户填的多行文本解析成可匹配的模式列表。
// 接受换行与逗号分隔；去空白、转小写、丢弃空条目、补前导 /；
// 每条截断到 256 字符、整表截断到 50 条（截断只影响匹配能力，不影响安全性）。
func BuildPathPatterns(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	replaced := strings.NewReplacer("\r\n", "\n", "\r", "\n", ",", "\n").Replace(raw)
	var out []string
	for _, line := range strings.Split(replaced, "\n") {
		if len(out) >= pathPatternMaxEntries {
			break
		}
		item := strings.ToLower(strings.TrimSpace(line))
		if item == "" {
			continue
		}
		// 路径都以 / 开头（*.php 归一成 /*.php 后语义不变：请求路径必然带前导 /）
		if !strings.HasPrefix(item, "/") {
			item = "/" + item
		}
		if len(item) > pathPatternMaxLen {
			item = item[:pathPatternMaxLen]
		}
		out = append(out, item)
	}
	return out
}

// MatchPathPatterns 判断已归一化的请求路径 p 是否命中模式列表。
//
// 双语义，由条目自己决定：
//   - 不含 *：段边界前缀，与 MatchPathPrefix 同款——/admin 命中 /admin 与 /admin/**，
//     不误伤 /adminconsole。这是默认写法，用户填的绝大多数是这种。
//   - 含 *：全路径通配，* 可跨 /（/api/*/private、*.php、/admin*）。
//     用户显式写了 * 就等于放弃段边界保护，按字面通配。
//
// 调用方须先把 p 归一化（小写 + path.Clean），与 MatchPathPrefix 的约定一致。
func MatchPathPatterns(p string, list []string) bool {
	for _, item := range list {
		if item == "" {
			continue
		}
		if strings.Contains(item, "*") {
			if globMatch(item, p) {
				return true
			}
			continue
		}
		// 尾斜杠归一化 + 段边界比对，逻辑与 MatchPathPrefix 单条一致
		item = strings.TrimRight(item, "/")
		if item == "" {
			return true // 用户显式写了单个 "/"，语义就是全部路径
		}
		if p == item || strings.HasPrefix(p, item+"/") {
			return true
		}
	}
	return false
}

// globMatch 只支持 * 一种元字符的全路径通配匹配（* 可跨 /）。
//
// 刻意用双指针贪心+回退而不是 regexp.Compile：多个 * 的正则会产生灾难性回溯，
// 而这个算法是线性的，模式再长也不会让一个请求把引擎拖死。
func globMatch(pattern, s string) bool {
	si, pi := 0, 0
	starIdx, matchIdx := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			starIdx = pi
			matchIdx = si
			pi++
		case pi < len(pattern) && pattern[pi] == s[si]:
			si++
			pi++
		case starIdx != -1:
			// 当前位置失配，回退到最近一个 * 的下一位，让它多吃一个字符
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
