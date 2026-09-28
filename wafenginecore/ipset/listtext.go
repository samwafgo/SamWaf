package ipset

import "strings"

// 「IP 清单文本」的统一解析。
//
// 放在 ipset 这个叶子包的理由和 groups.go 一样：**判定侧与查询侧必须用同一套解析**。
// 引擎按它决定「这个请求记不记日志」，IP归属查询按它回答「这个 IP 为什么没有日志」——
// 两边各写一份，早晚会在某个边角（大小写、空格、逗号换行混用）分叉，
// 而那种分叉的表现是「界面说没排除，实际排除了」，最难查。

// listGroupPrefix 引用 IP 组的前缀
const listGroupPrefix = "group:"

// ParseListText 把一段清单文本拆成 IP 模式与组短码两组。
//
// 行格式：单IP / CIDR / 通配符 / 区间（语法同 MatchSet），或 group:组短码；
// `#` 开头是注释，空行跳过，逗号与换行都算分隔。组短码去重且保持出现顺序。
func ParseListText(raw string) (patterns []string, groupCodes []string) {
	seen := map[string]struct{}{}
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) >= len(listGroupPrefix) && strings.EqualFold(line[:len(listGroupPrefix)], listGroupPrefix) {
			code := strings.TrimSpace(line[len(listGroupPrefix):])
			if code == "" {
				continue
			}
			if _, dup := seen[code]; !dup {
				seen[code] = struct{}{}
				groupCodes = append(groupCodes, code)
			}
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, groupCodes
}

// BuildFromListText 编译清单文本里的 IP 模式（不含组引用）；没有模式时返回 nil。
func BuildFromListText(raw string) *MatchSet {
	patterns, _ := ParseListText(raw)
	if len(patterns) == 0 {
		return nil
	}
	return BuildMatchSet(patterns)
}

// GroupCodesOf 取出清单文本里引用的组短码（去重保序）。
func GroupCodesOf(raw string) []string {
	_, codes := ParseListText(raw)
	return codes
}
