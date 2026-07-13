package utils

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// 规则动作
const (
	RuleActionDeny  = "deny"  // 拦截（默认）
	RuleActionAllow = "allow" // 放行
	RuleActionLog   = "log"   // 仅记录
)

// 可跳过的检测模块名（Allow 的参数只接受这些值，大小写不敏感）
const (
	RuleSkipAll = "ALL"
)

// ruleSkipModules 允许被跳过的检测模块白名单
// 注意：跳过只对"排在自定义规则之后"的检测环节生效，具体取决于规则编排模式
var ruleSkipModules = []string{
	"BOT",       // 爬虫检测
	"SQLI",      // SQL注入
	"XSS",       // XSS
	"SCAN",      // 扫描工具
	"RCE",       // 远程命令执行
	"DIR",       // 目录穿越
	"CC",        // CC防护
	"AI",        // AI智能检测
	"SENSITIVE", // 敏感词
	"OWASP",     // OWASP规则集
	"ANTILEECH", // 防盗链
	"CSRF",      // CSRF
	"UPLOAD",    // 文件上传检测
	"CAPTCHA",   // 验证码
	RuleSkipAll, // 全部
}

var ruleSkipModuleSet = func() map[string]bool {
	m := make(map[string]bool, len(ruleSkipModules))
	for _, v := range ruleSkipModules {
		m[v] = true
	}
	return m
}()

// RuleSkipModules 返回允许跳过的模块名列表（供接口/前端提示使用）
func RuleSkipModules() []string {
	out := make([]string, len(ruleSkipModules))
	copy(out, ruleSkipModules)
	return out
}

// RuleActionInfo 一条规则的动作信息
type RuleActionInfo struct {
	Action      string   // deny / allow / log
	SkipModules []string // 仅 allow 有效，元素为大写模块名；含 "ALL" 表示跳过全部
}

// SkipAll 是否跳过后续所有检测
func (info RuleActionInfo) SkipAll() bool {
	for _, m := range info.SkipModules {
		if m == RuleSkipAll {
			return true
		}
	}
	return false
}

var (
	// 规则块起始：rule 规则名
	ruleBlockRegex = regexp.MustCompile(`(?m)\brule\s+([A-Za-z0-9_]+)`)
	// then 关键字
	ruleThenRegex = regexp.MustCompile(`\bthen\b`)
	// 动作标记：RF.Allow(...) / RF.AllowAll() / RF.Deny() / RF.Log()
	ruleActionRegex = regexp.MustCompile(`RF\s*\.\s*(AllowAll|Allow|Deny|Log)\s*\(([^)]*)\)`)
)

// BuildGrlSkeleton 生成规则文本的"骨架"：把字符串字面量和注释里的内容全部替换成空格，
// 其余字符原样保留，输出与输入等长（按字节），因此骨架上的位置可以直接对应到原文。
//
// 这是动作解析的安全基础。规则文本里混着用户可控内容（比如 MF.URL.Contains("...") 里的值
// 可能直接来自攻击者的请求），如果直接拿正则去原文里找 RF.Deny()，攻击者只要在值里写一段
// 假的动作标记就能骗过解析，出现"保存时看到的是拦截、运行时按放行执行"的认知差。
// 在骨架上定位就不会被字符串字面量和注释里的内容欺骗。
//
// 词法参照 grule 的 grulev3.g4：
//
//	DQUOTA_STRING : '"'  ( '\\'. | '""'   | ~('"' |'\\') )* '"'
//	SQUOTA_STRING : '\'' ( '\\'. | '\'\'' | ~('\''|'\\') )* '\''
func BuildGrlSkeleton(ruleText string) string {
	src := []byte(ruleText)
	out := make([]byte, len(src))

	const (
		stCode = iota
		stDQuote
		stSQuote
		stLineComment
		stBlockComment
	)
	state := stCode

	blank := func(i int) {
		// 保留换行，方便按行定位；其余一律变空格
		if src[i] == '\n' || src[i] == '\r' {
			out[i] = src[i]
		} else {
			out[i] = ' '
		}
	}

	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case stCode:
			switch {
			case c == '"':
				out[i] = c // 引号本身保留，方便取参数时定位
				state = stDQuote
			case c == '\'':
				out[i] = c
				state = stSQuote
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				blank(i)
				state = stLineComment
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				blank(i)
				state = stBlockComment
			default:
				out[i] = c
			}
		case stDQuote:
			if c == '\\' && i+1 < len(src) {
				// 转义序列：两个字符都吃掉
				blank(i)
				i++
				blank(i)
				continue
			}
			if c == '"' {
				// 连续两个双引号是转义写法 ""，不是结束
				if i+1 < len(src) && src[i+1] == '"' {
					blank(i)
					i++
					blank(i)
					continue
				}
				out[i] = c
				state = stCode
				continue
			}
			blank(i)
		case stSQuote:
			if c == '\\' && i+1 < len(src) {
				blank(i)
				i++
				blank(i)
				continue
			}
			if c == '\'' {
				if i+1 < len(src) && src[i+1] == '\'' {
					blank(i)
					i++
					blank(i)
					continue
				}
				out[i] = c
				state = stCode
				continue
			}
			blank(i)
		case stLineComment:
			if c == '\n' {
				out[i] = c
				state = stCode
				continue
			}
			blank(i)
		case stBlockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				blank(i)
				i++
				blank(i)
				state = stCode
				continue
			}
			blank(i)
		}
	}
	return string(out)
}

// ruleBlock 规则块在文本中的位置
type ruleBlock struct {
	Name  string // 规则名（含 R 前缀），与 ast.RuleEntry.RuleName 一致
	Start int    // 在原文中的起始位置
	End   int    // 在原文中的结束位置（下一条规则的起点，或文本末尾）
}

// splitRuleBlocks 在骨架上按 rule 关键字切分规则块
func splitRuleBlocks(skeleton string) []ruleBlock {
	locs := ruleBlockRegex.FindAllStringSubmatchIndex(skeleton, -1)
	blocks := make([]ruleBlock, 0, len(locs))
	for i, loc := range locs {
		end := len(skeleton)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		blocks = append(blocks, ruleBlock{
			Name:  skeleton[loc[2]:loc[3]],
			Start: loc[0],
			End:   end,
		})
	}
	return blocks
}

// parseActionArgs 解析动作参数，返回大写去重后的模块名列表和非法模块名列表
// argsRaw 取自原文（骨架里字符串内容已被抹空），形如: "CC", "AI"
func parseActionArgs(argsRaw string) (modules []string, invalid []string) {
	seen := make(map[string]bool)
	for _, part := range strings.Split(argsRaw, ",") {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		// 去掉包裹的引号
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if !ruleSkipModuleSet[v] {
			invalid = append(invalid, v)
			continue
		}
		if !seen[v] {
			seen[v] = true
			modules = append(modules, v)
		}
	}
	sort.Strings(modules)
	return modules, invalid
}

// extractBlockAction 解析单个规则块的动作
// 只扫描 then 之后的部分，避免 when 里的内容干扰
func extractBlockAction(skeletonBlock, rawBlock string) (info RuleActionInfo, count int, invalid []string) {
	info = RuleActionInfo{Action: RuleActionDeny}

	thenLoc := ruleThenRegex.FindStringIndex(skeletonBlock)
	if thenLoc == nil {
		return info, 0, nil
	}
	offset := thenLoc[1]
	matches := ruleActionRegex.FindAllStringSubmatchIndex(skeletonBlock[offset:], -1)
	if len(matches) == 0 {
		return info, 0, nil
	}

	for i, m := range matches {
		fnName := skeletonBlock[offset+m[2] : offset+m[3]]
		// 参数从原文同位置取（骨架里字符串内容已被抹空）
		argsRaw := ""
		if m[4] >= 0 && offset+m[5] <= len(rawBlock) {
			argsRaw = rawBlock[offset+m[4] : offset+m[5]]
		}

		var cur RuleActionInfo
		switch fnName {
		case "Deny":
			cur = RuleActionInfo{Action: RuleActionDeny}
		case "Log":
			cur = RuleActionInfo{Action: RuleActionLog}
		case "AllowAll":
			cur = RuleActionInfo{Action: RuleActionAllow, SkipModules: []string{RuleSkipAll}}
		case "Allow":
			mods, bad := parseActionArgs(argsRaw)
			invalid = append(invalid, bad...)
			cur = RuleActionInfo{Action: RuleActionAllow, SkipModules: mods}
		}
		// 多个标记时以第一个为准
		if i == 0 {
			info = cur
		}
	}
	return info, len(matches), invalid
}

// ExtractRuleActions 从规则文本中解析出每条规则的动作
// 支持一段文本包含多条规则。没有声明动作的规则不会出现在结果里（查不到即默认拦截）。
// 运行期使用：宽容处理，多个动作标记取第一个，非法模块名忽略。
func ExtractRuleActions(ruleText string) map[string]RuleActionInfo {
	result := make(map[string]RuleActionInfo)
	skeleton := BuildGrlSkeleton(ruleText)
	for _, block := range splitRuleBlocks(skeleton) {
		info, count, _ := extractBlockAction(skeleton[block.Start:block.End], ruleText[block.Start:block.End])
		if count == 0 {
			continue
		}
		result[block.Name] = info
	}
	return result
}

// ExtractRuleActionForCheck 保存规则时的动作校验（严格模式）
// 返回该规则的动作；发现下列情况直接报错：
//   - 声明了多个不同的动作标记
//   - Allow 的参数里有不认识的模块名
func ExtractRuleActionForCheck(ruleText string) (RuleActionInfo, error) {
	skeleton := BuildGrlSkeleton(ruleText)
	blocks := splitRuleBlocks(skeleton)
	if len(blocks) == 0 {
		return RuleActionInfo{Action: RuleActionDeny}, fmt.Errorf("未找到规则定义")
	}

	info := RuleActionInfo{Action: RuleActionDeny}
	for _, block := range blocks {
		skeletonBlock := skeleton[block.Start:block.End]
		blockInfo, count, invalid := extractBlockAction(skeletonBlock, ruleText[block.Start:block.End])
		if len(invalid) > 0 {
			return info, fmt.Errorf("规则动作 RF.Allow 参数中存在无法识别的检测模块: %s，可用模块: %s",
				strings.Join(invalid, ", "), strings.Join(ruleSkipModules, ", "))
		}
		if count > 1 {
			// 多个标记：只要动作语义不完全一致就报错
			if !hasSingleAction(skeletonBlock) {
				return info, fmt.Errorf("规则 %s 中声明了多个不同的动作，一条规则只能有一个动作(RF.Deny/RF.Allow/RF.Log)", block.Name)
			}
		}
		info = blockInfo
	}
	return info, nil
}

// hasSingleAction 判断规则块里的多个动作标记是否语义一致（完全相同的调用视为重复书写，允许）
func hasSingleAction(skeletonBlock string) bool {
	thenLoc := ruleThenRegex.FindStringIndex(skeletonBlock)
	if thenLoc == nil {
		return true
	}
	matches := ruleActionRegex.FindAllString(skeletonBlock[thenLoc[1]:], -1)
	if len(matches) <= 1 {
		return true
	}
	first := strings.Join(strings.Fields(matches[0]), "")
	for _, m := range matches[1:] {
		if strings.Join(strings.Fields(m), "") != first {
			return false
		}
	}
	return true
}

// CountRuleBlocks 统计规则文本里有几条规则（用于保存时限制"一条规则内容只能有一条规则"）
func CountRuleBlocks(ruleText string) int {
	return len(splitRuleBlocks(BuildGrlSkeleton(ruleText)))
}

// ExtractRuleNamesFromText 提取规则文本中所有规则名（含 R 前缀）
func ExtractRuleNamesFromText(ruleText string) []string {
	blocks := splitRuleBlocks(BuildGrlSkeleton(ruleText))
	names := make([]string, 0, len(blocks))
	for _, b := range blocks {
		names = append(names, b.Name)
	}
	return names
}
