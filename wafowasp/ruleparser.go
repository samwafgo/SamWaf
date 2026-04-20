package wafowasp

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// RuleMeta 规则元数据（不包含完整正则细节，仅供前端展示与过滤）。
type RuleMeta struct {
	ID         int      `json:"id"`
	File       string   `json:"file"` // 相对 data/owasp 的路径
	Phase      int      `json:"phase"`
	Severity   string   `json:"severity"` // CRITICAL/ERROR/WARNING/NOTICE/...
	Paranoia   int      `json:"paranoia"` // 1..4，0 表示未指定
	Message    string   `json:"message"`
	Tags       []string `json:"tags"`
	RawSnippet string   `json:"raw"`        // 该 SecRule/SecAction 块的原始多行文本
	LineStart  int      `json:"line_start"` // 起始行号（1-based）
	LineEnd    int      `json:"line_end"`
	Directive  string   `json:"directive"` // SecRule / SecAction
}

// ParsedRuleFile 一个规则文件的全部解析结果。
type ParsedRuleFile struct {
	File    string     `json:"file"`  // 相对 owasp 根目录
	ModTime int64      `json:"mtime"` // mtime 纳秒时间戳
	Rules   []RuleMeta `json:"rules"`
}

// ruleDirectiveRe 匹配 SecRule/SecAction 指令开头（大小写不敏感，忽略开头空白）。
var ruleDirectiveRe = regexp.MustCompile(`(?i)^\s*(SecRule|SecAction)\b`)

// 元数据正则。都使用 (?i) 不区分大小写；id 必需，其他尽量提取。
var (
	reID       = regexp.MustCompile(`(?i)\bid\s*:\s*'?(\d+)'?`)
	rePhase    = regexp.MustCompile(`(?i)\bphase\s*:\s*'?(\d+)'?`)
	reSeverity = regexp.MustCompile(`(?i)\bseverity\s*:\s*'?([A-Za-z]+)'?`)
	// paranoia-level 可能是 tag:'paranoia-level/2' 形式
	reParanoia = regexp.MustCompile(`(?i)tag\s*:\s*'paranoia-level/(\d+)'`)
	reTag      = regexp.MustCompile(`(?i)\btag\s*:\s*'([^']+)'`)
	reMsg      = regexp.MustCompile(`(?i)\bmsg\s*:\s*'((?:[^'\\]|\\.)*)'`)
)

// ruleFileCache 规则文件的解析缓存。
// key: 文件绝对路径 → value: {mtime, rules}
// 读多写少，用 RWMutex 即可。
var (
	ruleFileCache   = make(map[string]*ParsedRuleFile)
	ruleFileCacheMu sync.RWMutex
)

// ParseRuleFile 解析单个 .conf 文件。带 mtime 缓存，文件未变动时直接复用。
//
// absPath 应为绝对路径，relFile 是相对 data/owasp 的路径（填入 RuleMeta.File）。
// 空路径返回 nil, nil。
func ParseRuleFile(absPath string, relFile string) (*ParsedRuleFile, error) {
	if absPath == "" {
		return nil, nil
	}
	st, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}
	mtime := st.ModTime().UnixNano()

	ruleFileCacheMu.RLock()
	if cached, ok := ruleFileCache[absPath]; ok && cached.ModTime == mtime {
		ruleFileCacheMu.RUnlock()
		return cached, nil
	}
	ruleFileCacheMu.RUnlock()

	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rules, err := parseRules(f, relFile)
	if err != nil {
		return nil, err
	}

	parsed := &ParsedRuleFile{
		File:    relFile,
		ModTime: mtime,
		Rules:   rules,
	}

	ruleFileCacheMu.Lock()
	ruleFileCache[absPath] = parsed
	ruleFileCacheMu.Unlock()

	return parsed, nil
}

// parseRules 从 reader 流式读取并解析 SecRule/SecAction 块。
func parseRules(r io.Reader, relFile string) ([]RuleMeta, error) {
	scanner := bufio.NewScanner(r)
	// 单条 SecRule 最长可达几十 KB（PHP 黑词列表），给足缓冲
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var (
		result    []RuleMeta
		current   strings.Builder
		startLine int
		lineNum   int
		inBlock   bool
		directive string
	)

	flush := func(endLine int) {
		if !inBlock {
			return
		}
		raw := current.String()
		if meta := extractRuleMeta(raw, relFile, startLine, endLine, directive); meta.ID != 0 {
			result = append(result, meta)
		}
		current.Reset()
		inBlock = false
		directive = ""
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimLeft(line, " \t")

		// 注释行（不属于 SecRule 内部时忽略）
		if !inBlock && strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !inBlock {
			if m := ruleDirectiveRe.FindStringSubmatch(trimmed); m != nil {
				inBlock = true
				startLine = lineNum
				directive = m[1]
				current.WriteString(line)
				current.WriteByte('\n')
				// 判断本行是否以续行符结束
				if !endsWithBackslash(line) {
					flush(lineNum)
				}
				continue
			}
			// 其他顶级指令（SecComponentSignature / SecDefaultAction 等）忽略
			continue
		}

		current.WriteString(line)
		current.WriteByte('\n')
		if !endsWithBackslash(line) {
			flush(lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush(lineNum)
	return result, nil
}

// endsWithBackslash 判断行是否以续行符结尾（忽略尾部空白）。
func endsWithBackslash(line string) bool {
	t := strings.TrimRight(line, " \t")
	return strings.HasSuffix(t, "\\")
}

// extractRuleMeta 从规则原始块中提取元数据。
func extractRuleMeta(raw, relFile string, startLine, endLine int, directive string) RuleMeta {
	meta := RuleMeta{
		File:       relFile,
		RawSnippet: raw,
		LineStart:  startLine,
		LineEnd:    endLine,
		Directive:  directive,
	}

	if m := reID.FindStringSubmatch(raw); len(m) == 2 {
		if id, err := strconv.Atoi(m[1]); err == nil {
			meta.ID = id
		}
	}
	if meta.ID == 0 {
		return meta
	}

	if m := rePhase.FindStringSubmatch(raw); len(m) == 2 {
		if v, err := strconv.Atoi(m[1]); err == nil {
			meta.Phase = v
		}
	}
	if m := reSeverity.FindStringSubmatch(raw); len(m) == 2 {
		meta.Severity = strings.ToUpper(m[1])
	}
	if m := reParanoia.FindStringSubmatch(raw); len(m) == 2 {
		if v, err := strconv.Atoi(m[1]); err == nil {
			meta.Paranoia = v
		}
	}
	if m := reMsg.FindStringSubmatch(raw); len(m) == 2 {
		meta.Message = unescapeSingleQuoted(m[1])
	}

	tagMatches := reTag.FindAllStringSubmatch(raw, -1)
	if len(tagMatches) > 0 {
		tags := make([]string, 0, len(tagMatches))
		for _, tm := range tagMatches {
			tags = append(tags, tm[1])
		}
		meta.Tags = tags
	}

	return meta
}

// unescapeSingleQuoted 处理单引号字符串里的 \\ 和 \'
func unescapeSingleQuoted(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			sb.WriteByte(s[i+1])
			i++
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// ScanAllRules 扫描 data/owasp 下所有规则 .conf（coreruleset + overrides），
// 返回按文件聚合的列表。
//
// owaspRoot 是 data/owasp 目录绝对路径。
func ScanAllRules(owaspRoot string) ([]*ParsedRuleFile, error) {
	if owaspRoot == "" {
		return nil, nil
	}
	var files []string
	// overridesDir 下的文件是 SamWaf 自动生成的调参/禁用指令，不是 CRS WAF 规则，排除扫描。
	overridesDir := filepath.Join(owaspRoot, "overrides")
	err := filepath.Walk(owaspRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// 跳过 overrides 目录（包含 SamWaf 生成的调参/禁用指令，不是真正的 WAF 规则）
			if filepath.Clean(p) == filepath.Clean(overridesDir) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(info.Name()) != ".conf" {
			return nil
		}
		// 忽略 .example 文件（官方示例，不被加载）
		if strings.HasSuffix(info.Name(), ".conf.example") {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	out := make([]*ParsedRuleFile, 0, len(files))
	for _, abs := range files {
		rel, e := filepath.Rel(owaspRoot, abs)
		if e != nil {
			rel = filepath.Base(abs)
		}
		rel = filepath.ToSlash(rel)
		parsed, perr := ParseRuleFile(abs, rel)
		if perr != nil || parsed == nil {
			continue
		}
		out = append(out, parsed)
	}
	return out, nil
}

// InvalidateRuleCache 清空规则解析缓存（用于在写文件后强制下次重新解析）。
func InvalidateRuleCache() {
	ruleFileCacheMu.Lock()
	ruleFileCache = make(map[string]*ParsedRuleFile)
	ruleFileCacheMu.Unlock()
}
