package wafonekey

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// 解析相关安全上限
const (
	maxNginxConfigLen  = 1 << 20 // 粘贴文本上限 1MB
	maxScanFileCount   = 500     // 扫描目录最多读取的 .conf 文件数
	maxScanFileSize    = 2 << 20 // 单个 .conf 文件读取上限 2MB
	scanRequiredSubDir = "server/panel/vhost"
)

// NginxHostCandidate 从一个 nginx server{} 块解析出的待添加主机候选
type NginxHostCandidate struct {
	Domains    []string `json:"domains"`     // server_name 全部域名（已过滤 _ / 空 / 非法FQDN）
	Port       int      `json:"port"`        // listen 端口 → 拟作 remote_port
	Ssl        bool     `json:"ssl"`         // listen ssl / 存在 ssl_certificate
	Root       string   `json:"root"`        // nginx root，仅展示/备注用，不参与代理
	SourceFile string   `json:"source_file"` // 扫描模式下来源 .conf 文件名（粘贴模式为空）
}

var (
	reServerBlock = regexp.MustCompile(`(?:^|\s)server\s*\{`)
	reListen      = regexp.MustCompile(`(?mi)^\s*listen\s+([^;]+);`)
	reServerName  = regexp.MustCompile(`(?mi)^\s*server_name\s+([^;]+);`)
	reRoot        = regexp.MustCompile(`(?mi)^\s*root\s+([^;]+);`)
	reSslCert     = regexp.MustCompile(`(?mi)^\s*ssl_certificate\s+[^;]+;`)
	reFQDN        = regexp.MustCompile(`^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// ParseNginxText 解析粘贴的 nginx 配置文本
func ParseNginxText(content string) ([]NginxHostCandidate, error) {
	if len(content) > maxNginxConfigLen {
		return nil, errors.New("配置内容过长")
	}
	return parseNginxContent(content, ""), nil
}

// ScanNginxDir 安全地扫描目录下 .conf 并解析
func ScanNginxDir(dirPath string) ([]NginxHostCandidate, error) {
	safeDir, err := resolveSafeNginxDir(dirPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(safeDir)
	if err != nil {
		return nil, err
	}
	candidates := make([]NginxHostCandidate, 0)
	readCnt := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".conf") {
			continue
		}
		if readCnt >= maxScanFileCount {
			break
		}
		readCnt++
		filePath := filepath.Join(safeDir, entry.Name())
		info, err := entry.Info()
		if err != nil || info.Size() > maxScanFileSize {
			continue
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		candidates = append(candidates, parseNginxContent(string(data), entry.Name())...)
	}
	return candidates, nil
}

// resolveSafeNginxDir 校验用户提供的目录必须是真实的 nginx vhost 目录，防止路径穿越/任意目录读取。
// 采用「绝对化 + Clean + 路径分段判定」而非现有 OneKeyModifyBt 的弱子串判断：
// 要求路径分段中连续出现 server/panel/vhost，避免 .../vhostEVIL 之类的旁路。
func resolveSafeNginxDir(dirPath string) (string, error) {
	if strings.TrimSpace(dirPath) == "" {
		dirPath = "/www/server/panel/vhost/nginx"
	}
	absPath, err := filepath.Abs(filepath.Clean(dirPath))
	if err != nil {
		return "", errors.New("无法解析目录路径")
	}
	// 分段（统一为斜杠）判定
	normalized := filepath.ToSlash(absPath)
	segs := strings.Split(normalized, "/")
	cleaned := make([]string, 0, len(segs))
	for _, s := range segs {
		if s == "" || s == "." {
			continue
		}
		if s == ".." {
			return "", errors.New("目录不在允许范围内")
		}
		cleaned = append(cleaned, s)
	}
	required := strings.Split(scanRequiredSubDir, "/")
	if !containsContiguous(cleaned, required) {
		return "", errors.New("目录不在允许范围内（须为宝塔 nginx vhost 目录）")
	}
	return absPath, nil
}

// containsContiguous 判断 required 是否作为连续子序列出现在 segs 中
func containsContiguous(segs, required []string) bool {
	if len(required) == 0 || len(segs) < len(required) {
		return false
	}
	for i := 0; i+len(required) <= len(segs); i++ {
		match := true
		for j := range required {
			if segs[i+j] != required[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// parseNginxContent 从配置文本中提取每个 server{} 块的候选
func parseNginxContent(content, sourceFile string) []NginxHostCandidate {
	candidates := make([]NginxHostCandidate, 0)
	for _, block := range splitServerBlocks(content) {
		candidate, ok := parseServerBlock(block)
		if !ok {
			continue
		}
		candidate.SourceFile = sourceFile
		candidates = append(candidates, candidate)
	}
	return candidates
}

// splitServerBlocks 用花括号配对切分出所有 server{} 块的内部内容
func splitServerBlocks(content string) []string {
	blocks := make([]string, 0)
	locs := reServerBlock.FindAllStringIndex(content, -1)
	for _, loc := range locs {
		open := strings.IndexByte(content[loc[0]:loc[1]], '{')
		if open < 0 {
			continue
		}
		open += loc[0]
		depth := 0
		end := -1
		for i := open; i < len(content); i++ {
			switch content[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end > open {
			blocks = append(blocks, content[open+1:end])
		}
	}
	return blocks
}

// parseServerBlock 解析单个 server 块内容
func parseServerBlock(block string) (NginxHostCandidate, bool) {
	var candidate NginxHostCandidate

	// listen：取第一条含合法端口的；ssl 为任意一条含 ssl 关键字或存在 ssl_certificate
	for _, m := range reListen.FindAllStringSubmatch(block, -1) {
		port, ssl := parseListen(m[1])
		if candidate.Port == 0 && port > 0 && port <= 65535 {
			candidate.Port = port
		}
		if ssl {
			candidate.Ssl = true
		}
	}
	if reSslCert.MatchString(block) {
		candidate.Ssl = true
	}
	if candidate.Port == 0 {
		return candidate, false
	}

	// server_name：拆分并过滤非法域名
	if m := reServerName.FindStringSubmatch(block); m != nil {
		for _, name := range strings.Fields(m[1]) {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || name == "_" || name == "localhost" {
				continue
			}
			if reFQDN.MatchString(name) {
				candidate.Domains = append(candidate.Domains, name)
			}
		}
	}
	if len(candidate.Domains) == 0 {
		return candidate, false
	}

	// root：仅展示
	if m := reRoot.FindStringSubmatch(block); m != nil {
		candidate.Root = strings.TrimSpace(m[1])
	}

	return candidate, true
}

// parseListen 解析 listen 指令值，返回端口与是否 ssl
// 兼容: "81" / "127.0.0.1:81" / "[::]:81" / "443 ssl http2" / "0.0.0.0:443 ssl"
func parseListen(value string) (int, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, false
	}
	ssl := false
	for _, f := range fields[1:] {
		if strings.EqualFold(f, "ssl") {
			ssl = true
		}
	}
	return extractPort(fields[0]), ssl
}

// extractPort 从 listen 的地址部分取端口
func extractPort(addr string) int {
	// IPv6: [::]:81
	if i := strings.LastIndex(addr, "]:"); i >= 0 {
		if n, err := strconv.Atoi(addr[i+2:]); err == nil {
			return n
		}
		return 0
	}
	// host:port
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		if n, err := strconv.Atoi(addr[i+1:]); err == nil {
			return n
		}
		return 0
	}
	// 纯端口
	if n, err := strconv.Atoi(addr); err == nil {
		return n
	}
	return 0
}
