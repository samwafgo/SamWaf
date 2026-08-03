// Package threatip 提供威胁情报 IP 订阅的解析、拉取与差异计算逻辑。
package threatip

import (
	"SamWaf/model"
	"SamWaf/utils"
	"bufio"
	"fmt"
	"io"
	"strings"
)

// ParseResult 解析结果：有效 IP/CIDR 列表 + 被丢弃的非法行数(用于日志/告警)
type ParseResult struct {
	IPs     []string
	Dropped int
}

// Parser 可插拔解析器：把某渠道的原始响应解析为规范化的 IP/CIDR 列表。
// threshold 仅对支持"命中数阈值"的解析器(如 ipsum)有意义，其它忽略。
type Parser interface {
	Parse(r io.Reader, threshold int) (ParseResult, error)
}

// parsers 解析器注册表
var parsers = map[string]Parser{
	model.ThreatParserCIDROnly:   cidrOnlyParser{},
	model.ThreatParserIpsum:      ipsumParser{},
	model.ThreatParserPlainMixed: plainMixedParser{},
}

// ParseByType 按渠道 parserType 选择解析器解析。未知类型回退 plain_mixed(最宽容)。
func ParseByType(parserType string, r io.Reader, threshold int) (ParseResult, error) {
	p, ok := parsers[parserType]
	if !ok {
		p = plainMixedParser{}
	}
	return p.Parse(r, threshold)
}

// keepIfValid 校验单条并追加到结果，非法则计入 dropped
func keepIfValid(item string, res *ParseResult) {
	item = strings.TrimSpace(item)
	if item == "" {
		return
	}
	if ok, _ := utils.IsValidIPOrNetwork(item); ok {
		res.IPs = append(res.IPs, item)
	} else {
		res.Dropped++
	}
}

// cidrOnlyParser 适配 USTC blackip：一行一条(单 IP 或 CIDR，v4/v6 混合)，无注释头。
type cidrOnlyParser struct{}

func (cidrOnlyParser) Parse(r io.Reader, _ int) (ParseResult, error) {
	var res ParseResult
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keepIfValid(line, &res)
	}
	return res, sc.Err()
}

// ipsumParser 适配 stamparm/ipsum：`#` 注释头 + `IP\t命中黑名单数`(纯 v4)。
// 仅收命中数 >= threshold 的条目(threshold<=0 时全收)。
type ipsumParser struct{}

func (ipsumParser) Parse(r io.Reader, threshold int) (ParseResult, error) {
	var res ParseResult
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if threshold > 0 && len(fields) >= 2 {
			var cnt int
			if _, err := fmt.Sscanf(fields[1], "%d", &cnt); err == nil && cnt < threshold {
				continue // 命中数不足阈值，丢弃
			}
		}
		keepIfValid(fields[0], &res)
	}
	return res, sc.Err()
}

// plainMixedParser 通用兜底：忽略空行与 `#` 注释，取每行第一个字段做校验。
type plainMixedParser struct{}

func (plainMixedParser) Parse(r io.Reader, _ int) (ParseResult, error) {
	var res ParseResult
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		keepIfValid(fields[0], &res)
	}
	return res, sc.Err()
}
