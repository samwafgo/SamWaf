package wafhostguard

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sshd 日志行解析。纯逻辑、无 build tag、无外部依赖，可以在 Windows 开发机上
// 直接 go test 验证 Linux 日志的解析结果——这是整个模块最容易出错的部分，
// 所以刻意不让它沾任何平台特定代码。
//
// **不解析行首时间戳**：传统 syslog 行首 `Aug  6 14:55:01 host sshd[123]:` 不带年份，
// RFC5424 是 `2026-08-06T14:55:01.123+08:00 host sshd 123 - -`，而 journalctl -o cat
// 干脆没有行首。既然是近实时 tail，用"读到该行的时刻"做事件时间误差在毫秒级，
// 完全够用，还彻底绕开了时间戳格式地狱。

// ipPat 宽松抓取 IPv4 / IPv6 / IPv4-mapped，抓完一律交给 net.ParseIP 严格校验，
// 校验不过就整行丢弃——宁可漏一条，不可封错一个。
const ipPat = `([0-9a-fA-F:.]+)`

// sshdRule 一条解析规则。
// hint 用于 strings.Contains 粗筛：绝大多数日志行都不是登录失败，先做一次
// 字符串包含判断再跑正则，比无条件跑全部正则快约一个数量级。
type sshdRule struct {
	kind      FailKind
	hint      string
	re        *regexp.Regexp
	methodIdx int // 认证方式捕获组下标(仅 Failed <method> for 规则)，0=无
	userIdx   int // 用户名捕获组下标，0=无
	ipIdx     int // IP 捕获组下标，必须 > 0
	portIdx   int // 源端口捕获组下标，0=无
}

// sshdRules 顺序即优先级：hard(确定的认证失败)在前，soft(可能与 hard 行重复计数的)在后。
var sshdRules = []sshdRule{
	// —— hard：确定的一次认证失败 ——
	// 覆盖 password / publickey / none / keyboard-interactive/pam 等各种 method
	{
		kind: FailPassword, hint: "Failed ",
		re:        regexp.MustCompile(`Failed (\S+) for (invalid user )?(\S+) from ` + ipPat + ` port (\d+)`),
		methodIdx: 1, userIdx: 3, ipIdx: 4, portIdx: 5,
	},
	// 单连接内尝试次数超过 MaxAuthTries，明确是在撞库
	{
		kind: FailMaxAuthTries, hint: "maximum authentication attempts exceeded",
		re:      regexp.MustCompile(`maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ` + ipPat + ` port (\d+)`),
		userIdx: 1, ipIdx: 2, portIdx: 3,
	},
	// 被 AllowUsers / DenyUsers / AllowGroups 挡下
	{
		kind: FailNotAllowed, hint: "not allowed because",
		re:      regexp.MustCompile(`User (\S+) from ` + ipPat + ` not allowed because`),
		userIdx: 1, ipIdx: 2,
	},

	// —— soft：默认不计入阈值，原因见 IsHard 的说明 ——
	// 用户名枚举。sshd 通常先打这行、紧接着再打一条 Failed password，
	// 两条都计会让阈值实际腰斩。
	{
		kind: FailInvalidUser, hint: "Invalid user",
		re:      regexp.MustCompile(`Invalid user (\S*) from ` + ipPat + `(?: port (\d+))?`),
		userIdx: 1, ipIdx: 2, portIdx: 3,
	},
	// PAM 层失败。RHEL 系的 /var/log/secure 会和 Failed password 成对出现，同样会重复计数；
	// 但少数发行版只有这行带得出 IP，所以保留解析、交给配置决定是否计数。
	{
		kind: FailPamAuth, hint: "authentication failure",
		re:    regexp.MustCompile(`authentication failure;.*?rhost=` + ipPat + `(?:\s+user=(\S+))?`),
		ipIdx: 1, userIdx: 2,
	},
	// preauth 阶段断连：端口扫描、健康探针、LB 探活的高发来源
	{
		kind: FailPreauthClose, hint: "[preauth]",
		re:      regexp.MustCompile(`Connection (?:closed|reset) by (?:(?:invalid|authenticating) user (\S+) )?` + ipPat + ` port (\d+)`),
		userIdx: 1, ipIdx: 2, portIdx: 3,
	},
	{
		kind: FailPreauthClose, hint: "[preauth]",
		re:      regexp.MustCompile(`Disconnected from (?:(?:invalid|authenticating) user (\S+) )?` + ipPat + ` port (\d+)`),
		userIdx: 1, ipIdx: 2, portIdx: 3,
	},

	// —— 扫描探测：连登录尝试都算不上，只展示不计数 ——
	// HTTP/其他协议的请求打到 SSH 端口上，典型的全网端口扫描
	{
		kind: FailScanProbe, hint: "Bad protocol version identification",
		re:    regexp.MustCompile(`Bad protocol version identification .* from ` + ipPat),
		ipIdx: 1,
	},
	// 连上就走、不发协议标识，扫描器探活的典型特征
	{
		kind: FailScanProbe, hint: "Did not receive identification string",
		re:    regexp.MustCompile(`Did not receive identification string from ` + ipPat),
		ipIdx: 1,
	},
}

// listenPortRe 从 `Server listening on 0.0.0.0 port 2222.` 抓 sshd 实际监听端口，
// 用于和 portdetect 的探测结果交叉验证(用户改过默认端口时)。
var listenPortRe = regexp.MustCompile(`Server listening on \S+ port (\d+)`)

// ParseSSHDLine 解析一行 sshd 日志。
// ok=false 表示该行不是登录失败，或抓到的 IP 非法(一律丢弃，不做任何猜测)。
func ParseSSHDLine(line string, now time.Time) (LoginFailEvent, bool) {
	if line == "" {
		return LoginFailEvent{}, false
	}
	for i := range sshdRules {
		r := &sshdRules[i]
		if !strings.Contains(line, r.hint) {
			continue
		}
		m := r.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip := groupAt(m, r.ipIdx)
		if net.ParseIP(ip) == nil {
			// rhost= 可能是域名、IP 可能被日志截断——都不是能拿来封禁的东西
			continue
		}

		ev := LoginFailEvent{
			Source: SourceSSH,
			IP:     ip,
			User:   groupAt(m, r.userIdx),
			Kind:   r.kind,
			Raw:    TruncRaw(line),
			At:     now,
		}
		if p := groupAt(m, r.portIdx); p != "" {
			ev.Port, _ = strconv.Atoi(p)
		}
		// Failed <method> 规则：按 method 细分类型，并补上 invalid user 语义
		if r.methodIdx > 0 {
			switch strings.ToLower(groupAt(m, r.methodIdx)) {
			case "publickey":
				ev.Kind = FailPublicKey
			default:
				ev.Kind = FailPassword
			}
		}
		return ev, true
	}
	return LoginFailEvent{}, false
}

// ParseSSHDListenPort 从日志行中提取 sshd 实际监听端口，未命中返回 0
func ParseSSHDListenPort(line string) int {
	if !strings.Contains(line, "Server listening on") {
		return 0
	}
	m := listenPortRe.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	p, _ := strconv.Atoi(m[1])
	return p
}

// groupAt 安全取捕获组，下标为 0 或越界时返回空串
func groupAt(m []string, idx int) string {
	if idx <= 0 || idx >= len(m) {
		return ""
	}
	return m[idx]
}
