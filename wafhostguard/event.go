// Package wafhostguard 主机侧远程登录爆破防护。
//
// 保护的是 SamWaf 所在这台机器**自身**的 SSH / RDP，与 WAF 引擎(保护 Web 站点)
// 完全是两件事。工作方式与 fail2ban / IPBan 一致：
//
//	读系统日志 -> 归一化事件 -> 滑动窗口计数 -> 超阈值 -> 阶梯递进封禁 -> 到期解封
//
// 判定依据是**日志内容**而非端口，所以用户把 sshd 改成 22222、RDP 改成 33890
// 都不影响检测(日志里的 port 是源端口，不是服务端口)。
package wafhostguard

import (
	"context"
	"time"
)

// 事件来源
const (
	SourceSSH = "ssh"
	SourceRDP = "rdp"
)

// FailKind 失败类型，决定是否计入阈值与展示文案
type FailKind string

const (
	FailPassword     FailKind = "failed_password"  // Failed password for [invalid user] X from IP port N
	FailPublicKey    FailKind = "failed_publickey" // Failed publickey for X from IP port N
	FailInvalidUser  FailKind = "invalid_user"     // Invalid user X from IP
	FailMaxAuthTries FailKind = "max_auth_tries"   // maximum authentication attempts exceeded
	FailNotAllowed   FailKind = "not_allowed"      // User X not allowed because not listed in AllowUsers
	FailPamAuth      FailKind = "pam_auth_failure" // pam_unix(sshd:auth): authentication failure ... rhost=IP
	FailPreauthClose FailKind = "preauth_close"    // Connection closed/reset by ... [preauth]   <- soft
	FailScanProbe    FailKind = "scan_probe"       // 端口扫描/协议探测，不是登录尝试        <- soft
	FailRdpLogon     FailKind = "rdp_logon_failed" // Windows 安全日志 4625
)

// IsHard 报告该失败类型是否计入封禁阈值。软失败默认不计数，这是防误封的第一道闸，
// 比白名单更早生效；用户确实想计的话可以打开 host_guard_count_soft_fail。
//
// 三类被判为软失败的原因各不相同：
//   - FailPreauthClose：preauth 阶段断连由端口扫描、健康探针、负载均衡探活大量产生，
//     计数会误封监控系统。
//   - FailInvalidUser：sshd 通常先打 `Invalid user X from IP`，紧接着再打一条
//     `Failed password for invalid user X from IP`，同一次尝试出现两行。
//   - FailPamAuth：RHEL 系 /var/log/secure 里 pam_unix 那行同样与 Failed password 成对出现。
//   - FailScanProbe：端口扫描与协议探测(HTTP 请求打到 SSH 端口之类)，压根不是登录尝试，
//     只做展示让用户知道"有人在扫我"，不参与封禁判定。
//
// 中间两类若一并计数，配 8 次的阈值实际 4 次就会触发，"自己敲错几次密码"就被封了。
func (k FailKind) IsHard() bool {
	switch k {
	case FailPreauthClose, FailInvalidUser, FailPamAuth, FailScanProbe:
		return false
	default:
		return true
	}
}

// IsScanProbe 报告是否属于"扫描探测"而非登录失败。
// 这类事件即使用户打开了 host_guard_count_soft_fail 也不该计数——
// 它连一次登录尝试都算不上，计进去纯属噪声。
func (k FailKind) IsScanProbe() bool { return k == FailScanProbe }

// LoginFailEvent 归一化后的一次远程登录失败
type LoginFailEvent struct {
	Source    string    // ssh | rdp
	IP        string    // 已经 net.ParseIP 严格校验过的字符串形式
	Port      int       // 源端口，未知为 0
	User      string    // 尝试的用户名，可能为空
	Kind      FailKind  //
	LogonType string    // 仅 Windows：3=Network 10=RemoteInteractive
	Raw       string    // 原始行/XML 摘要，入库前截断
	At        time.Time // 采集时刻(不解析日志行内时间戳，见 parser_sshd.go 的说明)
}

// RawLimit 原始内容入库长度上限
const RawLimit = 500

// TruncRaw 截断原始内容，避免超长日志行把事件表撑爆
func TruncRaw(s string) string {
	if len(s) <= RawLimit {
		return s
	}
	return s[:RawLimit]
}

// Source 事件源。各实现必须做到：
//   - Run 阻塞运行直到 ctx.Done()，退出前释放全部资源(fd / 子进程 / 系统句柄)
//   - 内部错误不 panic，只记 zlog 并自愈重试
//   - 向 out 发送时必须 select ctx.Done()，否则 Stop 时会卡死在满通道上
type Source interface {
	Name() string // 展示用，如 "file:/var/log/secure"
	Run(ctx context.Context, out chan<- LoginFailEvent) error
}
