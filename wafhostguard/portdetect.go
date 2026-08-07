package wafhostguard

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// SSH/RDP 实际监听端口的自动发现。
//
// **注意：爆破检测本身完全不依赖端口。** sshd 日志里的 `port N` 是源端口，
// Windows 4625 压根不带服务端口，所以用户把 SSH 改成 22222、RDP 改成 33890
// 检测照样工作。这个文件只服务两个次要用途：
//  1. 端口级封禁(只封 SSH/RDP 端口而不是全端口，误封时杀伤面更小)
//  2. 连接看板里高亮远程管理端口
//
// 探测方式：取 LISTEN 状态的连接 + 进程名匹配。用户也可以在设置里手工指定，
// 手工值优先——自动发现只是省事，不是唯一真相。

// 进程名到来源的映射。Windows 上 RDP 由 svchost 承载 TermService，
// 进程名匹配不到，所以额外用默认端口兜底。
var (
	sshProcNames = []string{"sshd", "sshd-session"}
	rdpProcNames = []string{"termsrv", "svchost"}
)

// 默认端口。自动发现失败时的兜底值。
const (
	defaultSSHPort = 22
	defaultRDPPort = 3389
)

type portSnapshot struct {
	ssh     []int
	rdp     []int
	builtAt time.Time
	auto    bool // 是否来自自动发现(false=用户手工配置)
}

var (
	portMu     sync.RWMutex
	portCur    *portSnapshot
	portTTL    = 5 * time.Minute
	portDetect = detectListenPorts // 便于测试替换
)

// InvalidatePorts 丢弃端口缓存，下次取用时重新探测(配置变更时调用)
func InvalidatePorts() {
	portMu.Lock()
	portCur = nil
	portMu.Unlock()
}

// GuardPorts 返回当前认定的 SSH / RDP 端口。
// 用户手工配置了就用手工的，否则自动探测；探测不到用默认端口兜底。
func GuardPorts() (ssh []int, rdp []int) {
	portMu.RLock()
	if portCur != nil && time.Since(portCur.builtAt) < portTTL {
		snap := portCur
		portMu.RUnlock()
		return snap.ssh, snap.rdp
	}
	portMu.RUnlock()

	portMu.Lock()
	defer portMu.Unlock()
	if portCur != nil && time.Since(portCur.builtAt) < portTTL {
		return portCur.ssh, portCur.rdp
	}

	snap := &portSnapshot{builtAt: time.Now(), auto: true}
	manualSSH := parsePorts(global.GCONFIG_HOST_GUARD_SSH_PORTS)
	manualRDP := parsePorts(global.GCONFIG_HOST_GUARD_RDP_PORTS)
	if len(manualSSH) > 0 || len(manualRDP) > 0 {
		snap.auto = false
	}

	var autoSSH, autoRDP []int
	if len(manualSSH) == 0 || len(manualRDP) == 0 {
		autoSSH, autoRDP = portDetect()
	}

	snap.ssh = pickPorts(manualSSH, autoSSH, defaultSSHPort)
	snap.rdp = pickPorts(manualRDP, autoRDP, defaultRDPPort)
	portCur = snap
	return snap.ssh, snap.rdp
}

// pickPorts 手工 > 自动 > 默认
func pickPorts(manual, auto []int, fallback int) []int {
	if len(manual) > 0 {
		return manual
	}
	if len(auto) > 0 {
		return auto
	}
	return []int{fallback}
}

// detectListenPorts 用 gopsutil 找 LISTEN 端口并按进程名归类。
// 拿不到进程名(权限不足/进程已退出)时按默认端口反查兜底。
func detectListenPorts() (ssh []int, rdp []int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conns, err := gnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		zlog.Debug("[主机登录防护] 探测监听端口失败", "error", err.Error())
		return nil, nil
	}

	sshSet := make(map[int]struct{})
	rdpSet := make(map[int]struct{})
	nameCache := make(map[int32]string)

	for _, c := range conns {
		if !strings.EqualFold(c.Status, "LISTEN") {
			continue
		}
		port := int(c.Laddr.Port)
		if port == 0 {
			continue
		}
		// 默认端口无条件认领，不依赖进程名——Windows 上 RDP 挂在 svchost 里认不出来
		if port == defaultSSHPort {
			sshSet[port] = struct{}{}
			continue
		}
		if port == defaultRDPPort {
			rdpSet[port] = struct{}{}
			continue
		}
		if c.Pid <= 0 {
			continue
		}
		name, ok := nameCache[c.Pid]
		if !ok {
			name = procName(ctx, c.Pid)
			nameCache[c.Pid] = name
		}
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)
		if matchAny(lower, sshProcNames) {
			sshSet[port] = struct{}{}
		} else if matchAny(lower, rdpProcNames) {
			// svchost 承载着一大堆服务，不能仅凭进程名就把它的端口全当成 RDP。
			// 所以这里只在进程名明确是 termsrv 时才认领；svchost 一律靠上面的默认端口分支。
			if strings.Contains(lower, "termsrv") {
				rdpSet[port] = struct{}{}
			}
		}
	}
	return sortedKeys(sshSet), sortedKeys(rdpSet)
}

// procName 取进程名，失败返回空串
func procName(ctx context.Context, pid int32) string {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return ""
	}
	name, err := p.NameWithContext(ctx)
	if err != nil {
		return ""
	}
	return name
}

func matchAny(s string, candidates []string) bool {
	for _, c := range candidates {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[int]struct{}) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// 端口数量极少(通常 1~2 个)，插入排序比引 sort 更直白
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// parsePorts 解析逗号分隔的端口配置，忽略非法项
func parsePorts(s string) []int {
	items := splitList(s)
	if len(items) == 0 {
		return nil
	}
	out := make([]int, 0, len(items))
	for _, item := range items {
		p, err := strconv.Atoi(item)
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		out = append(out, p)
	}
	return out
}
