package wafhostguard

import (
	"SamWaf/firewall"
	"SamWaf/global"
	"sync"
	"time"
)

// 环境能力探测。仿 firewall/available.go 的做法：结果带 30 秒缓存，
// 返回的 reason 是**可以直接展示给用户的中文**，而不是英文错误码——
// 用户看到"当前进程无权读取 /var/log/secure，请以 root 身份运行"能立刻知道怎么办，
// 看到 "permission denied" 只会来提 issue。

const capabilityCacheTTL = 30 * time.Second

// Capability 环境能力快照
type Capability struct {
	// LogReadable 能否读到认证日志(Linux)/安全事件日志(Windows)
	LogReadable bool
	// LogReason LogReadable=false 时的中文原因
	LogReason string
	// FirewallReady 系统防火墙是否可用(不可用时自动降级为观察模式)
	FirewallReady bool
	// FirewallReason FirewallReady=false 时的中文原因
	FirewallReason string
	// InContainer 是否运行在容器里(容器内看不到宿主机日志，提示文案要不一样)
	InContainer bool
	// CheckedAt 探测时刻
	CheckedAt time.Time
}

// Degraded 报告是否处于降级状态(能采集但封不了，或压根采集不了)
func (c Capability) Degraded() bool {
	return !c.LogReadable || !c.FirewallReady
}

var (
	capMu     sync.Mutex
	capCache  *Capability
	capCached time.Time
)

// GetCapability 取能力快照，带 30 秒缓存
func GetCapability() Capability {
	capMu.Lock()
	defer capMu.Unlock()
	if capCache != nil && time.Since(capCached) < capabilityCacheTTL {
		return *capCache
	}

	c := Capability{CheckedAt: time.Now()}
	c.LogReadable, c.LogReason, c.InContainer = checkLogCapability()

	var fw firewall.FireWallEngine
	if err := fw.CheckAvailable(); err != nil {
		c.FirewallReady = false
		c.FirewallReason = err.Error()
	} else {
		c.FirewallReady = true
	}

	capCache = &c
	capCached = time.Now()
	return c
}

// InvalidateCapability 丢弃缓存，强制下次重新探测
func InvalidateCapability() {
	capMu.Lock()
	capCache = nil
	capMu.Unlock()
}

// globalLogPaths 读用户自定义的日志路径配置(逗号分隔)。
// 单独包一层是为了让平台文件不用直接引 global 包，测试时也好替换。
func globalLogPaths() string {
	return global.GCONFIG_HOST_GUARD_LOG_PATHS
}

// checkLogCapability 由各平台文件实现(capability_linux.go / capability_windows.go /
// capability_other.go)：能否读到登录失败日志。
// 返回 (可读, 不可读时的中文原因, 是否在容器内)
