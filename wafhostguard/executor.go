package wafhostguard

import (
	"SamWaf/common/zlog"
	"SamWaf/firewall"
	"SamWaf/global"
	"SamWaf/model"
	"sync"
	"time"
)

// BanSetName 防爆破专用的封禁集合名。
//
// 刻意与威胁情报订阅集合(samwaf_sub_*)和手工逐条封禁规则(SamWAF_ 前缀)完全分开：
// 三者的生命周期、更新频率、真相来源都不同，共用一个集合迟早会互相覆盖或误删。
const BanSetName = "samwaf_hostguard"

// BanExecutor 把"当前应该被封禁的 IP 集合"同步到系统防火墙。
//
// 内存里维护一份集合镜像作为唯一真相，各平台按能力选择同步方式：
//   - Linux / macOS：支持增量，来一个封一个，立即生效
//   - Windows：分片规则模型无法增量，只能全量重建；重建代价高(要先逐序号扫描删除旧分片)，
//     所以攒够去抖窗口(默认 30 秒)再合并成一次重建。主机爆破封禁不需要秒级生效，
//     多等半分钟换来的是不会在爆破高峰把 netsh fork 成千上万次。
type BanExecutor struct {
	mu      sync.Mutex
	current map[string]struct{}
	fw      firewall.FireWallEngine

	// applyMu 串行化"全量重建"这类防火墙写操作(与 mu 分开：mu 只保护内存镜像，
	// 持有它的时间必须短，不能跨越动辄数秒的 netsh/ipset 调用)。
	//
	// 必须有：ReplayOnStart(启动重放)、FlushPending(去抖定时器、端口范围变更、Stop)
	// 都会对同一个集合做"清旧 + 全量重建"，而它们分属不同 goroutine。
	// Windows 上 netsh 的 add 是**追加**不是替换，两次重建交错的结果就是同名分片规则
	// 一层层叠加(威胁情报模块线上实测同一分片名堆到 7 份)。
	applyMu sync.Mutex

	dirty      bool          // Windows 路径：集合有变更待同步
	syncTimer  *time.Timer   // 去抖定时器
	stopCh     chan struct{} // 关闭信号
	lastSyncAt time.Time
	lastSyncMs int64
}

var (
	executorOnce sync.Once
	executorInst *BanExecutor
)

// GetBanExecutor 取执行器单例
func GetBanExecutor() *BanExecutor {
	executorOnce.Do(func() {
		executorInst = &BanExecutor{
			current: make(map[string]struct{}),
			stopCh:  make(chan struct{}),
		}
	})
	return executorInst
}

// useIncremental 判断本次是否走增量路径
func (e *BanExecutor) useIncremental() bool {
	switch global.GCONFIG_HOST_GUARD_EXEC_MODE {
	case "rule":
		// 强制逐条规则(调试用)：逐条 BlockIP 本身就是增量语义
		return true
	case "ipset":
		return e.fw.SupportsIncrementalIPSet()
	default:
		return e.fw.SupportsIncrementalIPSet()
	}
}

// useRuleMode 是否走逐条防火墙规则而不是集合
func (e *BanExecutor) useRuleMode() bool {
	if global.GCONFIG_HOST_GUARD_EXEC_MODE == "rule" {
		return true
	}
	if global.GCONFIG_HOST_GUARD_EXEC_MODE == "ipset" {
		return false
	}
	// auto：集合不可用时退回逐条规则(比如 Linux 上没装 ipset)
	return !e.fw.SupportsIPSet()
}

// ExecMode 返回当前实际使用的执行方式，供状态展示
func (e *BanExecutor) ExecMode() string {
	if e.useRuleMode() {
		return model.HostBanExecRule
	}
	return model.HostBanExecIPSet
}

// SupportsPortScope 报告当前平台能否把封禁限制在指定端口。
// 供状态接口暴露给前端——不支持时页面要把"仅SSH/RDP端口"这个选项禁掉，
// 否则用户选了、界面提示保存成功、实际却静默按全端口封，就是个假开关。
func (e *BanExecutor) SupportsPortScope() bool {
	if e.useRuleMode() {
		// 逐条规则模式走 BlockIP，那是整机封禁，没有端口维度
		return false
	}
	return e.fw.SupportsPortScopedSet()
}

// ApplyPortScope 按配置调整封禁作用端口。
//
// port_scope=detected 时只封 SSH/RDP 端口——误封的代价从"整台机器进不去"
// 降到"远程登录进不去，Web 与业务端口照常"，排查余地大得多。
// 逐条规则模式(useRuleMode)下不支持，因为 BlockIP 走的是整机规则。
func (e *BanExecutor) ApplyPortScope() {
	if e.useRuleMode() {
		return
	}
	if global.GCONFIG_HOST_GUARD_PORT_SCOPE != "detected" {
		// 恢复全端口
		if err := e.fw.ApplyIPSetPortScope(BanSetName, nil); err != nil {
			zlog.Warn("[主机登录防护] 恢复全端口封禁范围失败", "error", err.Error())
			return
		}
		e.rebuildAfterScopeChange()
		return
	}

	if !e.fw.SupportsPortScopedSet() {
		zlog.Warn("[主机登录防护] 当前系统不支持端口级封禁，已按全端口封禁执行。" +
			"macOS 请在 /etc/pf.conf 的 block 规则上自行加 port 限制")
		return
	}

	sshPorts, rdpPorts := GuardPorts()
	ports := append(append([]int{}, sshPorts...), rdpPorts...)
	if len(ports) == 0 {
		zlog.Warn("[主机登录防护] 未探测到 SSH/RDP 端口，端口级封禁降级为全端口")
		ports = nil
	}
	if err := e.fw.ApplyIPSetPortScope(BanSetName, ports); err != nil {
		zlog.Warn("[主机登录防护] 设置端口级封禁范围失败，已按全端口封禁执行", "error", err.Error())
		return
	}
	e.rebuildAfterScopeChange()
	if len(ports) > 0 {
		zlog.Info("[主机登录防护] 封禁范围已限制在远程登录端口", "端口", ports)
	}
}

// rebuildAfterScopeChange 范围改完后，让新范围立刻作用到**已经生效**的封禁上。
//
// Linux/macOS 不需要：端口写在那条独立的引用规则上，ApplyIPSetPortScope 已经把
// 规则重建过了，集合内容原封不动，新范围自动对全部已封 IP 生效。
//
// Windows 需要：那边没有独立的引用规则，端口是写在每条分片规则自身的 localport= 上的，
// ApplyIPSetPortScope 只记下了范围。不在这里补一次全量重建，用户在页面上把范围
// 从"全部端口"改成"仅SSH/RDP"之后，已经封着的 IP 仍然是全端口封禁，
// 要等下一次有新封禁或解封触发去抖重建才会变——那是个说不通的行为。
func (e *BanExecutor) rebuildAfterScopeChange() {
	if e.fw.SupportsIncrementalIPSet() {
		return
	}
	e.mu.Lock()
	empty := len(e.current) == 0
	if !empty {
		e.dirty = true
	}
	e.mu.Unlock()
	if empty {
		return
	}
	if err := e.FlushPending(); err != nil {
		zlog.Warn("[主机登录防护] 切换封禁范围后重建防火墙规则失败", "error", err.Error())
	}
}

// Apply 增删封禁。add/del 可以同时非空(到期解封与新增封禁在同一轮里发生)。
func (e *BanExecutor) Apply(add, del []string) error {
	if len(add) == 0 && len(del) == 0 {
		return nil
	}

	e.mu.Lock()
	changed := false
	for _, ip := range add {
		if _, ok := e.current[ip]; !ok {
			e.current[ip] = struct{}{}
			changed = true
		}
	}
	for _, ip := range del {
		if _, ok := e.current[ip]; ok {
			delete(e.current, ip)
			changed = true
		}
	}
	if !changed {
		e.mu.Unlock()
		return nil
	}
	ruleMode := e.useRuleMode()
	incremental := e.useIncremental()
	e.mu.Unlock()

	if ruleMode {
		return e.applyByRules(add, del)
	}
	if incremental {
		return e.applyIncremental(add, del)
	}
	// Windows：标脏，交给去抖协程合并重建
	e.markDirty()
	return nil
}

// applyByRules 逐条防火墙规则模式(Linux 无 ipset 时的退路，或用户强制指定)
func (e *BanExecutor) applyByRules(add, del []string) error {
	var firstErr error
	for _, ip := range add {
		if err := e.fw.BlockIP(ip, "SamWaf主机防爆破"); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, ip := range del {
		if err := e.fw.UnblockIP(ip); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// applyIncremental Linux/macOS：直接增删集合元素
func (e *BanExecutor) applyIncremental(add, del []string) error {
	start := time.Now()
	var firstErr error
	if len(add) > 0 {
		if err := e.fw.AddToIPSet(BanSetName, add); err != nil {
			firstErr = err
		}
	}
	if len(del) > 0 {
		if err := e.fw.DelFromIPSet(BanSetName, del); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	e.recordSync(start)
	return firstErr
}

// markDirty 标脏并启动/重置去抖定时器
func (e *BanExecutor) markDirty() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dirty = true

	debounce := time.Duration(global.GCONFIG_HOST_GUARD_DEBOUNCE_SEC) * time.Second
	if debounce <= 0 {
		debounce = 30 * time.Second
	}
	if e.syncTimer != nil {
		e.syncTimer.Stop()
	}
	e.syncTimer = time.AfterFunc(debounce, func() {
		if err := e.FlushPending(); err != nil {
			zlog.Warn("[主机登录防护] 同步封禁集合到系统防火墙失败", "error", err.Error())
		}
	})
}

// FlushPending 立即把待同步的集合全量重建掉。
// Stop() 时必须调用一次，否则最后一批封禁会随进程退出一起丢失。
func (e *BanExecutor) FlushPending() error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	e.mu.Lock()
	if !e.dirty {
		e.mu.Unlock()
		return nil
	}
	e.dirty = false
	if e.syncTimer != nil {
		e.syncTimer.Stop()
		e.syncTimer = nil
	}
	ips := e.snapshotLocked()
	e.mu.Unlock()

	start := time.Now()
	err := e.fw.RestoreIPSet(BanSetName, ips)
	e.recordSync(start)
	return err
}

// ReplayOnStart 把库里未过期的封禁全量重灌进系统防火墙。
//
// **必须做**：ipset 是内核内存态，机器重启就没了；Windows 的分片规则虽然能持久化，
// 但也可能被用户手工清理或被组策略刷掉。不重放的话，重启后数据库里明明写着
// "这 200 个 IP 正在封禁中"，实际却一个都没生效——用户完全无从察觉。
// 做法参照威胁情报模块的 RestoreAllOnStartup()。
func (e *BanExecutor) ReplayOnStart() error {
	if global.GWAF_LOCAL_DB == nil {
		return nil
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	now := time.Now().Unix()
	var bans []model.HostGuardBan
	err := global.GWAF_LOCAL_DB.
		Where("status = ? AND (expire_time = 0 OR expire_time > ?)", model.HostBanStatusActive, now).
		Find(&bans).Error
	if err != nil {
		return err
	}
	if len(bans) == 0 {
		return nil
	}

	ips := make([]string, 0, len(bans))
	e.mu.Lock()
	e.current = make(map[string]struct{}, len(bans))
	for _, b := range bans {
		if b.IP == "" {
			continue
		}
		e.current[b.IP] = struct{}{}
		ips = append(ips, b.IP)
	}
	ruleMode := e.useRuleMode()
	e.mu.Unlock()

	start := time.Now()
	if ruleMode {
		// 逐条模式下 BlockIP 自身幂等(内部会查规则是否已存在)
		_, failed, err := e.fw.BlockIPList(ips)
		if len(failed) > 0 {
			zlog.Warn("[主机登录防护] 重放封禁时部分IP失败", "失败数", len(failed))
		}
		e.recordSync(start)
		zlog.Info("[主机登录防护] 已重放封禁规则", "数量", len(ips), "方式", "逐条规则")
		return err
	}

	if err := e.fw.RestoreIPSet(BanSetName, ips); err != nil {
		return err
	}
	e.recordSync(start)
	zlog.Info("[主机登录防护] 已重放封禁集合", "数量", len(ips), "集合", BanSetName)
	return nil
}

// Count 当前集合内的封禁条目数
func (e *BanExecutor) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.current)
}

// Contains 该 IP 当前是否在封禁集合内
func (e *BanExecutor) Contains(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.current[ip]
	return ok
}

// LastSync 返回最近一次同步的时刻与耗时(毫秒)，供状态页展示
func (e *BanExecutor) LastSync() (time.Time, int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastSyncAt, e.lastSyncMs
}

// recordSync 记录同步耗时，超过 5 秒给告警——这通常意味着集合太大或系统防火墙很慢
func (e *BanExecutor) recordSync(start time.Time) {
	elapsed := time.Since(start)
	e.mu.Lock()
	e.lastSyncAt = time.Now()
	e.lastSyncMs = elapsed.Milliseconds()
	count := len(e.current)
	e.mu.Unlock()

	if elapsed > 5*time.Second {
		zlog.Warn("[主机登录防护] 同步封禁到系统防火墙耗时过长，可考虑调大去抖窗口或收紧封禁条数",
			"耗时", elapsed.Round(time.Millisecond).String(), "封禁条数", count)
	}
}

// snapshotLocked 取集合快照(调用方需持锁)
func (e *BanExecutor) snapshotLocked() []string {
	out := make([]string, 0, len(e.current))
	for ip := range e.current {
		out = append(out, ip)
	}
	return out
}
