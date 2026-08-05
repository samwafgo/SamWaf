package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
*
通知频率控制引擎（issue #822）

为什么要把频控从 wafqueue 下沉到这里：

	老实现在 wafqueue/message_queue.go 的 checkCanSend()，有两个致命问题：
	 1. key 用的是「规则原文」，攻击方变换 payload 就会产生新 key，每个新 key 都算"首次出现→立即发送"，
	    冷却形同虚设 —— 这正是 issue #822 里"只要有消息就往飞书发"的直接原因。
	 2. 冷却跨渠道共享，没法做到"飞书只收严重告警、邮件收全量"。

	改到订阅维度后，key = 订阅ID + 可配置的去重维度（默认域名+攻击类型这类稳定字段），
	payload 变换不再能刷新冷却，且每个渠道各管各的。

状态存在进程内而不是 GCACHE_WAFCACHE：频控要做「读-改-写」（冷却级别递增、抑制计数累加），
而缓存没有原子自增，用它会有竞态；且频控状态本来就是进程本地的，没有跨进程共享的必要。
*/

// 内置默认（与升级前的硬编码行为逐项对齐，保证不配置=不变化）
const (
	defaultAggregateWindowSec = 10   // 原 wafqueue.notifyAggFlushInterval
	defaultAggregateMaxDetail = 10   // 原 wafqueue.notifyAggMaxDetail
	defaultCooldownResetSec   = 1800 // 原 30 分钟冷却级别重置
	defaultMaxPerHour         = 0    // 原实现无上限
)

// defaultCooldownStepsSec 原 1分钟 → 5分钟 → 15分钟 递增梯度
var defaultCooldownStepsSec = []int{60, 300, 900}

// defaultDedupKeys 默认去重维度：域名 + 攻击类型
//
// 刻意不含 rule（规则原文）：那正是老实现被绕过的原因。用户确实想按规则细分时可以自己勾上。
var defaultDedupKeys = []string{model.DedupKeyMessageType, model.DedupKeyDomain, model.DedupKeyAttackType}

// SystemConfigItemNotifyGlobal 全局默认频控配置在 system_configs 里的 item 名
const SystemConfigItemNotifyGlobal = "notify_global_throttle"

// 频控判定动作
const (
	ThrottleActionSend      = "send"      // 立即发送
	ThrottleActionAggregate = "aggregate" // 进聚合缓冲区
	ThrottleActionSuppress  = "suppress"  // 抑制，不发送
)

// NotifyGlobalThrottle 全局默认频控配置（存 system_configs，JSON 格式）
type NotifyGlobalThrottle struct {
	Mode      string                     `json:"mode"`       // 默认频控模式
	Config    model.NotifyThrottleConfig `json:"config"`     // 默认频控细项
	DebugMode bool                       `json:"debug_mode"` // 开启后把每次判定链路写 debug 日志
}

// EffectiveThrottle 订阅生效的频控参数（全局默认 + 订阅覆盖 合并后的结果）
type EffectiveThrottle struct {
	Mode               string
	AggregateWindowSec int
	AggregateMaxDetail int
	CooldownStepsSec   []int
	CooldownResetSec   int
	MaxPerHour         int
	DedupKeys          []string
	QuietHours         string
	QuietBypass        string
}

// ThrottleDecision 一次频控判定的结果
type ThrottleDecision struct {
	Action        string // send / aggregate / suppress
	Reason        string // Action=suppress 时的原因（model.SuppressReason*）
	SuppressedNum int    // Action!=suppress 时：本次之前累计被压掉了多少条
	DedupKey      string // 参与判定的去重 key（调试用）
	Effective     EffectiveThrottle
}

// throttleState 单个 (订阅 × 去重key) 的频控状态
type throttleState struct {
	cooldownUntil time.Time // 冷却截止
	level         int       // 当前冷却级别
	levelExpire   time.Time // 冷却级别的重置时间
	suppressed    int       // 本抑制窗口内压掉的条数
	suppressLogID string    // 本抑制窗口写下的那条抑制日志ID（用于最终回填条数）
	suppressLogAt time.Time // 本抑制窗口的日志写入时间，用于滚动
	hourStart     time.Time // 每小时计数窗口起点
	hourCount     int       // 本小时已发送条数
	lastTouch     time.Time // 最近访问时间，用于清理
}

// 状态表容量上限：超过就整体清空。
// 正常情况下 key 数量 = 订阅数 × 去重维度基数，很小；能涨到这个量级只可能是
// 去重维度选了 ip 且遭遇大规模扫描，这时保内存比保精度重要。
const throttleStateMaxEntries = 50000

// suppressLogRollupInterval 抑制日志的滚动间隔
//
// 像「过滤条件未命中」这种永远不会转成发送的抑制，如果只在"下次发送时"回填，
// 那条日志的条数会永远停在 1。所以每隔这个间隔就结算一次，产生一条滚动汇总。
const suppressLogRollupInterval = 10 * time.Minute

// suppressLogPending 日志ID的占位值：已经有协程认领了本窗口的日志写入
const suppressLogPending = "pending"

type WafNotifyThrottleService struct {
	mu     sync.Mutex
	states map[string]*throttleState

	globalMu     sync.RWMutex
	globalCache  NotifyGlobalThrottle
	globalLoaded time.Time
}

var WafNotifyThrottleServiceApp = &WafNotifyThrottleService{
	states: make(map[string]*throttleState),
}

// ========== 全局默认配置 ==========

// BuiltinGlobalThrottle 内置默认（用户从未配置过时使用）
func BuiltinGlobalThrottle() NotifyGlobalThrottle {
	return NotifyGlobalThrottle{
		Mode: model.ThrottleModeAggregate,
		Config: model.NotifyThrottleConfig{
			AggregateWindowSec: defaultAggregateWindowSec,
			AggregateMaxDetail: defaultAggregateMaxDetail,
			CooldownStepsSec:   append([]int{}, defaultCooldownStepsSec...),
			CooldownResetSec:   defaultCooldownResetSec,
			MaxPerHour:         defaultMaxPerHour,
			DedupKeys:          append([]string{}, defaultDedupKeys...),
		},
	}
}

// GetGlobal 取全局默认配置（带 30 秒缓存，避免每条通知都查库）
func (receiver *WafNotifyThrottleService) GetGlobal() NotifyGlobalThrottle {
	receiver.globalMu.RLock()
	if time.Since(receiver.globalLoaded) < 30*time.Second {
		cfg := receiver.globalCache
		receiver.globalMu.RUnlock()
		return cfg
	}
	receiver.globalMu.RUnlock()
	return receiver.loadGlobal()
}

// loadGlobal 从 system_configs 读取全局默认配置
func (receiver *WafNotifyThrottleService) loadGlobal() NotifyGlobalThrottle {
	cfg := BuiltinGlobalThrottle()

	// 数据库还没初始化（进程启动早期、单测）时直接用内置默认，不能让通知链路在这里 panic
	if global.GWAF_LOCAL_DB == nil {
		return cfg
	}

	bean := WafSystemConfigServiceApp.GetDetailByItem(SystemConfigItemNotifyGlobal)
	if strings.TrimSpace(bean.Value) != "" {
		var stored NotifyGlobalThrottle
		if err := json.Unmarshal([]byte(bean.Value), &stored); err == nil {
			if model.IsValidThrottleMode(stored.Mode) && stored.Mode != model.ThrottleModeInherit {
				cfg.Mode = stored.Mode
			}
			stored.Config = stored.Config.Sanitize()
			// 逐项覆盖：全局配置里没填的项继续用内置默认
			if stored.Config.AggregateWindowSec > 0 {
				cfg.Config.AggregateWindowSec = stored.Config.AggregateWindowSec
			}
			if stored.Config.AggregateMaxDetail > 0 {
				cfg.Config.AggregateMaxDetail = stored.Config.AggregateMaxDetail
			}
			if len(stored.Config.CooldownStepsSec) > 0 {
				cfg.Config.CooldownStepsSec = stored.Config.CooldownStepsSec
			}
			if stored.Config.CooldownResetSec > 0 {
				cfg.Config.CooldownResetSec = stored.Config.CooldownResetSec
			}
			if stored.Config.MaxPerHour > 0 {
				cfg.Config.MaxPerHour = stored.Config.MaxPerHour
			}
			if len(stored.Config.DedupKeys) > 0 {
				cfg.Config.DedupKeys = stored.Config.DedupKeys
			}
			cfg.Config.QuietHours = stored.Config.QuietHours
			cfg.Config.QuietHoursBypassSeverity = stored.Config.QuietHoursBypassSeverity
			cfg.DebugMode = stored.DebugMode
		}
	}

	receiver.globalMu.Lock()
	receiver.globalCache = cfg
	receiver.globalLoaded = time.Now()
	receiver.globalMu.Unlock()
	return cfg
}

// SaveGlobal 保存全局默认配置并立即让缓存失效
func (receiver *WafNotifyThrottleService) SaveGlobal(cfg NotifyGlobalThrottle) error {
	if !model.IsValidThrottleMode(cfg.Mode) || cfg.Mode == model.ThrottleModeInherit {
		cfg.Mode = model.ThrottleModeAggregate
	}
	cfg.Config = cfg.Config.Sanitize()

	buf, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	bean := WafSystemConfigServiceApp.GetDetailByItem(SystemConfigItemNotifyGlobal)
	if bean.Id == "" {
		err = WafSystemConfigServiceApp.AddApi(request.WafSystemConfigAddReq{
			ItemClass: "通知管理",
			Item:      SystemConfigItemNotifyGlobal,
			Value:     string(buf),
			Remarks:   "通知全局默认频率控制配置",
		})
	} else {
		err = WafSystemConfigServiceApp.ModifyByItemApi(request.WafSystemConfigEditByItemReq{
			Item:  SystemConfigItemNotifyGlobal,
			Value: string(buf),
		})
	}
	if err != nil {
		return err
	}

	receiver.globalMu.Lock()
	receiver.globalCache = cfg
	receiver.globalLoaded = time.Now()
	receiver.globalMu.Unlock()
	return nil
}

// IsDebugMode 是否开启通知判定调试日志
func (receiver *WafNotifyThrottleService) IsDebugMode() bool {
	return receiver.GetGlobal().DebugMode
}

// ========== 生效配置合并 ==========

// Resolve 把「全局默认」与「订阅覆盖」合并成本次生效的参数
func (receiver *WafNotifyThrottleService) Resolve(sub model.NotifySubscription) EffectiveThrottle {
	g := receiver.GetGlobal()
	subCfg := sub.GetThrottleConfig()

	eff := EffectiveThrottle{
		Mode:               g.Mode,
		AggregateWindowSec: g.Config.AggregateWindowSec,
		AggregateMaxDetail: g.Config.AggregateMaxDetail,
		CooldownStepsSec:   g.Config.CooldownStepsSec,
		CooldownResetSec:   g.Config.CooldownResetSec,
		MaxPerHour:         g.Config.MaxPerHour,
		DedupKeys:          g.Config.DedupKeys,
		QuietHours:         g.Config.QuietHours,
		QuietBypass:        g.Config.QuietHoursBypassSeverity,
	}

	if model.IsValidThrottleMode(sub.ThrottleMode) && sub.ThrottleMode != model.ThrottleModeInherit {
		eff.Mode = sub.ThrottleMode
	}
	if subCfg.AggregateWindowSec > 0 {
		eff.AggregateWindowSec = subCfg.AggregateWindowSec
	}
	if subCfg.AggregateMaxDetail > 0 {
		eff.AggregateMaxDetail = subCfg.AggregateMaxDetail
	}
	if len(subCfg.CooldownStepsSec) > 0 {
		eff.CooldownStepsSec = subCfg.CooldownStepsSec
	}
	if subCfg.CooldownResetSec > 0 {
		eff.CooldownResetSec = subCfg.CooldownResetSec
	}
	if subCfg.MaxPerHour > 0 {
		eff.MaxPerHour = subCfg.MaxPerHour
	}
	if len(subCfg.DedupKeys) > 0 {
		eff.DedupKeys = subCfg.DedupKeys
	}
	// 免打扰是"订阅想单独安静"的场景，订阅填了就以订阅为准，填空串表示显式不启用
	if strings.TrimSpace(sub.ThrottleJSON) != "" {
		eff.QuietHours = subCfg.QuietHours
		eff.QuietBypass = subCfg.QuietHoursBypassSeverity
	}

	// 兜底：任何一项为空都退回内置默认，避免出现 0 窗口 / 空梯度导致除零或死循环
	if eff.AggregateWindowSec <= 0 {
		eff.AggregateWindowSec = defaultAggregateWindowSec
	}
	if eff.AggregateMaxDetail <= 0 {
		eff.AggregateMaxDetail = defaultAggregateMaxDetail
	}
	if len(eff.CooldownStepsSec) == 0 {
		eff.CooldownStepsSec = defaultCooldownStepsSec
	}
	if eff.CooldownResetSec <= 0 {
		eff.CooldownResetSec = defaultCooldownResetSec
	}
	if len(eff.DedupKeys) == 0 {
		eff.DedupKeys = defaultDedupKeys
	}
	if !model.IsValidThrottleMode(eff.Mode) || eff.Mode == model.ThrottleModeInherit {
		eff.Mode = model.ThrottleModeAggregate
	}
	return eff
}

// ========== 判定 ==========

// Decide 判定这条事件在该订阅上应该发送 / 聚合 / 抑制
func (receiver *WafNotifyThrottleService) Decide(sub model.NotifySubscription, ev NotifyEvent) ThrottleDecision {
	eff := receiver.Resolve(sub)
	dedupKey := buildDedupKey(sub.Id, eff.DedupKeys, ev)
	decision := ThrottleDecision{DedupKey: dedupKey, Effective: eff}

	// 1) 过滤条件（纯内存比对，最便宜，放最前面）
	if !MatchNotifyFilter(sub.GetFilterConfig(), ev) {
		decision.Action = ThrottleActionSuppress
		decision.Reason = model.SuppressReasonFilterMiss
		receiver.incSuppressed(dedupKey)
		receiver.debugLog(sub, ev, decision)
		return decision
	}

	// 2) 免打扰时段
	if isInQuietHours(eff.QuietHours, ev.Time) && !severityBypass(eff.QuietBypass, ev.Severity) {
		decision.Action = ThrottleActionSuppress
		decision.Reason = model.SuppressReasonQuietHours
		receiver.incSuppressed(dedupKey)
		receiver.debugLog(sub, ev, decision)
		return decision
	}

	// 冷却/限流一律用当前时钟，不用事件自带的时间：
	// 事件时间是"事情发生的时刻"，可能来自更早的队列积压，拿它做状态推进会让冷却永远算不完。
	now := time.Now()

	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	st := receiver.getStateLocked(dedupKey, now)

	// 3) 每小时上限（0=不限）
	if eff.MaxPerHour > 0 {
		if now.Sub(st.hourStart) >= time.Hour {
			st.hourStart = now
			st.hourCount = 0
		}
		if st.hourCount >= eff.MaxPerHour {
			st.suppressed++
			decision.Action = ThrottleActionSuppress
			decision.Reason = model.SuppressReasonRateLimit
			receiver.debugLog(sub, ev, decision)
			return decision
		}
	}

	// 4) 频控模式
	switch eff.Mode {
	case model.ThrottleModeRealtime:
		decision.Action = ThrottleActionSend
		decision.SuppressedNum = st.suppressed

	case model.ThrottleModeAggregate:
		// 聚合模式下是否发送由聚合器的窗口决定，这里只放行入桶
		decision.Action = ThrottleActionAggregate
		decision.SuppressedNum = st.suppressed

	default: // cooldown
		if now.Before(st.cooldownUntil) {
			st.suppressed++
			decision.Action = ThrottleActionSuppress
			decision.Reason = model.SuppressReasonCooldown
			receiver.debugLog(sub, ev, decision)
			return decision
		}
		// 冷却级别过期则回落到初始级别，恢复灵敏度
		if !st.levelExpire.IsZero() && now.After(st.levelExpire) {
			st.level = 0
		}
		cooldown := time.Duration(cooldownStepAt(eff.CooldownStepsSec, st.level)) * time.Second
		st.cooldownUntil = now.Add(cooldown)
		st.level++
		st.levelExpire = now.Add(time.Duration(eff.CooldownResetSec) * time.Second)

		decision.Action = ThrottleActionSend
		decision.SuppressedNum = st.suppressed
	}

	receiver.debugLog(sub, ev, decision)
	return decision
}

// DryRunResult 干跑结果
type DryRunResult struct {
	WouldSend    bool              `json:"would_send"`    // 现在来一条事件会不会发出去
	Action       string            `json:"action"`        // send/aggregate/suppress
	Reason       string            `json:"reason"`        // 被拦时的原因
	ReasonText   string            `json:"reason_text"`   // 原因的中文说明
	CooldownLeft int               `json:"cooldown_left"` // 冷却剩余秒数
	HourUsed     int               `json:"hour_used"`     // 本小时已发送条数
	Suppressed   int               `json:"suppressed"`    // 当前累计被抑制条数
	Effective    EffectiveThrottle `json:"-"`
	DedupKey     string            `json:"dedup_key"`
}

// DryRun 干跑：用样例事件演算一遍判定链路，只读不改状态
//
// "为什么我收不到通知"这个问题，用户自己点一下就能得到答案，不用再翻日志或者提 issue。
func (receiver *WafNotifyThrottleService) DryRun(sub model.NotifySubscription) DryRunResult {
	ev := SampleNotifyEvent(sub.MessageType)
	eff := receiver.Resolve(sub)
	dedupKey := buildDedupKey(sub.Id, eff.DedupKeys, ev)
	res := DryRunResult{Effective: eff, DedupKey: dedupKey}

	if sub.Status != 1 {
		res.Action, res.Reason, res.ReasonText = ThrottleActionSuppress, "disabled", "该订阅已被禁用"
		return res
	}
	if !MatchNotifyFilter(sub.GetFilterConfig(), ev) {
		res.Action, res.Reason, res.ReasonText = ThrottleActionSuppress, model.SuppressReasonFilterMiss, "样例事件未命中过滤条件"
		return res
	}
	now := time.Now()
	if isInQuietHours(eff.QuietHours, now) && !severityBypass(eff.QuietBypass, ev.Severity) {
		res.Action, res.Reason, res.ReasonText = ThrottleActionSuppress, model.SuppressReasonQuietHours, "当前处于免打扰时段 "+eff.QuietHours
		return res
	}

	receiver.mu.Lock()
	st, exists := receiver.states[dedupKey]
	if exists {
		res.Suppressed = st.suppressed
		if now.Sub(st.hourStart) < time.Hour {
			res.HourUsed = st.hourCount
		}
		if now.Before(st.cooldownUntil) {
			res.CooldownLeft = int(st.cooldownUntil.Sub(now).Seconds())
		}
	}
	receiver.mu.Unlock()

	if eff.MaxPerHour > 0 && res.HourUsed >= eff.MaxPerHour {
		res.Action, res.Reason = ThrottleActionSuppress, model.SuppressReasonRateLimit
		res.ReasonText = fmt.Sprintf("本小时已发送 %d 条，达到上限 %d", res.HourUsed, eff.MaxPerHour)
		return res
	}

	switch eff.Mode {
	case model.ThrottleModeRealtime:
		res.Action, res.WouldSend, res.ReasonText = ThrottleActionSend, true, "直发模式，会立即发送"
	case model.ThrottleModeAggregate:
		res.Action, res.WouldSend = ThrottleActionAggregate, true
		res.ReasonText = fmt.Sprintf("聚合模式，最多 %d 秒后合并发送", eff.AggregateWindowSec)
	default:
		if res.CooldownLeft > 0 {
			res.Action, res.Reason = ThrottleActionSuppress, model.SuppressReasonCooldown
			res.ReasonText = fmt.Sprintf("处于冷却期，还剩 %d 秒", res.CooldownLeft)
			return res
		}
		res.Action, res.WouldSend, res.ReasonText = ThrottleActionSend, true, "冷却已结束，会立即发送"
	}
	return res
}

// NoteSent 实际发出去以后回调：清空抑制计数、累加小时计数，并返回需要回填的抑制日志ID
//
// 返回的 (logId, count) 由调用方去更新那条 status=2 的抑制日志，
// 这样一个抑制窗口无论压掉多少条，都只产生 2 次数据库写入（首条插入 + 结束回填）。
func (receiver *WafNotifyThrottleService) NoteSent(dedupKey string) (string, int) {
	now := time.Now()
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	st := receiver.getStateLocked(dedupKey, now)

	if st.hourStart.IsZero() || now.Sub(st.hourStart) >= time.Hour {
		st.hourStart = now
		st.hourCount = 0
	}
	st.hourCount++

	logID, count := st.suppressLogID, st.suppressed
	st.suppressed = 0
	st.suppressLogID = ""
	return logID, count
}

// SuppressLogAction 抑制日志的写入指令
type SuppressLogAction struct {
	WriteNew      bool   // 需要新写一条 status=2 的抑制日志
	FinalizeLogID string // 需要把这条旧日志的抑制条数回填成 FinalizeCount
	FinalizeCount int
}

// OnSuppress 抑制发生时调用，决定要不要落日志
//
// 核心约束：抑制日志本身不能把库刷爆。所以一个抑制窗口只写一条日志，
// 期间的条数在内存里累加，窗口结束（真正发出一条 / 超过滚动间隔）时一次性回填。
// 压掉 10000 条只产生 2 次数据库写入。
func (receiver *WafNotifyThrottleService) OnSuppress(dedupKey string) SuppressLogAction {
	now := time.Now()
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	st := receiver.getStateLocked(dedupKey, now)

	// 已有窗口且还没到滚动时间 → 只计数，不写日志
	if st.suppressLogID != "" {
		if now.Sub(st.suppressLogAt) < suppressLogRollupInterval {
			return SuppressLogAction{}
		}
		// 到滚动时间：回填旧的那条，然后开新窗口
		action := SuppressLogAction{
			WriteNew:      true,
			FinalizeLogID: st.suppressLogID,
			FinalizeCount: st.suppressed,
		}
		st.suppressed = 1
		st.suppressLogID = suppressLogPending
		st.suppressLogAt = now
		return action
	}

	st.suppressLogID = suppressLogPending
	st.suppressLogAt = now
	return SuppressLogAction{WriteNew: true}
}

// incSuppressed 累加抑制条数（用于在 Decide 里没持锁的分支）
func (receiver *WafNotifyThrottleService) incSuppressed(dedupKey string) {
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	receiver.getStateLocked(dedupKey, time.Now()).suppressed++
}

// SetSuppressLogID 把刚写下的抑制日志ID登记到状态里，供后续回填
func (receiver *WafNotifyThrottleService) SetSuppressLogID(dedupKey, logID string) {
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	st := receiver.getStateLocked(dedupKey, time.Now())
	if st.suppressLogID == suppressLogPending {
		st.suppressLogID = logID
	}
}

// ResetAll 清空全部频控状态（单测与"立即生效"场景使用）
func (receiver *WafNotifyThrottleService) ResetAll() {
	receiver.mu.Lock()
	receiver.states = make(map[string]*throttleState)
	receiver.mu.Unlock()

	receiver.globalMu.Lock()
	receiver.globalLoaded = time.Time{}
	receiver.globalMu.Unlock()
}

// getStateLocked 取状态，顺带做过期清理（调用前必须持有 receiver.mu）
func (receiver *WafNotifyThrottleService) getStateLocked(key string, now time.Time) *throttleState {
	if st, ok := receiver.states[key]; ok {
		st.lastTouch = now
		return st
	}

	// 容量保护：状态表本身不能成为内存泄漏点
	if len(receiver.states) >= throttleStateMaxEntries {
		receiver.cleanupLocked(now)
		if len(receiver.states) >= throttleStateMaxEntries {
			zlog.Warn("通知频控状态表超出上限，已整体清空", "entries", len(receiver.states))
			receiver.states = make(map[string]*throttleState)
		}
	}

	st := &throttleState{lastTouch: now, hourStart: now}
	receiver.states[key] = st
	return st
}

// cleanupLocked 清掉一小时没被碰过、且没有待回填抑制日志的状态
func (receiver *WafNotifyThrottleService) cleanupLocked(now time.Time) {
	for k, st := range receiver.states {
		if now.Sub(st.lastTouch) > time.Hour && st.suppressLogID == "" {
			delete(receiver.states, k)
		}
	}
}

// debugLog 判定链路调试日志（默认关闭，系统设置里打开）
func (receiver *WafNotifyThrottleService) debugLog(sub model.NotifySubscription, ev NotifyEvent, d ThrottleDecision) {
	if !receiver.IsDebugMode() {
		return
	}
	zlog.Debug(fmt.Sprintf("[通知调试] 订阅=%s 渠道=%s 类型=%s 模式=%s 动作=%s 原因=%s 去重key=%s 已抑制=%d",
		sub.Id, sub.ChannelId, ev.MessageType, d.Effective.Mode, d.Action, d.Reason, d.DedupKey, d.SuppressedNum))
}

// ========== 工具 ==========

// buildDedupKey 按配置的去重维度拼出频控 key
//
// 用哈希而不是原文：维度里可能带 URL/规则原文这种超长且含任意字符的串，
// 原文直接做 map key 会让内存和日志都不可控。
func buildDedupKey(subId string, dedupKeys []string, ev NotifyEvent) string {
	parts := make([]string, 0, len(dedupKeys)+1)
	for _, k := range dedupKeys {
		v := ev.DedupParts[k]
		if v == "" {
			continue // 该事件没有这个维度就跳过，不能因为缺维度把不同事件混成一个key
		}
		if len(v) > 256 {
			v = v[:256]
		}
		parts = append(parts, k+"="+v)
	}
	raw := strings.Join(parts, "|")
	sum := sha1.Sum([]byte(raw))
	return subId + ":" + hex.EncodeToString(sum[:])[:16]
}

// cooldownStepAt 取第 level 级冷却时长，超出梯度长度则取最后一级（封顶）
func cooldownStepAt(steps []int, level int) int {
	if len(steps) == 0 {
		return defaultCooldownStepsSec[0]
	}
	if level < 0 {
		level = 0
	}
	if level >= len(steps) {
		return steps[len(steps)-1]
	}
	return steps[level]
}

// isInQuietHours 判断当前是否落在免打扰时段，支持跨天（如 23:00-07:00）
func isInQuietHours(quietHours string, now time.Time) bool {
	if !model.IsValidQuietHours(quietHours) || quietHours == "" {
		return false
	}
	parts := strings.Split(quietHours, "-")
	start, ok1 := parseHHMM(strings.TrimSpace(parts[0]))
	end, ok2 := parseHHMM(strings.TrimSpace(parts[1]))
	if !ok1 || !ok2 || start == end {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	cur := now.Hour()*60 + now.Minute()
	if start < end {
		return cur >= start && cur < end
	}
	// 跨天：23:00-07:00 => [23:00, 24:00) ∪ [00:00, 07:00)
	return cur >= start || cur < end
}

func parseHHMM(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h, err1 := strconv.Atoi(s[0:2])
	m, err2 := strconv.Atoi(s[3:5])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// severityBypass 该级别是否可以穿透免打扰
func severityBypass(bypass, severity string) bool {
	if bypass == "" {
		return false
	}
	return model.SeverityLevel(severity) >= model.SeverityLevel(bypass)
}

// MatchNotifyFilter 过滤条件判定：命中返回 true（可以发送）
//
// 空配置一律放行。宁可多发也不能因为一条脏配置把告警全吞掉。
func MatchNotifyFilter(filter model.NotifyFilterConfig, ev NotifyEvent) bool {
	if filter.IsEmpty() {
		return true
	}

	// 最低严重级别
	if filter.MinSeverity != "" && model.SeverityLevel(ev.Severity) < model.SeverityLevel(filter.MinSeverity) {
		return false
	}

	// 域名白名单（事件本身没有域名维度时不拦，例如周报/系统错误）
	if len(filter.Domains) > 0 {
		domain := ev.DedupParts[model.DedupKeyDomain]
		if domain != "" && !matchDomainList(filter.Domains, domain) {
			return false
		}
	}

	// IP 排除（支持 CIDR）
	if len(filter.ExcludeIps) > 0 {
		ip := ev.DedupParts[model.DedupKeyIp]
		if ip != "" && matchIPList(filter.ExcludeIps, ip) {
			return false
		}
	}

	// 关键字：规则信息 / 攻击类型 / URL / 正文 命中任一即可
	if len(filter.Keywords) > 0 {
		haystack := strings.ToLower(strings.Join([]string{
			ev.Vars["RuleInfo"], ev.Vars["AttackType"], ev.Vars["Url"],
			ev.Vars["Reason"], ev.Vars["ErrorType"], ev.DefaultContent,
		}, "\n"))
		hit := false
		for _, kw := range filter.Keywords {
			kw = strings.ToLower(strings.TrimSpace(kw))
			if kw == "" {
				continue
			}
			if strings.Contains(haystack, kw) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}

	return true
}

// matchDomainList 域名匹配，支持 *.a.com 形式的通配
func matchDomainList(list []string, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, item := range list {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if item == domain {
			return true
		}
		if strings.HasPrefix(item, "*.") {
			suffix := item[1:] // ".a.com"
			if strings.HasSuffix(domain, suffix) {
				return true
			}
			if domain == item[2:] { // *.a.com 也认为覆盖 a.com 本身
				return true
			}
		}
	}
	return false
}

// matchIPList IP 匹配，支持单 IP 与 CIDR
func matchIPList(list []string, ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			if _, cidr, err := net.ParseCIDR(item); err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if other := net.ParseIP(item); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}
