package wafhostguard

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"sort"
	"sync"
	"time"
)

// 阶梯递进封禁。同一个 IP 第 N 次被封就用第 N 级的时长：
// 默认 5分 → 15分 → 60分 → 1天 → 永久。
//
// 之所以第一级只有 5 分钟：绝大多数"触发阈值"的其实是管理员自己敲错密码、
// 或者扫描器随手扫一下。5 分钟的代价用户等得起，而真正的爆破者会在解封后
// 立刻再来，于是被顶到第 2、3 级——惩罚自动向真正的攻击者倾斜。

const ladderCacheTTL = time.Minute

var (
	ladderMu      sync.RWMutex
	ladderCache   []model.HostGuardBanLadder
	ladderLoadAt  time.Time
	ladderLoadErr error
)

// InvalidateLadder 丢弃阶梯缓存(页面上改完阶梯后调用)
func InvalidateLadder() {
	ladderMu.Lock()
	ladderCache = nil
	ladderMu.Unlock()
}

// loadLadders 读取启用中的阶梯，按 Level 升序。带 1 分钟缓存——
// 每次封禁都查库没必要，但也不能缓存太久，用户改完阶梯要能较快看到效果。
func loadLadders() []model.HostGuardBanLadder {
	ladderMu.RLock()
	if ladderCache != nil && time.Since(ladderLoadAt) < ladderCacheTTL {
		l := ladderCache
		ladderMu.RUnlock()
		return l
	}
	ladderMu.RUnlock()

	ladderMu.Lock()
	defer ladderMu.Unlock()
	if ladderCache != nil && time.Since(ladderLoadAt) < ladderCacheTTL {
		return ladderCache
	}

	var list []model.HostGuardBanLadder
	if global.GWAF_LOCAL_DB != nil {
		if err := global.GWAF_LOCAL_DB.Where("enable = ?", 1).Find(&list).Error; err != nil {
			zlog.Warn("[主机登录防护] 读取封禁阶梯失败，回退到内置默认阶梯", "error", err.Error())
			list = nil
		}
	}
	if len(list) == 0 {
		// 库里没有(迁移未跑/被用户清空)时用内置默认，绝不能因为阶梯为空就不封禁
		list = model.DefaultBanLadders()
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Level < list[j].Level })

	ladderCache = list
	ladderLoadAt = time.Now()
	return list
}

// LadderDecision 阶梯决策结果
type LadderDecision struct {
	Level      int   // 命中的级别
	BanMinutes int64 // 封禁时长(分钟)，0=永久
	BanCount   int64 // 这是该 IP 第几次被封
	Reset      bool  // 是否因超过记忆期而重置回第一级
}

// DecideLadder 根据攻击者档案决定这次封多久。
//
// offender 为 nil 表示这个 IP 第一次被封。
// 记忆期(host_guard_offender_reset_day，默认 7 天)内没有再犯的，下次从第 1 级重新开始——
// 不然一个几个月前误触过一次的 IP，今天再犯就直接被顶到高级别，惩罚与行为不匹配。
func DecideLadder(offender *model.HostGuardOffender, now time.Time) LadderDecision {
	ladders := loadLadders()

	banCount := int64(1)
	reset := false
	if offender != nil && offender.BanCount > 0 {
		resetDays := global.GCONFIG_HOST_GUARD_OFFENDER_RESET_DAY
		if resetDays > 0 && offender.LastBanTime > 0 {
			idleDays := now.Sub(time.Unix(offender.LastBanTime, 0)).Hours() / 24
			if idleDays > float64(resetDays) {
				reset = true
			}
		}
		if !reset {
			banCount = offender.BanCount + 1
		}
	}

	// 次数超过最高级就一直用最高级
	idx := int(banCount) - 1
	if idx >= len(ladders) {
		idx = len(ladders) - 1
	}
	if idx < 0 {
		idx = 0
	}
	chosen := ladders[idx]

	return LadderDecision{
		Level:      chosen.Level,
		BanMinutes: chosen.BanMinutes,
		BanCount:   banCount,
		Reset:      reset,
	}
}
