package wafhostguard

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"fmt"
	"time"
)

// 处置执行：把"这个 IP 该封了"变成数据库记录 + 系统防火墙规则 + 一条通知。

// BanRequest 一次封禁请求
type BanRequest struct {
	IP        string
	Source    string
	HitCount  int64
	FailKinds string // 触发时窗口内出现过的失败类型/用户名摘要，写进原因文本
	Manual    bool   // 手工封禁(来自页面操作)，不走阈值也不受观察模式限制
	ManualMin int64  // 手工封禁时长(分钟)，0=永久
	Reason    string // 手工封禁时的自定义原因
}

// BanResult 封禁结果
type BanResult struct {
	Banned     bool   // 是否真的下发了封禁
	Observed   bool   // 观察模式下"本应封禁但没动手"
	Skipped    string // 未封禁的原因(白名单/限速/容量满/已封禁)
	Level      int
	BanMinutes int64
	ExpireTime int64
	IsSubnet   bool
	TargetIP   string // 实际封禁目标(网段聚合时是 CIDR)
}

// ApplyBan 执行一次封禁决策。
//
// 顺序刻意如此：白名单 -> 已封禁去重 -> 限速 -> 容量 -> 阶梯 -> 网段聚合 -> 落库 -> 下发 -> 通知。
// 前四道闸都在"动系统防火墙"之前，任何一道拦下都不会留下需要回滚的副作用。
func ApplyBan(req BanRequest, now time.Time) BanResult {
	res := BanResult{TargetIP: req.IP}

	// 硬开关：conf/config.yml 或环境变量强制关闭时，连手工封禁也不放行——
	// 这个开关的使用场景就是"出事了，先让它彻底别动手"。
	if global.GCONFIG_HOST_GUARD_FORCE_DISABLE {
		res.Skipped = "已被配置文件强制关闭主机防爆破"
		return res
	}

	if !req.Manual {
		if white, reason := IsWhitelisted(req.IP); white {
			res.Skipped = "白名单豁免(" + reason + ")"
			return res
		}
	}

	exec := GetBanExecutor()
	if exec.Contains(req.IP) {
		res.Skipped = "该IP已在封禁中"
		return res
	}

	if !req.Manual {
		if !allowBanRate() {
			res.Skipped = "已达每分钟新增封禁上限，本次跳过"
			zlog.Warn("[主机登录防护] 触发封禁限速，可能正在遭遇分布式爆破",
				"ip", req.IP, "上限", global.GCONFIG_HOST_GUARD_BAN_RATE_LIMIT)
			return res
		}
		if !ensureCapacity(now) {
			res.Skipped = "封禁集合已达容量上限且无可淘汰的临时封禁"
			zlog.Warn("[主机登录防护] 封禁集合已满，请在页面上清理永久封禁或调大容量上限",
				"上限", global.GCONFIG_HOST_GUARD_MAX_BAN_ENTRIES)
			return res
		}
	}

	// 阶梯决策
	offender := loadOffender(req.IP)
	var level int
	var banMinutes int64
	var banCount int64
	if req.Manual {
		level = 0
		banMinutes = req.ManualMin
		banCount = 1
		if offender != nil {
			banCount = offender.BanCount + 1
		}
	} else {
		d := DecideLadder(offender, now)
		level, banMinutes, banCount = d.Level, d.BanMinutes, d.BanCount
		if d.Reset {
			zlog.Debug("[主机登录防护] 该IP超过累犯记忆期，阶梯重置", "ip", req.IP)
		}
	}
	res.Level = level
	res.BanMinutes = banMinutes

	// 网段聚合(默认关)
	target := req.IP
	if !req.Manual {
		if cidr, agg := ShouldAggregateSubnet(req.IP, now); agg {
			target = cidr
			res.IsSubnet = true
			zlog.Warn("[主机登录防护] 同网段被封IP数达到阈值，升级为整段封禁", "网段", cidr)
		}
	}
	res.TargetIP = target

	var expireTime int64
	if banMinutes > 0 {
		expireTime = now.Add(time.Duration(banMinutes) * time.Minute).Unix()
	}
	res.ExpireTime = expireTime

	reason := req.Reason
	if reason == "" {
		reason = buildReason(req, level, banMinutes)
	}

	// 观察模式：到此为止，只记录不动手。
	// 这是整个功能的安全底线，必须保证一行防火墙规则都不写、一条通知都不发
	//(发了通知用户会以为真封了)。
	if !req.Manual && global.GCONFIG_HOST_GUARD_MODE != "block" {
		res.Observed = true
		zlog.Info(fmt.Sprintf("[主机登录防护][观察模式] 本应封禁 %s 第%d级%s（%s），当前仅记录不处置",
			target, level, humanDuration(banMinutes), reason))
		return res
	}

	// 落库在下发之前：先有账本再有规则。
	// 反过来的话，写库失败会留下一条"防火墙里有、数据库里没有"的孤儿规则，
	// 到期没人解封，用户还查不到它是谁封的。
	ban := model.HostGuardBan{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		},
		IP:         target,
		Source:     req.Source,
		Level:      level,
		BanMinutes: banMinutes,
		StartTime:  now.Unix(),
		ExpireTime: expireTime,
		Reason:     reason,
		Status:     model.HostBanStatusActive,
		ExecMode:   exec.ExecMode(),
		HitCount:   req.HitCount,
		Location:   utils.FormatIPLocation(req.IP),
	}
	if res.IsSubnet {
		ban.IsSubnet = 1
	}
	if global.GWAF_LOCAL_DB != nil {
		if err := global.GWAF_LOCAL_DB.Create(&ban).Error; err != nil {
			zlog.Error("[主机登录防护] 写入封禁记录失败，已放弃本次封禁", "ip", target, "error", err.Error())
			res.Skipped = "写入封禁记录失败：" + err.Error()
			return res
		}
	}

	if err := exec.Apply([]string{target}, nil); err != nil {
		// 下发失败就把账本回滚掉，不留"库里说封了、实际没封"的假象
		if global.GWAF_LOCAL_DB != nil {
			global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
				Where("id = ?", ban.Id).
				Updates(map[string]interface{}{"status": model.HostBanStatusReleased, "remarks": "下发系统防火墙失败：" + err.Error()})
		}
		zlog.Error("[主机登录防护] 下发系统防火墙失败", "ip", target, "error", err.Error())
		res.Skipped = "下发系统防火墙失败：" + err.Error()
		return res
	}

	upsertOffender(req, target, level, banCount, reason, now)
	markBanned(target, banMinutes)
	res.Banned = true

	zlog.Info("[主机登录防护] 已封禁", "ip", target, "来源", req.Source,
		"阶梯", level, "时长", humanDuration(banMinutes), "窗口内失败次数", req.HitCount)

	notifyBan(target, reason, banMinutes, expireTime, now)
	return res
}

// buildReason 生成给人看的封禁原因
func buildReason(req BanRequest, level int, banMinutes int64) string {
	src := "SSH"
	if req.Source == SourceRDP {
		src = "RDP"
	}
	reason := fmt.Sprintf("%s登录爆破：%d分钟内失败%d次", src, global.GCONFIG_HOST_GUARD_FIND_TIME, req.HitCount)
	if req.FailKinds != "" {
		reason += "（" + req.FailKinds + "）"
	}
	reason += fmt.Sprintf("，第%d级封禁%s", level, humanDuration(banMinutes))
	return reason
}

// humanDuration 把分钟数说成人话
func humanDuration(minutes int64) string {
	switch {
	case minutes <= 0:
		return "永久"
	case minutes < 60:
		return fmt.Sprintf("%d分钟", minutes)
	case minutes < 1440:
		return fmt.Sprintf("%d小时", minutes/60)
	default:
		return fmt.Sprintf("%d天", minutes/1440)
	}
}

// loadOffender 读攻击者档案，没有返回 nil
func loadOffender(ip string) *model.HostGuardOffender {
	if global.GWAF_LOCAL_DB == nil {
		return nil
	}
	var o model.HostGuardOffender
	err := global.GWAF_LOCAL_DB.Where("ip = ?", ip).First(&o).Error
	if err != nil {
		return nil
	}
	return &o
}

// upsertOffender 更新/新建攻击者档案。累犯次数是阶梯递进的唯一依据，必须持久化。
func upsertOffender(req BanRequest, target string, level int, banCount int64, reason string, now time.Time) {
	if global.GWAF_LOCAL_DB == nil {
		return
	}
	// 档案按真实来源 IP 记，不按聚合后的网段——否则整段封一次会把网段本身
	// 变成一个"攻击者"，而真正那个 IP 的累犯次数反倒不增长了
	ip := req.IP
	existing := loadOffender(ip)
	if existing == nil {
		o := model.HostGuardOffender{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(now),
				UPDATE_TIME: customtype.JsonTime(now),
			},
			IP:             ip,
			Source:         req.Source,
			BanCount:       banCount,
			CurrentLevel:   level,
			FirstBanTime:   now.Unix(),
			LastBanTime:    now.Unix(),
			TotalFailCount: req.HitCount,
			LastReason:     reason,
			Location:       utils.FormatIPLocation(ip),
		}
		if err := global.GWAF_LOCAL_DB.Create(&o).Error; err != nil {
			zlog.Warn("[主机登录防护] 创建攻击者档案失败", "ip", ip, "error", err.Error())
		}
		return
	}

	err := global.GWAF_LOCAL_DB.Model(&model.HostGuardOffender{}).
		Where("id = ?", existing.Id).
		Updates(map[string]interface{}{
			"source":           req.Source,
			"ban_count":        banCount,
			"current_level":    level,
			"last_ban_time":    now.Unix(),
			"total_fail_count": existing.TotalFailCount + req.HitCount,
			"last_reason":      reason,
			"update_time":      customtype.JsonTime(now),
		}).Error
	if err != nil {
		zlog.Warn("[主机登录防护] 更新攻击者档案失败", "ip", ip, "error", err.Error())
	}
}

// markBanned 打去重标记，TTL 与封禁时长一致(永久封给 24 小时，靠 executor 的内存镜像兜底)
func markBanned(ip string, banMinutes int64) {
	if global.GCACHE_WAFCACHE == nil {
		return
	}
	ttl := 24 * time.Hour
	if banMinutes > 0 {
		ttl = time.Duration(banMinutes) * time.Minute
	}
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_HOST_GUARD_BANNED_PRE+ip, 1, ttl)
}

// allowBanRate 每分钟新增封禁限速。
// 分布式爆破一次能带来成百上千个源 IP，不限速的话集合瞬间被打满，
// 后面真正该封的反而挤不进来。
func allowBanRate() bool {
	limit := global.GCONFIG_HOST_GUARD_BAN_RATE_LIMIT
	if limit <= 0 || global.GCACHE_WAFCACHE == nil {
		return true
	}
	key := enums.CACHE_HOST_GUARD_RATE + ":" + time.Now().Format("200601021504")
	curInt, _ := global.GCACHE_WAFCACHE.GetInt(key) // 键不存在时返回 0，正是想要的初值
	cur := int64(curInt)
	if cur >= limit {
		return false
	}
	// 窗口是"当前这一分钟"，给 2 分钟 TTL 让它自然过期
	global.GCACHE_WAFCACHE.SetWithTTl(key, int(cur+1), 2*time.Minute)
	return true
}

// ensureCapacity 保证集合还装得下。超限时淘汰"剩余时间最短的临时封禁"——
// 它们本来也马上就要解封了，牺牲它们的代价最小；永久封禁一律不动，
// 那是用户明确表达过"这个必须一直封着"的意思。
func ensureCapacity(now time.Time) bool {
	limit := global.GCONFIG_HOST_GUARD_MAX_BAN_ENTRIES
	if limit <= 0 {
		return true
	}
	exec := GetBanExecutor()
	if int64(exec.Count()) < limit {
		return true
	}
	if global.GWAF_LOCAL_DB == nil {
		return false
	}

	// 一次多淘汰几个，避免每封一个就查一次库
	const evictBatch = 16
	var victims []model.HostGuardBan
	err := global.GWAF_LOCAL_DB.
		Where("status = ? AND expire_time > 0", model.HostBanStatusActive).
		Order("expire_time asc").
		Limit(evictBatch).
		Find(&victims).Error
	if err != nil || len(victims) == 0 {
		return false
	}

	ips := make([]string, 0, len(victims))
	ids := make([]string, 0, len(victims))
	for _, v := range victims {
		ips = append(ips, v.IP)
		ids = append(ids, v.Id)
	}
	if err := exec.Apply(nil, ips); err != nil {
		zlog.Warn("[主机登录防护] 容量淘汰时解封失败", "error", err.Error())
	}
	global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
		Where("id in ?", ids).
		Updates(map[string]interface{}{
			"status":  model.HostBanStatusReleased,
			"remarks": "封禁集合达到容量上限，按剩余时间最短优先淘汰",
		})
	zlog.Warn("[主机登录防护] 封禁集合达到容量上限，已淘汰部分临时封禁", "淘汰数", len(ips))
	return true
}

// notifyBan 发封禁通知。复用已有的「IP封禁」消息类型，模板/频控/多渠道全都是现成的。
func notifyBan(ip, reason string, banMinutes, expireTime int64, now time.Time) {
	if global.GCONFIG_HOST_GUARD_NOTIFY != 1 || global.GQEQUE_MESSAGE_DB == nil {
		return
	}
	remaining := 0
	if expireTime > 0 {
		remaining = int(expireTime - now.Unix())
	}
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.IPBanMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{
			OperaType: "主机远程登录爆破封禁",
			Server:    global.GWAF_CUSTOM_SERVER_NAME,
		},
		Ip:               ip,
		Reason:           reason + "。如误封需手工解除：Linux 执行 `ipset del " + BanSetName + " " + ip + "`，Windows 在高级安全防火墙中删除对应规则",
		Duration:         int(banMinutes),
		RemainingSeconds: remaining,
		Time:             now.Format("2006-01-02 15:04:05"),
	})
}
