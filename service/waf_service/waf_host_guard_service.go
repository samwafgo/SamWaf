package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafhostguard"
	"errors"
	"strings"
	"sync"
	"time"
)

// 主机防爆破的数据服务：事件、封禁账本、攻击者档案、阶梯配置。

type WafHostGuardService struct {
	// 事件写入缓冲。爆破高峰下每秒几十上百条，逐条 INSERT 会把加密 SQLite
	// 打成慢查询——观察模式尤其明显(所有事件都要落库，一条都不过滤)。
	bufMu      sync.Mutex
	buf        []model.HostLoginEvent
	flushTimer *time.Timer
}

var WafHostGuardServiceApp = new(WafHostGuardService)

const (
	// eventFlushSize 攒够这么多条就写一次
	eventFlushSize = 50
	// eventFlushInterval 或者最多攒这么久，保证低频时事件也能及时可见
	eventFlushInterval = time.Second
)

// InitEventSink 把事件落库能力注入 wafhostguard。
//
// 用注入而不是让 wafhostguard 直接 import service：
// service 层已经引了 wafhostguard(要调封禁/白名单)，反过来再引就成环了。
func (receiver *WafHostGuardService) InitEventSink() {
	wafhostguard.SetEventSink(receiver.RecordEvent)
}

// RecordEvent 收一条事件进缓冲
func (receiver *WafHostGuardService) RecordEvent(ev model.HostLoginEvent) {
	receiver.bufMu.Lock()
	receiver.buf = append(receiver.buf, ev)
	needFlush := len(receiver.buf) >= eventFlushSize
	if receiver.flushTimer == nil {
		receiver.flushTimer = time.AfterFunc(eventFlushInterval, func() {
			receiver.FlushEvents()
		})
	}
	receiver.bufMu.Unlock()

	if needFlush {
		receiver.FlushEvents()
	}
}

// FlushEvents 把缓冲写库。停止采集时必须调一次，否则最后一批事件会丢。
func (receiver *WafHostGuardService) FlushEvents() {
	receiver.bufMu.Lock()
	if len(receiver.buf) == 0 {
		if receiver.flushTimer != nil {
			receiver.flushTimer.Stop()
			receiver.flushTimer = nil
		}
		receiver.bufMu.Unlock()
		return
	}
	batch := receiver.buf
	receiver.buf = nil
	if receiver.flushTimer != nil {
		receiver.flushTimer.Stop()
		receiver.flushTimer = nil
	}
	receiver.bufMu.Unlock()

	if global.GWAF_LOCAL_LOG_DB == nil {
		return
	}
	now := time.Now()
	for i := range batch {
		batch[i].BaseOrm = baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		}
	}
	if err := global.GWAF_LOCAL_LOG_DB.CreateInBatches(batch, eventFlushSize).Error; err != nil {
		zlog.Warn("[主机登录防护] 写入登录失败事件失败", "条数", len(batch), "error", err.Error())
	}
}

// GetEventList 分页查询登录失败事件
func (receiver *WafHostGuardService) GetEventList(req request.WafHostGuardEventSearchReq) ([]model.HostLoginEvent, int64, error) {
	var list []model.HostLoginEvent
	var total int64
	if global.GWAF_LOCAL_LOG_DB == nil {
		return list, 0, nil
	}

	query := global.GWAF_LOCAL_LOG_DB.Model(&model.HostLoginEvent{})
	if req.Source != "" {
		query = query.Where("source = ?", req.Source)
	}
	if req.IP != "" {
		query = query.Where("ip LIKE ?", "%"+req.IP+"%")
	}
	if req.UserName != "" {
		query = query.Where("user_name LIKE ?", "%"+req.UserName+"%")
	}
	if req.FailKind != "" {
		query = query.Where("fail_kind = ?", req.FailKind)
	}
	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}
	if req.StartTime > 0 {
		query = query.Where("event_time >= ?", req.StartTime)
	}
	if req.EndTime > 0 {
		query = query.Where("event_time <= ?", req.EndTime)
	}

	query.Count(&total)
	err := query.Order("event_time DESC").
		Limit(req.PageSize).
		Offset(req.PageSize * (req.PageIndex - 1)).
		Find(&list).Error
	return list, total, err
}

// GetBanList 分页查询封禁记录。status 留空默认只看生效中的——
// 用户点进"封禁列表"想看的是"现在谁被封着"，而不是历史流水。
func (receiver *WafHostGuardService) GetBanList(req request.WafHostGuardBanSearchReq) ([]model.HostGuardBan, int64, error) {
	var list []model.HostGuardBan
	var total int64

	query := global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{})
	status := req.Status
	if status == "" {
		status = model.HostBanStatusActive
	}
	if status != "all" {
		query = query.Where(dialect.Q("status")+" = ?", status)
	}
	if req.IP != "" {
		query = query.Where("ip LIKE ?", "%"+req.IP+"%")
	}
	if req.Source != "" {
		query = query.Where("source = ?", req.Source)
	}

	query.Count(&total)
	err := query.Order("start_time DESC").
		Limit(req.PageSize).
		Offset(req.PageSize * (req.PageIndex - 1)).
		Find(&list).Error
	return list, total, err
}

// ReleaseBan 手工提前解封
func (receiver *WafHostGuardService) ReleaseBan(id string) error {
	var ban model.HostGuardBan
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&ban).Error; err != nil {
		return errors.New("封禁记录不存在")
	}
	if ban.Status != model.HostBanStatusActive {
		return errors.New("该记录已不在封禁中")
	}

	if err := wafhostguard.GetBanExecutor().Apply(nil, []string{ban.IP}); err != nil {
		return errors.New("解除系统防火墙封禁失败：" + err.Error())
	}
	// Windows 走去抖，手工解封要立刻见效，这里强制刷一次
	if err := wafhostguard.GetBanExecutor().FlushPending(); err != nil {
		zlog.Warn("[主机登录防护] 手工解封时同步防火墙失败", "ip", ban.IP, "error", err.Error())
	}

	return global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":      model.HostBanStatusReleased,
			"remarks":     "管理员手工解封",
			"update_time": customtype.JsonTime(time.Now()),
		}).Error
}

// PromoteToPermanent 把一条临时封禁改成永久
func (receiver *WafHostGuardService) PromoteToPermanent(id string) error {
	var ban model.HostGuardBan
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&ban).Error; err != nil {
		return errors.New("封禁记录不存在")
	}
	if ban.Status != model.HostBanStatusActive {
		return errors.New("该记录已不在封禁中")
	}
	return global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"expire_time": 0,
			"ban_minutes": 0,
			"remarks":     "管理员手工提升为永久封禁",
			"update_time": customtype.JsonTime(time.Now()),
		}).Error
}

// ManualBan 手工封禁一个IP（从事件列表或连接看板一键操作）
func (receiver *WafHostGuardService) ManualBan(req request.WafHostGuardManualBanReq) error {
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		return errors.New("IP不能为空")
	}
	source := req.Source
	if source == "" {
		source = wafhostguard.SourceSSH
	}
	reason := req.Reason
	if reason == "" {
		reason = "管理员手工封禁"
	}

	res := wafhostguard.ApplyBan(wafhostguard.BanRequest{
		IP:        ip,
		Source:    source,
		Manual:    true,
		ManualMin: req.BanMinutes,
		Reason:    reason,
	}, time.Now())
	if !res.Banned {
		if res.Skipped != "" {
			return errors.New(res.Skipped)
		}
		return errors.New("封禁未生效")
	}
	// 手工操作要立刻见效，不等去抖
	if err := wafhostguard.GetBanExecutor().FlushPending(); err != nil {
		zlog.Warn("[主机登录防护] 手工封禁时同步防火墙失败", "ip", ip, "error", err.Error())
	}
	return nil
}

// GetOffenderList 分页查询攻击者档案
func (receiver *WafHostGuardService) GetOffenderList(req request.WafHostGuardOffenderSearchReq) ([]model.HostGuardOffender, int64, error) {
	var list []model.HostGuardOffender
	var total int64

	query := global.GWAF_LOCAL_DB.Model(&model.HostGuardOffender{})
	if req.IP != "" {
		query = query.Where("ip LIKE ?", "%"+req.IP+"%")
	}
	if req.Source != "" {
		query = query.Where("source = ?", req.Source)
	}

	query.Count(&total)
	err := query.Order("last_ban_time DESC").
		Limit(req.PageSize).
		Offset(req.PageSize * (req.PageIndex - 1)).
		Find(&list).Error
	return list, total, err
}

// ResetOffender 重置某个攻击者的阶梯（下次封禁从第1级重新开始）
func (receiver *WafHostGuardService) ResetOffender(id string) error {
	return global.GWAF_LOCAL_DB.Model(&model.HostGuardOffender{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"ban_count":     0,
			"current_level": 0,
			"last_reason":   "管理员手工重置阶梯",
			"update_time":   customtype.JsonTime(time.Now()),
		}).Error
}

// DeleteOffender 删除攻击者档案
func (receiver *WafHostGuardService) DeleteOffender(id string) error {
	return global.GWAF_LOCAL_DB.Where("id = ?", id).Delete(&model.HostGuardOffender{}).Error
}

// GetLadders 取阶梯配置（按级别升序）
func (receiver *WafHostGuardService) GetLadders() ([]model.HostGuardBanLadder, error) {
	var list []model.HostGuardBanLadder
	err := global.GWAF_LOCAL_DB.Order("level asc").Find(&list).Error
	return list, err
}

// SaveLadders 整表替换阶梯配置。
// 用整表替换而不是逐行增删改：阶梯是一个有序整体，级别之间要连续，
// 让前端一次提交完整列表，后端校验后原子替换，比维护单行 CRUD 的一致性简单得多。
func (receiver *WafHostGuardService) SaveLadders(req request.WafHostGuardLadderEditReq) error {
	if len(req.Ladders) == 0 {
		return errors.New("至少要保留一级封禁阶梯")
	}
	// 至少要有一级是启用的，否则触发阈值后无从取时长
	enabled := 0
	for _, l := range req.Ladders {
		if l.Enable == 1 {
			enabled++
		}
		if l.BanMinutes < 0 {
			return errors.New("封禁时长不能为负数（0 表示永久封禁）")
		}
	}
	if enabled == 0 {
		return errors.New("至少要启用一级封禁阶梯，否则达到阈值后无法确定封禁时长")
	}

	now := time.Now()
	tx := global.GWAF_LOCAL_DB.Begin()
	if err := tx.Where("1 = 1").Delete(&model.HostGuardBanLadder{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	for i, item := range req.Ladders {
		level := item.Level
		if level <= 0 {
			level = i + 1
		}
		ladder := model.HostGuardBanLadder{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(now),
				UPDATE_TIME: customtype.JsonTime(now),
			},
			Level:      level,
			BanMinutes: item.BanMinutes,
			Enable:     item.Enable,
			Remarks:    item.Remarks,
		}
		if err := tx.Create(&ladder).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return err
	}
	wafhostguard.InvalidateLadder()
	return nil
}

// CleanExpiredBans 解封所有到期封禁。由定时任务每分钟调用。
// 记录只置为 expired 不删行——攻击历史要留作取证，也是攻击者档案的佐证。
func (receiver *WafHostGuardService) CleanExpiredBans() (int, error) {
	now := time.Now().Unix()
	var expired []model.HostGuardBan
	err := global.GWAF_LOCAL_DB.
		Where(dialect.Q("status")+" = ? AND expire_time > 0 AND expire_time <= ?", model.HostBanStatusActive, now).
		Find(&expired).Error
	if err != nil {
		return 0, err
	}
	if len(expired) == 0 {
		return 0, nil
	}

	ips := make([]string, 0, len(expired))
	ids := make([]string, 0, len(expired))
	for _, b := range expired {
		ips = append(ips, b.IP)
		ids = append(ids, b.Id)
	}

	if err := wafhostguard.GetBanExecutor().Apply(nil, ips); err != nil {
		return 0, err
	}
	// 到期解封要真的到期就生效，不能再等一个去抖窗口
	if err := wafhostguard.GetBanExecutor().FlushPending(); err != nil {
		zlog.Warn("[主机登录防护] 解封时同步防火墙失败", "error", err.Error())
	}

	err = global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"status":      model.HostBanStatusExpired,
			"update_time": customtype.JsonTime(time.Now()),
		}).Error
	if err != nil {
		return 0, err
	}
	zlog.Info("[主机登录防护] 已解封到期IP", "数量", len(ips))
	return len(ips), nil
}

// HostGuardStatistics 概览统计
type HostGuardStatistics struct {
	Status         wafhostguard.Status `json:"status"`
	ActiveBans     int64               `json:"active_bans"`     // 当前生效封禁数
	PermanentBans  int64               `json:"permanent_bans"`  // 其中永久封禁数
	TotalBans      int64               `json:"total_bans"`      // 历史封禁总数
	OffenderCount  int64               `json:"offender_count"`  // 攻击者档案数
	Events24h      int64               `json:"events_24h"`      // 近24小时失败事件数
	TopSources     []HostGuardTopItem  `json:"top_sources"`     // Top 攻击源
	HourlyTrend    []HostGuardTrend    `json:"hourly_trend"`    // 近24小时趋势
	SourceBreakout []HostGuardTopItem  `json:"source_breakout"` // 按来源(ssh/rdp)分布
}

// HostGuardTopItem Top 榜条目
type HostGuardTopItem struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Level    int    `json:"level"`
	Count    int64  `json:"count"`
}

// HostGuardTrend 趋势点
type HostGuardTrend struct {
	Hour  string `json:"hour"`
	Count int64  `json:"count"`
}

// GetStatistics 概览页数据
func (receiver *WafHostGuardService) GetStatistics() HostGuardStatistics {
	st := HostGuardStatistics{Status: wafhostguard.GetStatus()}

	if global.GWAF_LOCAL_DB != nil {
		global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
			Where(dialect.Q("status")+" = ?", model.HostBanStatusActive).Count(&st.ActiveBans)
		global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
			Where(dialect.Q("status")+" = ? AND expire_time = 0", model.HostBanStatusActive).Count(&st.PermanentBans)
		global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).Count(&st.TotalBans)
		global.GWAF_LOCAL_DB.Model(&model.HostGuardOffender{}).Count(&st.OffenderCount)

		var offenders []model.HostGuardOffender
		global.GWAF_LOCAL_DB.Model(&model.HostGuardOffender{}).
			Order("ban_count DESC, total_fail_count DESC").Limit(10).Find(&offenders)
		for _, o := range offenders {
			st.TopSources = append(st.TopSources, HostGuardTopItem{
				Name:     o.IP,
				Location: o.Location,
				Level:    o.CurrentLevel,
				Count:    o.BanCount,
			})
		}
	}

	if global.GWAF_LOCAL_LOG_DB != nil {
		since := time.Now().Add(-24 * time.Hour).Unix()
		global.GWAF_LOCAL_LOG_DB.Model(&model.HostLoginEvent{}).
			Where("event_time >= ?", since).Count(&st.Events24h)

		// 按小时分桶。用应用层分桶而不是 SQL 的时间函数，是为了避开
		// SQLite/MySQL/PostgreSQL 三种方言在时间函数上的差异。
		var events []model.HostLoginEvent
		global.GWAF_LOCAL_LOG_DB.Select("event_time", "source").
			Where("event_time >= ?", since).Find(&events)

		buckets := make(map[string]int64, 24)
		bySource := make(map[string]int64, 2)
		for _, e := range events {
			hour := time.Unix(e.EventTime, 0).Format("2006-01-02 15:00")
			buckets[hour]++
			bySource[e.Source]++
		}
		now := time.Now()
		for i := 23; i >= 0; i-- {
			hour := now.Add(time.Duration(-i) * time.Hour).Format("2006-01-02 15:00")
			st.HourlyTrend = append(st.HourlyTrend, HostGuardTrend{Hour: hour, Count: buckets[hour]})
		}
		for name, cnt := range bySource {
			st.SourceBreakout = append(st.SourceBreakout, HostGuardTopItem{Name: name, Count: cnt})
		}
	}

	return st
}

// TestWhitelist 白名单自测：告诉用户某个IP会不会被豁免、命中哪一条
func (receiver *WafHostGuardService) TestWhitelist(ip string) (bool, string) {
	return wafhostguard.IsWhitelisted(strings.TrimSpace(ip))
}

// AddToWhitelist 把IP追加进白名单配置（从事件/封禁列表一键操作）。
// 顺带把该IP当前的封禁解掉——用户点"加白名单"的意思就是"这个别封了"。
func (receiver *WafHostGuardService) AddToWhitelist(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return errors.New("IP不能为空")
	}

	current := strings.TrimSpace(global.GCONFIG_HOST_GUARD_WHITELIST)
	for _, item := range strings.Split(current, ",") {
		if strings.TrimSpace(item) == ip {
			return errors.New("该IP已在白名单中")
		}
	}
	newValue := ip
	if current != "" {
		newValue = current + "," + ip
	}

	err := WafSystemConfigServiceApp.ModifyByItemApi(request.WafSystemConfigEditByItemReq{
		Item:  "host_guard_whitelist",
		Value: newValue,
	})
	if err != nil {
		return err
	}
	global.GCONFIG_HOST_GUARD_WHITELIST = newValue
	wafhostguard.InvalidateWhitelist()

	// 已经封着的要立刻放出来
	var bans []model.HostGuardBan
	global.GWAF_LOCAL_DB.Where("ip = ? AND "+dialect.Q("status")+" = ?", ip, model.HostBanStatusActive).Find(&bans)
	for _, b := range bans {
		if err := receiver.ReleaseBan(b.Id); err != nil {
			zlog.Warn("[主机登录防护] 加白名单后解封失败", "ip", ip, "error", err.Error())
		}
	}
	return nil
}
