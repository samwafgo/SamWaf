package waf_service

import (
	"SamWaf/common/tasklog"
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/firewall"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafenginecore/ipset"
	"SamWaf/waftask/threatip"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WafThreatIPService 威胁情报 IP 订阅服务：渠道 CRUD + 拉取同步 + 落地(WAF 应用层 / 系统防火墙)。
type WafThreatIPService struct {
	fw     firewall.FireWallEngine
	syncMu sync.Mutex // 串行化同步，避免多渠道并发拉取造成内核/内存压力

	// inflight 记录"当前正在处理(含排队等锁)的渠道 Code -> 开始时间戳(秒)"。
	// 纯内存态(重启即清空)，只用于列表接口回显"同步中"，让前端能轮询到结果。
	inflight sync.Map
	// lockHolder 当前持有 syncMu 的操作描述，用于在别人拿不到锁时说清楚"是谁占着"
	lockHolder atomic.Value
}

// lockWaitOnDemand 等待 syncMu 的上限。
// 超过就明确报错返回，而不是像以前那样无限期静默排队(用户会看到"提示已开始"却永远没结果)。
// 取 30s：既能容纳"连着点两个渠道同步"这种正常排队，又不会让失败无限期悬着。
const lockWaitOnDemand = 30 * time.Second

// lockWaitStartupPerChannel 启动重放为**单个渠道**等锁的上限。
// 取得短：启动重放是"尽力而为"的补偿动作，等不到就跳过(定时同步会重建)，
// 绝不能反过来把用户的手动同步挤掉。
const lockWaitStartupPerChannel = 5 * time.Second

// syncTriggerManual / syncTriggerSchedule 同步触发方式，进日志与 last_status 便于区分
const (
	syncTriggerManual   = "手动"
	syncTriggerSchedule = "定时"
)

// tryLockSync 在 wait 时间内尝试获取同步锁，holder 描述本次操作(用于让后来者知道是谁占着)。
// 用轮询式 TryLock 而非阻塞 Lock：这条链路上任何一次卡死都会把后续所有同步永久堵住，
// 宁可明确失败并留下日志，也不要无限期静默排队。
func (r *WafThreatIPService) tryLockSync(wait time.Duration, holder string) bool {
	deadline := time.Now().Add(wait)
	for {
		if r.syncMu.TryLock() {
			r.lockHolder.Store(holder)
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// unlockSync 释放同步锁并清掉持有者标记
func (r *WafThreatIPService) unlockSync() {
	r.lockHolder.Store("")
	r.syncMu.Unlock()
}

// busyHint 描述当前占着同步锁的操作，用于错误信息与日志
func (r *WafThreatIPService) busyHint() string {
	if h, _ := r.lockHolder.Load().(string); h != "" {
		return h
	}
	return "有其它订阅落地操作正在进行"
}

// safeGo 起一个带 panic 兜底的后台 goroutine。
// 以前这里是裸 go func()：一次 panic 会直接崩掉整个 SamWaf 进程，且什么线索都不留。
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if e := recover(); e != nil {
				zlog.Error(fmt.Sprintf("威胁情报订阅后台任务[%s]异常: %v 调试信息:%s", name, e, debug.Stack()))
			}
		}()
		fn()
	}()
}

var WafThreatIPServiceApp = new(WafThreatIPService)

// threatSetPrefix 系统防火墙 ipset 集合名前缀(每渠道一张私有集合)
const threatSetPrefix = "samwaf_sub_"

// shrinkGuardMin/shrinkGuardRatio 突变保护：老快照条数>Min 且新快照不足其 1/Ratio 时，视为源异常(如被清空)，
// 跳过应用并告警，避免误删全部威胁封禁。
const (
	shrinkGuardMin   = 100
	shrinkGuardRatio = 5
)

// setNameForChannel 渠道对应的系统 ipset 集合名
func setNameForChannel(code string) string { return threatSetPrefix + code }

// ---------------- 渠道 CRUD ----------------

// AddApi 新增订阅渠道
func (r *WafThreatIPService) AddApi(req request.WafThreatIPChannelAddReq) error {
	if err := validateChannelCode(req.Code); err != nil {
		return err
	}
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.ThreatIPChannel{}).Where("code = ?", req.Code).Count(&cnt)
	if cnt > 0 {
		return errors.New("渠道短码已存在")
	}
	bean := &model.ThreatIPChannel{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Code:         req.Code,
		Name:         req.Name,
		URL:          req.URL,
		ParserType:   defaultStr(req.ParserType, model.ThreatParserPlainMixed),
		Threshold:    req.Threshold,
		LandTarget:   defaultStr(req.LandTarget, model.ThreatLandWAF),
		Enable:       req.Enable,
		IntervalHour: defaultInt(req.IntervalHour, 24),
		Remarks:      req.Remarks,
	}
	return global.GWAF_LOCAL_DB.Create(bean).Error
}

// ModifyApi 修改订阅渠道(不允许改 Code，避免 ipset 集合名漂移导致残留)。
// DB 更新同步完成(快)后立即返回；落地生效(系统集合增删 + 重建 WAF 并集)可能较重，
// 放到后台异步执行并在完成后经通知中心提示，避免编辑保存时前端长时间卡住。
func (r *WafThreatIPService) ModifyApi(req request.WafThreatIPChannelEditReq) error {
	var bean model.ThreatIPChannel
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return errors.New("记录不存在")
	}
	landTarget := defaultStr(req.LandTarget, model.ThreatLandWAF)
	updates := map[string]interface{}{
		"Name":         req.Name,
		"URL":          req.URL,
		"ParserType":   defaultStr(req.ParserType, model.ThreatParserPlainMixed),
		"Threshold":    req.Threshold,
		"LandTarget":   landTarget,
		"Enable":       req.Enable,
		"IntervalHour": defaultInt(req.IntervalHour, 24),
		"Remarks":      req.Remarks,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.ThreatIPChannel{}).Where("id = ?", req.Id).Updates(updates).Error; err != nil {
		return err
	}
	// 异步落地：启用→回灌系统集合(若含系统层)并重建并集；停用→清理系统集合并重建并集
	code := bean.Code
	enable := req.Enable
	name := req.Name
	safeGo("保存生效:"+code, func() {
		err := r.applyEnableState(code, landTarget, enable)
		r.notifyOpResult("威胁情报订阅保存生效", name, err)
	})
	return nil
}

// applyEnableState 依据启用状态把某渠道落地到位：系统集合的增删 + 重建 WAF 应用层并集。
// 供编辑保存后异步调用；串行化(syncMu)避免与同步任务并发改动内核/内存态。
func (r *WafThreatIPService) applyEnableState(code, landTarget string, enable int) error {
	start := time.Now()
	if !r.tryLockSync(lockWaitOnDemand, fmt.Sprintf("渠道[%s]保存生效", code)) {
		msg := "订阅落地生效跳过：" + r.busyHint()
		zlog.Warn("威胁情报订阅落地生效未能获取同步锁", "channel", code, "detail", r.busyHint())
		return errors.New(msg)
	}
	defer r.unlockSync()

	zlog.Info("威胁情报订阅落地生效开始", "channel", code, "land", landTarget, "enable", enable)
	ips, sha := r.loadSnapshot(code)
	if enable == 0 {
		// 停用：清理系统集合(WAF 并集在下方重建时自动排除该渠道)。
		// 落地态清空——再启用时必须重新灌，不能因为 landed_sha 还等于内容 sha 就跳过。
		r.destroySystemSet(code)
		r.markLandedByCode(code, "", 0)
	} else if landTarget == model.ThreatLandSystem || landTarget == model.ThreatLandBoth {
		// 启用且落地含系统层：把快照重新灌回系统集合(重启/停用会丢，需按需回灌)
		if !r.fw.SupportsIPSet() {
			zlog.Warn("当前环境不支持 ipset 批量封禁，跳过系统层落地", "channel", code)
			r.markLandedByCode(code, sha, len(ips)) // 环境性跳过不算失败，见 landSystemLayer 注释
		} else if len(ips) == 0 {
			r.markLandedByCode(code, sha, 0)
		} else if err := r.fw.RestoreIPSet(setNameForChannel(code), ips); err != nil {
			// 落地失败不写 landed_sha：下一次同步/对账会发现落地态对不上并覆盖式重建
			zlog.Error(fmt.Sprintf("启用渠道系统层落地失败 channel=%s error=%s", code, err.Error()))
			r.RebuildWAFUnion()
			return fmt.Errorf("系统层落地失败(将自动重试): %w", err)
		} else {
			r.markLandedByCode(code, sha, len(ips))
		}
	} else {
		// 启用但落地不含系统层：清理可能残留的系统集合；系统层无需落地即视为到位
		r.destroySystemSet(code)
		r.markLandedByCode(code, sha, len(ips))
	}
	r.RebuildWAFUnion()
	zlog.Info("威胁情报订阅落地生效完成", "channel", code, "elapsed", time.Since(start).Round(time.Millisecond).String())
	return nil
}

// markLandedByCode 按渠道短码更新落地态(编辑保存路径手里只有 code，没有主键 id)
func (r *WafThreatIPService) markLandedByCode(code, landedSha string, count int) {
	if err := global.GWAF_LOCAL_DB.Model(&model.ThreatIPChannel{}).Where("code = ?", code).Updates(map[string]interface{}{
		"LandedSha":   landedSha,
		"LandedCount": count,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}).Error; err != nil {
		zlog.Warn("威胁情报订阅落地态回写失败", "channel", code, "error", err.Error())
	}
}

// destroySystemSet 清理某渠道在系统防火墙上的集合。
// 只在系统防火墙确实可用时才动手：纯 WAF 落地的渠道从没往系统层写过东西，
// 无条件调用只会白白 fork 一堆 iptables/netsh(Windows 上还可能长时间空转并占着同步锁)。
func (r *WafThreatIPService) destroySystemSet(code string) {
	if !r.fw.SupportsIPSet() {
		zlog.Debug("系统防火墙不可用，跳过系统层集合清理", "channel", code)
		return
	}
	if err := r.fw.DestroyIPSet(setNameForChannel(code)); err != nil {
		zlog.Warn("清理系统层集合失败", "channel", code, "error", err.Error())
	}
}

// notifyOpResult 把某异步操作结果推送到管理端通知中心(WebSocket 实时)。
func (r *WafThreatIPService) notifyOpResult(opera, name string, err error) {
	serverName := global.GWAF_CUSTOM_SERVER_NAME
	if err != nil {
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: opera, Server: serverName},
			Msg:             fmt.Sprintf("%s[%s]失败：%s", opera, name, err.Error()),
			Success:         "false",
		})
		return
	}
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: opera, Server: serverName},
		Msg:             fmt.Sprintf("%s[%s]已完成", opera, name),
		Success:         "true",
	})
}

// DelApi 删除订阅渠道(清理系统集合与快照)。DB 删除同步完成后立即返回；
// 系统集合清理 + 重建 WAF 并集可能较重，异步执行并在完成后通知，避免删除操作卡住。
func (r *WafThreatIPService) DelApi(id string) error {
	var bean model.ThreatIPChannel
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&bean).Error; err != nil {
		return errors.New("记录不存在")
	}
	code := bean.Code
	name := bean.Name
	// DB 删除(快)：先删快照再删渠道记录
	global.GWAF_LOCAL_DB.Where("channel_code = ?", code).Delete(&model.ThreatIPSnapshot{})
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).Delete(&model.ThreatIPChannel{}).Error; err != nil {
		return err
	}
	// 异步落地：撤系统集合 + 重建并集
	safeGo("删除生效:"+code, func() {
		if !r.tryLockSync(lockWaitOnDemand, fmt.Sprintf("渠道[%s]删除生效", code)) {
			zlog.Warn("威胁情报订阅删除生效未能获取同步锁", "channel", code, "detail", r.busyHint())
			r.notifyOpResult("威胁情报订阅删除生效", name, errors.New("落地生效跳过："+r.busyHint()+"；下次同步或重启后会自动对齐"))
			return
		}
		defer r.unlockSync() // 用 defer：以前是手动 Unlock，中途 panic 会永久泄漏锁，之后所有同步全卡死
		r.destroySystemSet(code)
		r.RebuildWAFUnion()
		zlog.Info("威胁情报订阅删除生效完成", "channel", code)
		r.notifyOpResult("威胁情报订阅删除生效", name, nil)
	})
	return nil
}

// GetListApi 渠道分页列表
func (r *WafThreatIPService) GetListApi(req request.WafThreatIPChannelSearchReq) ([]model.ThreatIPChannel, int64, error) {
	var list []model.ThreatIPChannel
	var total int64
	q := global.GWAF_LOCAL_DB.Model(&model.ThreatIPChannel{})
	if req.Name != "" {
		q = q.Where("name LIKE ?", "%"+req.Name+"%")
	}
	q.Count(&total)
	err := q.Order("create_time DESC").Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list).Error
	// 用快照真实条数覆盖 LastCount，避免状态回写失败/启动重放未回写导致"收录条数"显示 0
	for i := range list {
		cnt, sha := r.snapshotMeta(list[i].Code)
		if cnt >= 0 {
			list[i].LastCount = cnt
		}
		effSha, excluded := r.effectiveMeta(list[i], sha)
		list[i].ExcludedCount = excluded
		list[i].LandedOK = landedOK(list[i], effSha)
		// 回填内存态"同步中"，前端据此显示进行中并自动轮询
		list[i].Syncing, list[i].SyncStartedAt = r.syncingOf(list[i].Code)
	}
	return list, total, err
}

// effMetaEntry 某渠道有效集元信息的缓存项
type effMetaEntry struct {
	snapSha    string // 算出这份结果时的快照 sha
	excludeSha string // 算出这份结果时的排除集 sha
	sha        string
	excluded   int
}

var (
	effMetaMu    sync.Mutex
	effMetaStore = map[string]effMetaEntry{}
)

// rememberEffMeta 由**已经算过有效集**的路径(同步/启动重放/落地对账)回填缓存。
// 这些路径本来就要解压快照并过滤，顺手记一笔，展示接口就永远不必自己算。
func rememberEffMeta(code, snapshotSha, excludeSha, effSha string, excluded int) {
	effMetaMu.Lock()
	effMetaStore[code] = effMetaEntry{snapSha: snapshotSha, excludeSha: excludeSha, sha: effSha, excluded: excluded}
	effMetaMu.Unlock()
}

// effectiveMeta 取某渠道有效集的 sha 与被排除条数，供列表页/落地汇总展示。
//
// **这个函数只读缓存，绝不自己解压快照。** 它在列表接口里是**每行**调一次的，
// 一旦允许它按需计算，一次刷新就要解压 N 个渠道的快照并逐条过滤；线上实测叠加
// 启动重放/落地对账的 netsh 开销后，直接把 /threatip/channel/list 拖到 20s 超时。
//
// 缓存未命中(刚启动、还没跑过同步或对账)时退回**已落库的状态**：
// 拿 landed_sha 当 effSha、last_count-landed_count 当排除条数。
// 这会让"未完全落地"标签在冷启动的头一分钟内偏向"正常"——这正是我们要的方向，
// 宁可漏报也不能误报；启动时的对账跑完就会回填真实值。
func (r *WafThreatIPService) effectiveMeta(ch model.ThreatIPChannel, snapshotSha string) (effSha string, excluded int) {
	if snapshotSha == "" {
		return "", 0
	}
	excludeSha := WafThreatIPExcludeServiceApp.Get().Sha()

	effMetaMu.Lock()
	c, ok := effMetaStore[ch.Code]
	effMetaMu.Unlock()
	if ok && c.snapSha == snapshotSha && c.excludeSha == excludeSha {
		return c.sha, c.excluded
	}

	// 退回落库状态：不做任何 IO，展示接口必须是常数级的
	fallbackExcluded := ch.LastCount - ch.LandedCount
	if fallbackExcluded < 0 || ch.LandedSha == "" {
		fallbackExcluded = 0
	}
	if ch.LandedSha == "" {
		return snapshotSha, 0
	}
	return ch.LandedSha, fallbackExcluded
}

// landedOK 判断该渠道的系统防火墙是否已确认落地到**当前应有的内容**(有效集)。
//
// 以下情况一律算"到位"，避免给用户报无意义的警：
//   - 落地层不含系统防火墙：本来就不往系统层写
//   - 还没有任何快照：没什么可落地的
//
// 环境不支持 ipset 的情况不用在这里特判——落地流程已经把 LandedSha 记成了有效集 sha
// (见 landSystemLayer 的说明：那不是"落地失败"，是"这台机器就不做系统层")。
func landedOK(ch model.ThreatIPChannel, effSha string) bool {
	if ch.LandTarget != model.ThreatLandSystem && ch.LandTarget != model.ThreatLandBoth {
		return true
	}
	if effSha == "" {
		return true
	}
	return ch.LandedSha == effSha
}

// syncingOf 查某渠道当前是否正在同步，以及本次同步的开始时间戳
func (r *WafThreatIPService) syncingOf(code string) (bool, int64) {
	if v, ok := r.inflight.Load(code); ok {
		startedAt, _ := v.(int64)
		return true, startedAt
	}
	return false, 0
}

// ---------------- 订阅落地只读浏览(方案三：原页"订阅来源"Tab) ----------------

// LandedChannelSummary 某渠道在指定层的落地汇总
type LandedChannelSummary struct {
	Code          string `json:"code"`
	Name          string `json:"name"`
	LandTarget    string `json:"land_target"`
	Enable        int    `json:"enable"`
	Count         int    `json:"count"`           // 实际生效(已落地)条数：启用=有效集条数，停用=0(已从防火墙/WAF移除)
	SnapshotCount int    `json:"snapshot_count"`  // 快照收录条数(不论启用与否，供停用时提示"再启用可回灌")
	ExcludedCount int    `json:"excluded_count"`  // 被误报排除名单剔掉的条数，解释 Count 为什么比 SnapshotCount 少
	LastSyncAt    int64  `json:"last_sync_at"`    // 上次同步时间戳(秒)
	LastStatus    string `json:"last_status"`     // 上次同步结果
	Syncing       bool   `json:"syncing"`         // 当前是否有同步在进行(内存态)
	SyncStartedAt int64  `json:"sync_started_at"` // 本次同步开始时间戳(秒)
}

// GetLandedSummary 返回落地到指定层的各渠道汇总。
// land: "system" 只列落地含系统防火墙的渠道；"waf" 只列落地含 WAF 应用层的渠道；"" 全部。
func (r *WafThreatIPService) GetLandedSummary(land string) []LandedChannelSummary {
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Order("create_time DESC").Find(&channels)
	out := make([]LandedChannelSummary, 0, len(channels))
	for _, ch := range channels {
		if !landMatches(ch.LandTarget, land) {
			continue
		}
		snapCnt, snapSha := r.snapshotMeta(ch.Code)
		if snapCnt < 0 {
			snapCnt = 0
		}
		// 实际落地条数要扣掉被排除的误报，否则页面数字与防火墙里的真实条数对不上
		_, excluded := r.effectiveMeta(ch, snapSha)
		landed := snapCnt - excluded
		if landed < 0 {
			landed = 0
		}
		// 停用渠道已从防火墙/WAF 移除，落地数应为 0(快照仍保留以便再启用秒回灌)
		if ch.Enable == 0 {
			landed = 0
		}
		syncing, syncStartedAt := r.syncingOf(ch.Code)
		out = append(out, LandedChannelSummary{
			Code:          ch.Code,
			Name:          ch.Name,
			LandTarget:    ch.LandTarget,
			Enable:        ch.Enable,
			Count:         landed,
			SnapshotCount: snapCnt,
			ExcludedCount: excluded,
			LastSyncAt:    ch.LastSyncAt,
			LastStatus:    ch.LastStatus,
			Syncing:       syncing,
			SyncStartedAt: syncStartedAt,
		})
	}
	return out
}

// LandedIP 落地 IP 浏览的一行。
// ExcludedBy/Reason 只在"仅看已排除"模式下有值——用户问的是"这条为什么没进防火墙"，
// 光给个 IP 列表回答不了，必须指名是哪条排除规则干的。
type LandedIP struct {
	IP         string `json:"ip"`
	ExcludedBy string `json:"excluded_by"` // 命中的排除条目原文
	Reason     string `json:"reason"`      // 该条目的来源说明(内置自动来源才有)
}

// GetLandedIPs 分页浏览某渠道的 IP/CIDR(只读)。keyword 为子串过滤(可空)。
//
// 默认列的是**有效集**——页面标题是"已落地"，就该和防火墙里实际存在的东西一致，
// 否则用户排除完还能在这里看到那条 IP，会以为排除没生效。
// onlyExcluded=true 时反过来只列被排除掉的那些，并带上是被哪条规则排除的。
func (r *WafThreatIPService) GetLandedIPs(code, keyword string, onlyExcluded bool, pageIndex, pageSize int) ([]LandedIP, int64) {
	all, _ := r.loadSnapshot(code) // 已排序去重
	set := WafThreatIPExcludeServiceApp.Get()

	ips := make([]LandedIP, 0, len(all))
	for _, ip := range all {
		hit := set.matchEntry(ip)
		if onlyExcluded {
			if hit != nil {
				ips = append(ips, LandedIP{IP: ip, ExcludedBy: hit.Raw, Reason: hit.Reason})
			}
			continue
		}
		if hit == nil {
			ips = append(ips, LandedIP{IP: ip})
		}
	}

	if keyword = strings.TrimSpace(keyword); keyword != "" {
		filtered := make([]LandedIP, 0, len(ips))
		for _, ip := range ips {
			if strings.Contains(ip.IP, keyword) {
				filtered = append(filtered, ip)
			}
		}
		ips = filtered
	}
	total := int64(len(ips))
	if pageIndex < 1 {
		pageIndex = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}
	start := (pageIndex - 1) * pageSize
	if start >= len(ips) {
		return []LandedIP{}, total
	}
	end := start + pageSize
	if end > len(ips) {
		end = len(ips)
	}
	return ips[start:end], total
}

// snapshotCount 取某渠道快照的收录条数(不解压 payload)。无快照返回 -1。
func (r *WafThreatIPService) snapshotCount(code string) int {
	c, _ := r.snapshotMeta(code)
	return c
}

// snapshotMeta 取某渠道快照的条数与 sha(都在表头，不解压 payload)。无快照返回 (-1, "")。
func (r *WafThreatIPService) snapshotMeta(code string) (int, string) {
	var snap model.ThreatIPSnapshot
	if err := global.GWAF_LOCAL_DB.Select("count", "sha256").Where("channel_code = ?", code).First(&snap).Error; err != nil {
		return -1, ""
	}
	return snap.Count, snap.Sha256
}

// landMatches 判断渠道落地层是否匹配筛选。land 为空则全匹配。
func landMatches(landTarget, land string) bool {
	switch land {
	case "system":
		return landTarget == model.ThreatLandSystem || landTarget == model.ThreatLandBoth
	case "waf":
		return landTarget == model.ThreatLandWAF || landTarget == model.ThreatLandBoth
	default:
		return true
	}
}

// GetDetailApi 渠道详情
func (r *WafThreatIPService) GetDetailByIdApi(id string) model.ThreatIPChannel {
	var bean model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("id = ?", id).Find(&bean)
	return bean
}

// ---------------- 同步与落地 ----------------

// SyncByIdApi 手动触发某渠道同步。拉取(网络下载)+解析+灌内核 可能很慢，
// 异步执行避免阻塞 HTTP 请求；渠道状态回写在 SyncChannel 内完成，另经通知中心提示成败。
func (r *WafThreatIPService) SyncByIdApi(id string) error {
	var bean model.ThreatIPChannel
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&bean).Error; err != nil {
		return errors.New("记录不存在")
	}
	zlog.Info("威胁情报订阅收到手动同步请求", "channel", bean.Code, "name", bean.Name,
		"url", bean.URL, "parser", bean.ParserType, "land", bean.LandTarget)
	safeGo("手动同步:"+bean.Code, func() {
		err := r.syncChannelWithTrigger(bean, syncTriggerManual)
		r.notifyOpResult("威胁情报订阅同步", bean.Name, err)
	})
	return nil
}

// SyncChannel 拉取→解析→与上次快照比对→(突变保护)→保存快照→落地(系统 ipset + WAF 并集)。
func (r *WafThreatIPService) SyncChannel(ch model.ThreatIPChannel) error {
	return r.syncChannelWithTrigger(ch, syncTriggerSchedule)
}

// syncChannelWithTrigger 同 SyncChannel，额外带上触发方式(手动/定时)用于日志与状态回显。
//
// 这条链路以前失败时是完全静默的(四个失败分支都只写 DB、不打日志，失败通知又只走一次性 WebSocket)，
// 用户点完"立即同步"只能看到"已开始"然后什么都没有。所以这里每个阶段都留了日志与耗时，
// 并把手动触发也挂进任务日志，方便在"任务日志"页直接看到全过程。
func (r *WafThreatIPService) syncChannelWithTrigger(ch model.ThreatIPChannel, trigger string) error {
	// 让本 goroutine 的 zlog 输出同时落到任务日志文件(与定时任务同一个任务名)。
	// 定时路径下 ExecuteTask 已经设过任务上下文，这里就不能重复设——否则同步完第一个渠道时
	// 的 defer Clear 会把整个 SyncAllDue 剩余过程的任务日志上下文一起清掉。
	if _, ok := tasklog.GetCurrentTask(); !ok {
		tasklog.SetCurrentTask(enums.TASK_THREAT_IP_SYNC)
		defer tasklog.ClearCurrentTask()
	}

	start := time.Now()

	// 先标记"同步中"再去抢锁：排队等锁的这段时间前端也该看到进行中，
	// 否则轮询会以为已经结束而提前收工。无论从哪个分支返回都会清掉。
	r.inflight.Store(ch.Code, start.Unix())
	defer r.inflight.Delete(ch.Code)

	if !r.tryLockSync(lockWaitOnDemand, fmt.Sprintf("渠道[%s]%s同步", ch.Code, trigger)) {
		msg := fmt.Sprintf("已跳过(%s触发)：等待 %s 仍未轮到，%s，请稍后重试", trigger, lockWaitOnDemand, r.busyHint())
		zlog.Warn("威胁情报订阅同步未能获取同步锁", "channel", ch.Code, "trigger", trigger, "detail", r.busyHint())
		r.markSyncFail(ch.Id, msg)
		return errors.New(msg)
	}
	defer r.unlockSync()

	zlog.Info("威胁情报订阅同步开始", "channel", ch.Code, "trigger", trigger, "url", ch.URL, "parser", ch.ParserType,
		"waited", time.Since(start).Round(time.Millisecond).String())

	raw, stat, err := threatip.FetchWithStat(ch.URL)
	if err != nil {
		zlog.Error(fmt.Sprintf("威胁情报订阅拉取失败 channel=%s trigger=%s error=%s", ch.Code, trigger, err.Error()))
		r.markSyncFail(ch.Id, "拉取失败: "+err.Error())
		return err
	}
	zlog.Info("威胁情报订阅拉取完成", "channel", ch.Code, "status", stat.StatusCode,
		"bytes", stat.Bytes, "elapsed", stat.Elapsed.Round(time.Millisecond).String())

	parseStart := time.Now()
	parseRes, err := threatip.ParseByType(ch.ParserType, strings.NewReader(string(raw)), ch.Threshold)
	if err != nil {
		zlog.Error(fmt.Sprintf("威胁情报订阅解析失败 channel=%s parser=%s error=%s", ch.Code, ch.ParserType, err.Error()))
		r.markSyncFail(ch.Id, "解析失败: "+err.Error())
		return err
	}
	newIPs := parseRes.IPs
	zlog.Info("威胁情报订阅解析完成", "channel", ch.Code, "valid", len(newIPs), "dropped", parseRes.Dropped,
		"elapsed", time.Since(parseStart).Round(time.Millisecond).String())

	// 源返回 200 但一条有效数据都没有(常见于返回了验证页/错误页)，按失败处理，避免把空快照当成功
	if len(newIPs) == 0 {
		msg := fmt.Sprintf("解析结果为空(丢弃非法行 %d，响应 %d 字节)，可能订阅源返回了非预期内容或解析格式选错", parseRes.Dropped, stat.Bytes)
		zlog.Error(fmt.Sprintf("威胁情报订阅解析结果为空 channel=%s detail=%s", ch.Code, msg))
		r.markSyncFail(ch.Id, msg)
		return errors.New(msg)
	}

	// 载入上次快照做突变保护与 sha 比对
	oldIPs, oldSha := r.loadSnapshot(ch.Code)
	if len(oldIPs) > shrinkGuardMin && len(newIPs) < len(oldIPs)/shrinkGuardRatio {
		msg := fmt.Sprintf("疑似源异常：新快照 %d 条 远少于上次 %d 条，已跳过应用(丢弃非法行 %d)", len(newIPs), len(oldIPs), parseRes.Dropped)
		zlog.Warn("威胁情报订阅突变保护", "channel", ch.Code, "detail", msg)
		r.markSyncFail(ch.Id, msg)
		return errors.New(msg)
	}

	payload, sha, count, err := threatip.EncodeSnapshot(newIPs)
	if err != nil {
		zlog.Error(fmt.Sprintf("威胁情报订阅快照编码失败 channel=%s error=%s", ch.Code, err.Error()))
		r.markSyncFail(ch.Id, "快照编码失败: "+err.Error())
		return err
	}
	// 应用误报排除名单：内容集 → 有效集。落地相关的一切判据从这里往下都只认有效集，
	// 内容 sha 只继续负责"源内容变没变"。二者混用会导致"落地的是 N-k 条、对账的期望还是 N 条"，
	// 于是每小时判定不一致、全量重建、且永远对不上。
	effIPs, effSha, excluded := WafThreatIPExcludeServiceApp.EffectiveIPs(newIPs)
	rememberEffMeta(ch.Code, sha, WafThreatIPExcludeServiceApp.Get().Sha(), effSha, excluded)
	if excluded > 0 {
		zlog.Info("威胁情报订阅已应用误报排除", "channel", ch.Code, "content", count, "excluded", excluded, "effective", len(effIPs))
	}

	contentSame := sameContent(sha, oldSha)
	if landingUpToDate(sha, oldSha, ch.LandedSha, effSha) {
		// 内容与落地态都没变，才真的可以什么都不做
		zlog.Info("威胁情报订阅内容无变化且落地态一致，跳过落地", "channel", ch.Code, "count", count,
			"elapsed", time.Since(start).Round(time.Millisecond).String())
		r.markSyncOK(ch.Id, fmt.Sprintf("ok(无变化，%s触发，耗时%s)%s", trigger, time.Since(start).Round(time.Millisecond), excludedNote(excluded)), count, effSha, len(effIPs))
		return nil
	}
	if contentSame {
		// 内容没变但落地态对不上(上次落地中断/半截、排除名单刚改过、或从老版本升级上来 landed_sha 为空)：
		// 不早退，往下走一遍覆盖式重建把系统层拉回一致。
		zlog.Warn("威胁情报订阅内容无变化但落地态不一致，将覆盖式重建", "channel", ch.Code,
			"landed_sha", shortSha(ch.LandedSha), "eff_sha", shortSha(effSha))
	}

	added, removed := threatip.Diff(oldIPs, newIPs)

	// 保存新快照(替换该渠道旧快照)。快照存的是**内容集原文**，不是有效集——
	// 排除名单随时可能改回去，把过滤结果落库就再也还原不出源到底给了什么。
	// 内容没变时无需重写，省一次大 blob 读写。
	if !contentSame {
		if err := r.saveSnapshot(ch.Code, payload, sha, count); err != nil {
			zlog.Error(fmt.Sprintf("威胁情报订阅保存快照失败 channel=%s error=%s", ch.Code, err.Error()))
			r.markSyncFail(ch.Id, "保存快照失败: "+err.Error())
			return err
		}
	}

	// 落地系统防火墙(该渠道私有集合，全量重建)
	landErr := r.landSystemLayer(ch, effIPs, len(effIPs))

	// 落地 WAF 应用层(重建全局并集)。这层是纯内存 + atomic 发布，不存在半截状态。
	r.RebuildWAFUnion()

	elapsed := time.Since(start).Round(time.Millisecond)
	if landErr != nil {
		// 系统层没落全就**不能算成功**：不刷 LastSyncAt(下个整点定时会再来)，
		// 也不写 LandedSha(下次即使内容没变也会走覆盖式重建)。
		msg := fmt.Sprintf("系统层落地失败(内容已更新，将自动重试落地): %s", landErr.Error())
		zlog.Error(fmt.Sprintf("威胁情报订阅系统层落地失败 channel=%s trigger=%s error=%s", ch.Code, trigger, landErr.Error()))
		r.markSyncFail(ch.Id, msg)
		return landErr
	}

	r.markSyncOK(ch.Id, fmt.Sprintf("ok(+%d/-%d，丢弃%d，%s触发，耗时%s)%s", len(added), len(removed), parseRes.Dropped, trigger, elapsed, excludedNote(excluded)), count, effSha, len(effIPs))
	zlog.Info("威胁情报订阅同步完成", "channel", ch.Code, "trigger", trigger, "count", count,
		"added", len(added), "removed", len(removed), "elapsed", elapsed.String())
	return nil
}

// landSystemLayer 把这份 IP 列表落地到系统防火墙。
// 返回 nil 表示"已确认落地到位"，调用方据此写 LandedSha。
//
// 注意"环境不支持 ipset"返回 nil 而不是错误：那不是"这次落地失败"，是"这台机器就不做系统层"。
// 当成失败的话，LastSyncAt 永远不刷新，定时任务会每小时重新联网拉一次全量，对订阅源很不友好。
func (r *WafThreatIPService) landSystemLayer(ch model.ThreatIPChannel, ips []string, count int) error {
	if ch.LandTarget != model.ThreatLandSystem && ch.LandTarget != model.ThreatLandBoth {
		// 落地目标不含系统层：清理可能残留的系统集合(系统防火墙不可用时内部会直接跳过)
		r.destroySystemSet(ch.Code)
		return nil
	}
	if !r.fw.SupportsIPSet() {
		zlog.Warn("当前环境不支持 ipset 批量封禁，跳过系统层落地", "channel", ch.Code)
		return nil
	}
	landStart := time.Now()
	if err := r.fw.RestoreIPSet(setNameForChannel(ch.Code), ips); err != nil {
		return err
	}
	zlog.Info("威胁情报系统层落地完成", "channel", ch.Code, "count", count,
		"elapsed", time.Since(landStart).Round(time.Millisecond).String())
	return nil
}

// sameContent 本次拉到的内容与库里快照是否相同。
// snapshotSha 为空表示"从没存过快照"，此时一律按"内容变了"处理，必须走完整落地流程。
func sameContent(contentSha, snapshotSha string) bool {
	return contentSha == snapshotSha && snapshotSha != ""
}

// landingUpToDate 判断是否可以完全跳过落地：**内容态与落地态都一致**才行。
//
// 这是本模块最容易踩错的一个判据。只看内容 sha 的话会漏掉这条链路：
// 快照先落库 → 系统层落地中断(只封了一半) → 下次同步拉到相同内容 → 判定"无变化"早退
// → 永远不再落地，页面却一直显示 ok。加上 landedSha 之后，
// 落地没成功就永远不会等于应有的 sha，下一轮必定重建，直到真的落到位。
//
// landedSha 比的是 **effSha(有效集)** 而不是内容 sha：源内容没变、但用户改了误报排除名单时，
// 该落地的东西已经变了，必须重建。effSha 由过滤后的列表算出，排除名单一改它就变，
// 于是"排除生效"这件事完全不需要额外的失效通知机制，靠既有的对账循环自然完成。
// 排除名单为空时 effSha == contentSha，存量 landed_sha 保持有效，升级不会触发重建。
func landingUpToDate(contentSha, snapshotSha, landedSha, effSha string) bool {
	return sameContent(contentSha, snapshotSha) && landedSha == effSha && effSha != ""
}

// excludedNote 把"本次排除了多少条"拼进 last_status，让用户在列表上直接看到排除起了作用
func excludedNote(excluded int) string {
	if excluded <= 0 {
		return ""
	}
	return fmt.Sprintf("(已排除%d条误报)", excluded)
}

// shortSha 日志里只留 sha 前 8 位，够区分且不刷屏；空值显示为"(空)"
func shortSha(s string) string {
	if s == "" {
		return "(空)"
	}
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// RebuildWAFUnion 由所有"启用且落地含 waf"的渠道快照重建全局威胁情报并集，编译 MatchSet 后原子发布。
func (r *WafThreatIPService) RebuildWAFUnion() {
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = 1").Find(&channels)

	// 排除名单同样作用于 WAF 层：它的语义是"这个 IP 不是威胁"，
	// 而不是"这个 IP 别进防火墙"，两层心智必须一致。
	// 并集本来每次就全量重建、没有 sha 缓存，多一道过滤是白送的。
	exclude := WafThreatIPExcludeServiceApp.Get()

	uniq := make(map[string]struct{})
	excluded := 0
	for _, ch := range channels {
		if ch.LandTarget != model.ThreatLandWAF && ch.LandTarget != model.ThreatLandBoth {
			continue
		}
		ips, _ := r.loadSnapshot(ch.Code)
		res := exclude.Filter(ips)
		excluded += res.Excluded
		for _, ip := range res.Effective {
			uniq[ip] = struct{}{}
		}
	}
	if len(uniq) == 0 {
		ipset.SetGlobalThreatMatcher(nil)
		return
	}
	items := make([]string, 0, len(uniq))
	for ip := range uniq {
		items = append(items, ip)
	}
	buildStart := time.Now()
	ipset.SetGlobalThreatMatcher(ipset.BuildMatchSet(items))
	zlog.Info("威胁情报 WAF 并集已重建", "total", len(items), "excluded", excluded,
		"elapsed", time.Since(buildStart).Round(time.Millisecond).String())
}

// RestoreAllOnStartup 进程启动时重放：把各启用渠道的快照重新灌入系统 ipset(内存态，重启会丢)，
// 并重建 WAF 并集。由 main 启动流程调用。
//
// 需要持 syncMu：本方法在 main 里是裸 goroutine 起的，而紧接着几行就启动了任务调度器，
// 订阅到期时 task_threat_ip_sync 会立刻触发 SyncChannel，两边会对**同一个系统集合**
// 同时做"清旧 + 全量重建"。Windows 上 netsh 的 add 是追加不是替换，交错的结果就是
// 同名分片规则一层层叠加(线上实测同一分片名堆到 7 份)。
//
// 但锁只能**逐渠道**拿：整个循环持锁的话，几个大渠道就能把锁占住好几分钟，
// 用户这期间点"立即同步"只会看到"等待 30s 仍未轮到，启动重放"。
// 再叠加 IPSetUpToDate 快速跳过，正常启动这里几乎不会碰锁。
func (r *WafThreatIPService) RestoreAllOnStartup() {
	start := time.Now()
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = 1").Find(&channels)
	supportsIPSet := r.fw.SupportsIPSet()

	restored, skipped := 0, 0
	for _, ch := range channels {
		if ch.LandTarget != model.ThreatLandSystem && ch.LandTarget != model.ThreatLandBoth {
			continue
		}
		if !supportsIPSet {
			continue
		}
		ips, _ := r.loadSnapshot(ch.Code)
		if len(ips) == 0 {
			continue
		}
		// 重放的必须是**有效集**：直接灌快照原文，会把用户排除掉的误报 IP 每次重启都封回去
		effIPs, effSha, excluded := WafThreatIPExcludeServiceApp.EffectiveIPs(ips)
		_, snapSha := r.snapshotMeta(ch.Code)
		rememberEffMeta(ch.Code, snapSha, WafThreatIPExcludeServiceApp.Get().Sha(), effSha, excluded)
		if len(effIPs) == 0 {
			continue
		}
		setName := setNameForChannel(ch.Code)
		// 系统里已经就是这份内容(Windows 规则持久化)就别重建：省掉上百次 netsh，也不用抢锁
		if r.fw.IPSetUpToDate(setName, effIPs) {
			skipped++
			continue
		}
		if !r.tryLockSync(lockWaitStartupPerChannel, "启动重放渠道["+ch.Code+"]") {
			zlog.Warn("启动重放跳过该渠道(未获取同步锁)", "channel", ch.Code, "detail", r.busyHint())
			continue
		}
		if err := r.fw.RestoreIPSet(setName, effIPs); err != nil {
			// 不写 landed_sha：每小时的落地对账会发现落地态对不上并重试
			zlog.Error(fmt.Sprintf("启动重放系统层失败 channel=%s error=%s", ch.Code, err.Error()))
		} else {
			restored++
			r.markLanded(ch.Id, effSha, len(effIPs), "") // 启动重放不改"上次状态"，它反映的是上次同步结果
		}
		r.unlockSync()
	}

	// WAF 内存并集必须建起来，否则应用层威胁情报拦截整个失效。
	// 拿得到锁就在锁内建(避免与同步任务的重建互相覆盖)；拿不到也照建不误——
	// 并集发布是 atomic 的，宁可极小概率发布一份稍旧的，也不能让它压根没建。
	if r.tryLockSync(lockWaitStartupPerChannel, "启动重放重建并集") {
		r.RebuildWAFUnion()
		r.unlockSync()
	} else {
		r.RebuildWAFUnion()
	}
	zlog.Info("威胁情报启动重放完成", "channels", len(channels), "restored", restored,
		"skipped", skipped, "elapsed", time.Since(start).Round(time.Millisecond).String())
}

// ReconcileLanding 落地对账：**不联网**，只用库里已有的快照核对系统防火墙是否与之一致，
// 不一致就按渠道覆盖式重建。由每小时的 task_threat_ip_sync 在 SyncAllDue 之后调用。
//
// 为什么必须有这一步：内容 sha 与落地态是两码事。系统层落地可能被中断
// (Windows 一次重建是几十次独立 netsh，中途失败留下半截规则)、可能被用户手工清理、
// 可能被组策略刷掉。光看内容 sha 的话，源方内容不变就永远不会再落地，
// 防火墙里那份残缺状态会一直留着，而页面显示 ok —— 这是"沉默的部分失效"。
//
// 对账只针对系统防火墙层：WAF 应用层是纯内存 + atomic 发布，不存在半截状态，
// 每次 RebuildWAFUnion 都是从快照全量重算。
func (r *WafThreatIPService) ReconcileLanding() {
	if !r.fw.SupportsIPSet() {
		return // 环境本来就不做系统层落地，无账可对
	}
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = 1").Find(&channels)

	start := time.Now()
	checked, repaired, failed := 0, 0, 0
	for _, ch := range channels {
		if ch.LandTarget != model.ThreatLandSystem && ch.LandTarget != model.ThreatLandBoth {
			continue
		}
		ips, _ := r.loadSnapshot(ch.Code)
		if len(ips) == 0 {
			continue // 还没同步过，没什么可对
		}
		// 期望值必须是**有效集**，与落地时用的完全同源。
		// 若这里拿快照原文去比对，而落地的是过滤后的 N-k 条，就会每小时判定不一致、
		// 每小时全量重建、而且永远修不好——期望值和实际值天生对不上。
		effIPs, effSha, excluded := WafThreatIPExcludeServiceApp.EffectiveIPs(ips)
		_, snapSha := r.snapshotMeta(ch.Code)
		rememberEffMeta(ch.Code, snapSha, WafThreatIPExcludeServiceApp.Get().Sha(), effSha, excluded)
		if len(effIPs) == 0 {
			continue
		}
		checked++

		// 只问一次防火墙。IPSetUpToDate 在 Windows 上要枚举整张防火墙规则表，
		// 规则多时单次就是秒级——按渠道各问两遍会把整轮对账拖成分钟级，
		// 期间 CPU/磁盘被 netsh 占满，管理端接口跟着一起变慢。
		upToDate := r.fw.IPSetUpToDate(setNameForChannel(ch.Code), effIPs)
		if upToDate {
			if ch.LandedSha != effSha {
				// 系统里其实是对的，只是落地态没记上：只补记，不动"上次状态"——
				// 什么都没发生，不该把用户上次看到的结果冲掉。
				r.markLanded(ch.Id, effSha, len(effIPs), "")
			}
			continue
		}

		zlog.Warn("威胁情报落地对账发现不一致，开始覆盖式重建", "channel", ch.Code,
			"effective", len(effIPs), "excluded", excluded,
			"landed_sha", shortSha(ch.LandedSha), "eff_sha", shortSha(effSha))
		if !r.tryLockSync(lockWaitStartupPerChannel, fmt.Sprintf("渠道[%s]落地对账", ch.Code)) {
			zlog.Warn("落地对账跳过该渠道(未获取同步锁)", "channel", ch.Code, "detail", r.busyHint())
			continue
		}
		err := r.fw.RestoreIPSet(setNameForChannel(ch.Code), effIPs)
		r.unlockSync()

		if err != nil {
			failed++
			zlog.Error(fmt.Sprintf("威胁情报落地对账重建失败 channel=%s error=%s", ch.Code, err.Error()))
			// 不写 landed_sha，下一轮对账继续尝试；同时让用户在列表上看得见
			r.markSyncFail(ch.Id, "落地对账重建失败(将自动重试): "+err.Error())
			continue
		}
		repaired++
		// 必须覆盖"上次状态"：上一条多半是"系统层落地失败…"，修好了还挂着就成了假报错
		r.markLanded(ch.Id, effSha, len(effIPs), fmt.Sprintf("ok(落地对账已修复，%d条)%s", len(effIPs), excludedNote(excluded)))
		zlog.Info("威胁情报落地对账重建完成", "channel", ch.Code, "count", len(effIPs))
	}

	if checked > 0 {
		zlog.Info("威胁情报落地对账完成", "checked", checked, "repaired", repaired, "failed", failed,
			"elapsed", time.Since(start).Round(time.Millisecond).String())
	}
}

// SyncAllDue 定时任务调用：遍历启用渠道，按 IntervalHour 判断是否到期，逐个同步。
func (r *WafThreatIPService) SyncAllDue() {
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = 1").Find(&channels)
	now := time.Now().Unix()
	due := 0
	for _, ch := range channels {
		interval := int64(defaultInt(ch.IntervalHour, 24)) * 3600
		if ch.LastSyncAt > 0 && now-ch.LastSyncAt < interval {
			continue // 未到期
		}
		due++
		if err := r.syncChannelWithTrigger(ch, syncTriggerSchedule); err != nil {
			zlog.Warn("威胁情报订阅同步失败", "channel", ch.Code, "error", err.Error())
		}
	}
	zlog.Info("威胁情报订阅定时检查完成", "enabled", len(channels), "due", due)
}

// ---------------- 内部辅助 ----------------

// loadSnapshot 载入某渠道快照，返回 IP 列表与 sha(无则空)
func (r *WafThreatIPService) loadSnapshot(code string) ([]string, string) {
	var snap model.ThreatIPSnapshot
	err := global.GWAF_LOCAL_DB.Where("channel_code = ?", code).First(&snap).Error
	if err != nil {
		return nil, ""
	}
	ips, derr := threatip.DecodeSnapshot(snap.Payload)
	if derr != nil {
		zlog.Warn("解压威胁情报快照失败", "channel", code, "error", derr.Error())
		return nil, snap.Sha256
	}
	return ips, snap.Sha256
}

// saveSnapshot 替换某渠道的快照(删旧插新，一行一渠道)
func (r *WafThreatIPService) saveSnapshot(code string, payload []byte, sha string, count int) error {
	global.GWAF_LOCAL_DB.Where("channel_code = ?", code).Delete(&model.ThreatIPSnapshot{})
	snap := &model.ThreatIPSnapshot{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		ChannelCode: code,
		IPVersion:   0, // 0 表示 v4/v6 合并存放
		Count:       count,
		Payload:     payload,
		Sha256:      sha,
	}
	return global.GWAF_LOCAL_DB.Create(snap).Error
}

// markSyncOK 同步成功后回写：刷新同步时间、收录条数、状态，以及**已确认落地**的有效集 sha。
//
// count 是**内容集**条数(源收录了多少)，landedCount 是**有效集**条数(实际落地了多少)。
// 两者在有误报排除时会不一样，必须分开记：前者反映订阅源，后者反映防火墙里真实的样子。
func (r *WafThreatIPService) markSyncOK(id, status string, count int, landedSha string, landedCount int) {
	r.updateSyncFields(id, map[string]interface{}{
		"LastSyncAt":  time.Now().Unix(),
		"LastCount":   count,
		"LastStatus":  truncateStatus(status),
		"LandedSha":   landedSha,
		"LandedCount": landedCount,
	})
}

// markLanded 更新落地态。status 为空表示不动"上次状态"。
//
// 刻意**不动 LastSyncAt**：对账没有重新联网拉取，不该冒充一次成功同步。
// 但 status 该给的时候必须给——修好之后若不覆盖，列表里会一直挂着上一次的
// "系统层落地失败…"，用户看到的是个已经不成立的报错。
func (r *WafThreatIPService) markLanded(id, landedSha string, count int, status string) {
	fields := map[string]interface{}{
		"LandedSha":   landedSha,
		"LandedCount": count,
	}
	if status != "" {
		fields["LastStatus"] = truncateStatus(status)
	}
	r.updateSyncFields(id, fields)
}

// markSyncFail 同步失败后回写：只写状态原因。
//
// 刻意不动 LastSyncAt、LastCount：
//   - 以前失败也把 LastSyncAt 刷成当前时间，SyncAllDue 的到期判断就把失败当成了成功，
//     导致整整一个周期(默认 24h)不再重试——这正是用户说的"后面再也没成功"；
//     不刷新之后，下一次每小时的定时任务会自然重试。
//   - 以前失败还会把 LastCount 抹成 0，把上一次的真实条数丢掉。
func (r *WafThreatIPService) markSyncFail(id, status string) {
	r.updateSyncFields(id, map[string]interface{}{
		"LastStatus": truncateStatus(status),
	})
}

// updateSyncFields 统一回写同步相关字段(自动补 UPDATE_TIME)
func (r *WafThreatIPService) updateSyncFields(id string, fields map[string]interface{}) {
	fields["UPDATE_TIME"] = customtype.JsonTime(time.Now())
	if err := global.GWAF_LOCAL_DB.Model(&model.ThreatIPChannel{}).Where("id = ?", id).Updates(fields).Error; err != nil {
		zlog.Warn("威胁情报订阅状态回写失败", "id", id, "error", err.Error())
	}
}

func truncateStatus(s string) string {
	if len(s) > 250 {
		return s[:250]
	}
	return s
}

func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func defaultInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// validateChannelCode 校验渠道短码：小写字母/数字/下划线，长度 1-13(为 ipset 名 samwaf_sub_<code> ≤24 预留)
func validateChannelCode(code string) error {
	if len(code) == 0 || len(code) > 13 {
		return errors.New("渠道短码长度需为 1-13")
	}
	for _, c := range code {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_' {
			return errors.New("渠道短码仅允许小写字母/数字/下划线")
		}
	}
	return nil
}
