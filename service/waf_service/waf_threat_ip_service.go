package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
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
	"strings"
	"sync"
	"time"
)

// WafThreatIPService 威胁情报 IP 订阅服务：渠道 CRUD + 拉取同步 + 落地(WAF 应用层 / 系统防火墙)。
type WafThreatIPService struct {
	fw     firewall.FireWallEngine
	syncMu sync.Mutex // 串行化同步，避免多渠道并发拉取造成内核/内存压力
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
	go func() {
		r.applyEnableState(code, landTarget, enable)
		r.notifyOpResult("威胁情报订阅保存生效", name, nil)
	}()
	return nil
}

// applyEnableState 依据启用状态把某渠道落地到位：系统集合的增删 + 重建 WAF 应用层并集。
// 供编辑保存后异步调用；串行化(syncMu)避免与同步任务并发改动内核/内存态。
func (r *WafThreatIPService) applyEnableState(code, landTarget string, enable int) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	if enable == 0 {
		// 停用：清理系统集合(WAF 并集在下方重建时自动排除该渠道)
		r.fw.DestroyIPSet(setNameForChannel(code))
	} else if landTarget == model.ThreatLandSystem || landTarget == model.ThreatLandBoth {
		// 启用且落地含系统层：把快照重新灌回系统集合(重启/停用会丢，需按需回灌)
		if r.fw.SupportsIPSet() {
			if ips, _ := r.loadSnapshot(code); len(ips) > 0 {
				if err := r.fw.RestoreIPSet(setNameForChannel(code), ips); err != nil {
					zlog.Warn("启用渠道系统层落地失败", "channel", code, "error", err.Error())
				}
			}
		}
	} else {
		// 启用但落地不含系统层：清理可能残留的系统集合
		r.fw.DestroyIPSet(setNameForChannel(code))
	}
	r.RebuildWAFUnion()
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
	go func() {
		r.syncMu.Lock()
		r.fw.DestroyIPSet(setNameForChannel(code))
		r.RebuildWAFUnion()
		r.syncMu.Unlock()
		r.notifyOpResult("威胁情报订阅删除生效", name, nil)
	}()
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
		if c := r.snapshotCount(list[i].Code); c >= 0 {
			list[i].LastCount = c
		}
	}
	return list, total, err
}

// ---------------- 订阅落地只读浏览(方案三：原页"订阅来源"Tab) ----------------

// LandedChannelSummary 某渠道在指定层的落地汇总
type LandedChannelSummary struct {
	Code          string `json:"code"`
	Name          string `json:"name"`
	LandTarget    string `json:"land_target"`
	Enable        int    `json:"enable"`
	Count         int    `json:"count"`          // 实际生效(已落地)条数：启用=快照条数，停用=0(已从防火墙/WAF移除)
	SnapshotCount int    `json:"snapshot_count"` // 快照收录条数(不论启用与否，供停用时提示"再启用可回灌")
	LastSyncAt    int64  `json:"last_sync_at"`   // 上次同步时间戳(秒)
	LastStatus    string `json:"last_status"`    // 上次同步结果
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
		snapCnt := r.snapshotCount(ch.Code)
		if snapCnt < 0 {
			snapCnt = 0
		}
		// 实际落地条数：停用渠道已从防火墙/WAF 移除，落地数应为 0(快照仍保留以便再启用秒回灌)
		landed := snapCnt
		if ch.Enable == 0 {
			landed = 0
		}
		out = append(out, LandedChannelSummary{
			Code:          ch.Code,
			Name:          ch.Name,
			LandTarget:    ch.LandTarget,
			Enable:        ch.Enable,
			Count:         landed,
			SnapshotCount: snapCnt,
			LastSyncAt:    ch.LastSyncAt,
			LastStatus:    ch.LastStatus,
		})
	}
	return out
}

// GetLandedIPs 分页浏览某渠道快照里的 IP/CIDR(只读)。keyword 为子串过滤(可空)。
// 返回当前页切片与过滤后总数。
func (r *WafThreatIPService) GetLandedIPs(code, keyword string, pageIndex, pageSize int) ([]string, int64) {
	ips, _ := r.loadSnapshot(code) // 已排序去重
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		filtered := make([]string, 0, len(ips))
		for _, ip := range ips {
			if strings.Contains(ip, keyword) {
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
		return []string{}, total
	}
	end := start + pageSize
	if end > len(ips) {
		end = len(ips)
	}
	return ips[start:end], total
}

// snapshotCount 取某渠道快照的收录条数(不解压 payload)。无快照返回 -1。
func (r *WafThreatIPService) snapshotCount(code string) int {
	var snap model.ThreatIPSnapshot
	if err := global.GWAF_LOCAL_DB.Select("count").Where("channel_code = ?", code).First(&snap).Error; err != nil {
		return -1
	}
	return snap.Count
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
	go func() {
		err := r.SyncChannel(bean)
		r.notifyOpResult("威胁情报订阅同步", bean.Name, err)
	}()
	return nil
}

// SyncChannel 拉取→解析→与上次快照比对→(突变保护)→保存快照→落地(系统 ipset + WAF 并集)。
func (r *WafThreatIPService) SyncChannel(ch model.ThreatIPChannel) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()

	raw, err := threatip.Fetch(ch.URL)
	if err != nil {
		r.markSyncStatus(ch.Id, "拉取失败: "+err.Error(), 0)
		return err
	}
	parseRes, err := threatip.ParseByType(ch.ParserType, strings.NewReader(string(raw)), ch.Threshold)
	if err != nil {
		r.markSyncStatus(ch.Id, "解析失败: "+err.Error(), 0)
		return err
	}
	newIPs := parseRes.IPs

	// 载入上次快照做突变保护与 sha 比对
	oldIPs, oldSha := r.loadSnapshot(ch.Code)
	if len(oldIPs) > shrinkGuardMin && len(newIPs) < len(oldIPs)/shrinkGuardRatio {
		msg := fmt.Sprintf("疑似源异常：新快照 %d 条 远少于上次 %d 条，已跳过应用(丢弃非法行 %d)", len(newIPs), len(oldIPs), parseRes.Dropped)
		zlog.Warn("威胁情报订阅突变保护", "channel", ch.Code, "detail", msg)
		r.markSyncStatus(ch.Id, msg, len(oldIPs))
		return errors.New(msg)
	}

	payload, sha, count, err := threatip.EncodeSnapshot(newIPs)
	if err != nil {
		r.markSyncStatus(ch.Id, "快照编码失败: "+err.Error(), 0)
		return err
	}
	if sha == oldSha && oldSha != "" {
		// 无变化：仅更新同步时间
		r.markSyncStatus(ch.Id, "ok(无变化)", count)
		return nil
	}

	added, removed := threatip.Diff(oldIPs, newIPs)

	// 保存新快照(替换该渠道旧快照)
	if err := r.saveSnapshot(ch.Code, payload, sha, count); err != nil {
		r.markSyncStatus(ch.Id, "保存快照失败: "+err.Error(), 0)
		return err
	}

	// 落地系统防火墙(该渠道私有集合，全量重建)
	if ch.LandTarget == model.ThreatLandSystem || ch.LandTarget == model.ThreatLandBoth {
		if r.fw.SupportsIPSet() {
			if err := r.fw.RestoreIPSet(setNameForChannel(ch.Code), newIPs); err != nil {
				zlog.Warn("威胁情报系统层落地失败", "channel", ch.Code, "error", err.Error())
			}
		} else {
			zlog.Warn("当前环境不支持 ipset 批量封禁，跳过系统层落地", "channel", ch.Code)
		}
	} else {
		// 落地目标不含系统层：清理可能残留的系统集合
		r.fw.DestroyIPSet(setNameForChannel(ch.Code))
	}

	// 落地 WAF 应用层(重建全局并集)
	r.RebuildWAFUnion()

	r.markSyncStatus(ch.Id, fmt.Sprintf("ok(+%d/-%d，丢弃%d)", len(added), len(removed), parseRes.Dropped), count)
	zlog.Info("威胁情报订阅同步完成", "channel", ch.Code, "count", count, "added", len(added), "removed", len(removed))
	return nil
}

// RebuildWAFUnion 由所有"启用且落地含 waf"的渠道快照重建全局威胁情报并集，编译 MatchSet 后原子发布。
func (r *WafThreatIPService) RebuildWAFUnion() {
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = 1").Find(&channels)

	uniq := make(map[string]struct{})
	for _, ch := range channels {
		if ch.LandTarget != model.ThreatLandWAF && ch.LandTarget != model.ThreatLandBoth {
			continue
		}
		ips, _ := r.loadSnapshot(ch.Code)
		for _, ip := range ips {
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
	ipset.SetGlobalThreatMatcher(ipset.BuildMatchSet(items))
	zlog.Info("威胁情报 WAF 并集已重建", "total", len(items))
}

// RestoreAllOnStartup 进程启动时重放：把各启用渠道的快照重新灌入系统 ipset(内存态，重启会丢)，
// 并重建 WAF 并集。由 main 启动流程调用。
func (r *WafThreatIPService) RestoreAllOnStartup() {
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = 1").Find(&channels)
	supportsIPSet := r.fw.SupportsIPSet()
	for _, ch := range channels {
		if ch.LandTarget == model.ThreatLandSystem || ch.LandTarget == model.ThreatLandBoth {
			if !supportsIPSet {
				continue
			}
			ips, _ := r.loadSnapshot(ch.Code)
			if len(ips) > 0 {
				if err := r.fw.RestoreIPSet(setNameForChannel(ch.Code), ips); err != nil {
					zlog.Warn("启动重放系统层失败", "channel", ch.Code, "error", err.Error())
				}
			}
		}
	}
	r.RebuildWAFUnion()
}

// SyncAllDue 定时任务调用：遍历启用渠道，按 IntervalHour 判断是否到期，逐个同步。
func (r *WafThreatIPService) SyncAllDue() {
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = 1").Find(&channels)
	now := time.Now().Unix()
	for _, ch := range channels {
		interval := int64(defaultInt(ch.IntervalHour, 24)) * 3600
		if ch.LastSyncAt > 0 && now-ch.LastSyncAt < interval {
			continue // 未到期
		}
		if err := r.SyncChannel(ch); err != nil {
			zlog.Warn("威胁情报订阅同步失败", "channel", ch.Code, "error", err.Error())
		}
	}
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

// markSyncStatus 更新渠道同步状态字段
func (r *WafThreatIPService) markSyncStatus(id, status string, count int) {
	if err := global.GWAF_LOCAL_DB.Model(&model.ThreatIPChannel{}).Where("id = ?", id).Updates(map[string]interface{}{
		"LastSyncAt":  time.Now().Unix(),
		"LastCount":   count,
		"LastStatus":  truncateStatus(status),
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}).Error; err != nil {
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
