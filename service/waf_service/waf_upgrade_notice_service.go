package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"SamWaf/wafupgradenotice"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

// 升级须知：升级完成后在产品内告诉用户"这次变了什么、建议点哪个开关、点了和不点有什么区别"。
//
// 数据源是随版本编译进二进制的内置清单(wafupgradenotice)，库里只存 notice_id 与处理状态，
// 文案渲染时现取——文案修订随版本走，库里也不留冗余文本。
type WafUpgradeNoticeService struct{}

var WafUpgradeNoticeServiceApp = new(WafUpgradeNoticeService)

// downgradeAckItem 记录用户已确认过的降级告警对应的"历史最高版本"。
// 只有 max_run_version 再次变高（说明又升级又回退了一次，是新证据）时告警才会重新出现。
const downgradeAckItem = "downgrade_notice_ack"

// 启动时算出来的一次性状态：本次是从哪个版本升到哪个版本、是否在降级运行
var (
	upgradeStateMu     sync.RWMutex
	upgradeFromVersion string
	upgradeToVersion   string
	downgradeMessage   string
	downgradeMaxSeen   string // 触发本次降级告警的历史最高版本，确认告警时记它
)

// Generate 按"上次运行版本 → 当前版本"生成本次应当提示的须知。
//
// 由 main 在 CheckVersionDowngrade 之后调用（那个函数读完 last_run_version 会立刻写回当前版本，
// 所以旧版本号必须由它交出来，不能在这里再查一次）。
//
//	last 为空 + 库里没有任何站点 → 认作全新安装，只给"全新安装建议"
//	last 为空 + 库里已有站点     → 老实例首次升到带本功能的版本，起点未知，只给当前这一版的条目
//	last < current               → 给 (last, current] 区间内的条目
//	last >= current              → 不生成；降级时另记一条界面可见的告警
//
// maxSeen 是"曾经运行过的最高版本"（只升不降），**降级判定用它而不是 last**：
// last 会被写回成当前这个较低的版本，用它判定的话重启一次告警就消失了，
// 而"旧程序 + 新库"的状态还在（见 waftask.CheckVersionDowngrade 的说明）。
//
// 任何失败都只记日志，绝不阻断启动。
func (receiver *WafUpgradeNoticeService) Generate(last, current, maxSeen string) {
	if global.GWAF_LOCAL_DB == nil {
		return
	}
	last = strings.TrimSpace(last)
	current = strings.TrimSpace(current)
	maxSeen = strings.TrimSpace(maxSeen)
	if maxSeen == "" {
		maxSeen = last
	}

	upgradeStateMu.Lock()
	// 同版本重启时不报"从 vX 升级到 vX"：留空让界面改用"当前版本 vX"的说法。
	// 上次升级遗留的未处理条目仍在，提示条也还会出现，只是不再声称刚发生过一次升级。
	upgradeFromVersion = last
	if last == current {
		upgradeFromVersion = ""
	}
	upgradeToVersion = current
	downgradeMessage = ""
	downgradeMaxSeen = ""
	if maxSeen != "" && semver.IsValid(maxSeen) && semver.IsValid(current) && semver.Compare(maxSeen, current) > 0 {
		downgradeMaxSeen = maxSeen
		downgradeMessage = "检测到降级运行：数据库记录曾经运行过的最高版本是 " + maxSeen + "，当前程序版本是 " + current +
			"。若为容器部署，通常是应用内升级后容器被重建、程序回退到镜像自带版本所致；数据库已按新版本迁移且无法回退，请把镜像更新到 " + maxSeen + " 或更高版本后重建容器"
	}
	upgradeStateMu.Unlock()

	if err := wafupgradenotice.LoadError(); err != nil {
		zlog.Warn("升级须知内置清单解析失败", "error", err.Error())
		return
	}

	notes := wafupgradenotice.Select(last, current, receiver.isFreshInstall())
	if len(notes) == 0 {
		return
	}

	created := 0
	for _, note := range notes {
		var count int64
		if err := global.GWAF_LOCAL_DB.Model(&model.UpgradeNoticeRecord{}).
			Where("notice_id = ?", note.Id).Count(&count).Error; err != nil {
			zlog.Debug("查询升级须知记录失败", err.Error())
			continue
		}
		// 已生成过就跳过：不覆盖用户已有的处理状态
		if count > 0 {
			continue
		}
		bean := model.UpgradeNoticeRecord{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			NoticeId:    note.Id,
			Version:     note.Version,
			FromVersion: last,
			ToVersion:   current,
			Kind:        note.Kind,
			Level:       note.Level,
			Status:      model.UpgradeNoticeStatusPending,
		}
		if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
			zlog.Debug("写入升级须知记录失败", err.Error())
			continue
		}
		created++
	}
	if created > 0 {
		zlog.Info("升级须知已生成", "from", last, "to", current, "count", created)
	}
}

// isFreshInstall 判断是不是全新安装。
//
// 没有站点 = 这个实例还没被用起来。存量用户首次升到带本功能的版本时 last_run_version 同样为空，
// 靠这个信号把两者分开，避免给老用户倒一堆"改初始密码"之类的新手提示。
func (receiver *WafUpgradeNoticeService) isFreshInstall() bool {
	var hostCount int64
	if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Count(&hostCount).Error; err != nil {
		return false
	}
	return hostCount == 0
}

// GetListApi 分页查询升级须知
func (receiver *WafUpgradeNoticeService) GetListApi(req request.WafUpgradeNoticeSearchReq) ([]response.UpgradeNoticeItem, int64, error) {
	if global.GWAF_LOCAL_DB == nil {
		return nil, 0, errors.New("数据库未就绪")
	}
	known := knownNoticeIds()
	if len(known) == 0 {
		return []response.UpgradeNoticeItem{}, 0, nil
	}

	// 清单里已删除的条目会在库里留下孤儿记录，用 IN 直接排除，保证总数与分页都对得上
	tx := global.GWAF_LOCAL_DB.Model(&model.UpgradeNoticeRecord{}).Where("notice_id in ?", known)
	if req.Status != "" {
		tx = tx.Where("status = ?", req.Status)
	}
	if req.Kind != "" {
		tx = tx.Where("kind = ?", req.Kind)
	}
	if req.Version != "" {
		// 前端传的是归一化后的展示版本(v1.3.24)，库里存的是原始值(可能是 v1.3.24-beta.15)
		tx = tx.Where("version in ?", wafupgradenotice.RawVersionsFor(req.Version))
	}

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageIndex := req.PageIndex
	if pageIndex <= 0 {
		pageIndex = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}

	var beans []model.UpgradeNoticeRecord
	// 重要的排前面，同级按引入版本倒序（新版本的事更要紧）
	if err := tx.Order("case level when 'high' then 0 when 'normal' then 1 else 2 end, version desc, create_time desc").
		Offset((pageIndex - 1) * pageSize).Limit(pageSize).Find(&beans).Error; err != nil {
		return nil, 0, err
	}

	items := make([]response.UpgradeNoticeItem, 0, len(beans))
	for _, bean := range beans {
		if item, ok := toItem(bean, req.Lang); ok {
			items = append(items, item)
		}
	}
	return items, total, nil
}

// GetSummary 顶部提示条与登录弹窗需要的汇总
func (receiver *WafUpgradeNoticeService) GetSummary(lang string) response.UpgradeNoticeSummary {
	upgradeStateMu.RLock()
	summary := response.UpgradeNoticeSummary{
		CurrentVersion: global.GWAF_RELEASE_VERSION,
		FromVersion:    upgradeFromVersion,
		ToVersion:      upgradeToVersion,
		Downgrade:      downgradeMessage != "",
		DowngradeMsg:   downgradeMessage,
	}
	maxSeen := downgradeMaxSeen
	upgradeStateMu.RUnlock()

	// 用户确认过同一个"历史最高版本"就不再显示；max 再变高说明是新证据，告警重新出现
	if summary.Downgrade && WafSystemConfigServiceApp.GetDetailByItem(downgradeAckItem).Value == maxSeen {
		summary.Downgrade = false
		summary.DowngradeMsg = ""
	}

	if global.GWAF_LOCAL_DB == nil {
		return summary
	}
	known := knownNoticeIds()
	if len(known) == 0 {
		return summary
	}

	global.GWAF_LOCAL_DB.Model(&model.UpgradeNoticeRecord{}).
		Where("notice_id in ?", known).Count(&summary.TotalCount)
	global.GWAF_LOCAL_DB.Model(&model.UpgradeNoticeRecord{}).
		Where("notice_id in ? and status = ?", known, model.UpgradeNoticeStatusPending).
		Count(&summary.PendingCount)

	var highPending []model.UpgradeNoticeRecord
	global.GWAF_LOCAL_DB.Model(&model.UpgradeNoticeRecord{}).
		Where("notice_id in ? and status = ? and level = ?", known, model.UpgradeNoticeStatusPending, wafupgradenotice.LevelHigh).
		Order("version desc").Find(&highPending)
	summary.HighPendingCount = int64(len(highPending))

	for _, bean := range highPending {
		item, ok := toItem(bean, lang)
		if !ok {
			continue
		}
		summary.PopupItems = append(summary.PopupItems, item)
		// 只要有一条重要须知还没弹过窗，本次登录就弹一次
		if bean.PopupShown == 0 {
			summary.NeedPopup = true
		}
	}
	return summary
}

// SetStatus 标记处理状态（我知道了 / 忽略 / 恢复待处理）
func (receiver *WafUpgradeNoticeService) SetStatus(noticeId, status, operator string) error {
	if global.GWAF_LOCAL_DB == nil {
		return errors.New("数据库未就绪")
	}
	noticeId = strings.TrimSpace(noticeId)
	if noticeId == "" {
		return errors.New("条目不能为空")
	}
	// 只认内置清单里存在的条目，杜绝伪造 id 往表里写状态
	if _, ok := wafupgradenotice.ByID(noticeId); !ok {
		return errors.New("条目不存在")
	}
	switch status {
	case model.UpgradeNoticeStatusPending, model.UpgradeNoticeStatusDone, model.UpgradeNoticeStatusIgnored:
	default:
		return errors.New("状态非法")
	}

	updates := map[string]interface{}{
		"status":      status,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	if status == model.UpgradeNoticeStatusPending {
		updates["applied_user"] = ""
		updates["applied_time"] = nil
	} else {
		updates["applied_user"] = operator
		updates["applied_time"] = customtype.JsonTime(time.Now())
	}
	return global.GWAF_LOCAL_DB.Model(&model.UpgradeNoticeRecord{}).
		Where("notice_id = ?", noticeId).Updates(updates).Error
}

// MarkPopupShown 弹窗关闭后回写：此后不再弹，靠首页提示条和列表页兜底
func (receiver *WafUpgradeNoticeService) MarkPopupShown() error {
	if global.GWAF_LOCAL_DB == nil {
		return errors.New("数据库未就绪")
	}
	return global.GWAF_LOCAL_DB.Model(&model.UpgradeNoticeRecord{}).
		Where("popup_shown = ?", 0).
		Updates(map[string]interface{}{
			"popup_shown": 1,
			"UPDATE_TIME": customtype.JsonTime(time.Now()),
		}).Error
}

// AckDowngrade 确认降级告警：记下当前这个"历史最高版本"，此后不再显示。
//
// 不做成"永久关闭"：只要 max_run_version 再次变高（用户又升级又回退了一次），
// 就是新的证据，告警会重新出现。
func (receiver *WafUpgradeNoticeService) AckDowngrade() error {
	upgradeStateMu.RLock()
	maxSeen := downgradeMaxSeen
	hasWarning := downgradeMessage != ""
	upgradeStateMu.RUnlock()

	if !hasWarning || maxSeen == "" {
		return errors.New("当前没有降级告警")
	}

	existing := WafSystemConfigServiceApp.GetDetailByItem(downgradeAckItem)
	if existing.Id != "" {
		return WafSystemConfigServiceApp.ModifyByItemApi(request.WafSystemConfigEditByItemReq{
			Item:  downgradeAckItem,
			Value: maxSeen,
		})
	}
	return WafSystemConfigServiceApp.AddApi(request.WafSystemConfigAddReq{
		ItemClass: "system",
		Item:      downgradeAckItem,
		Value:     maxSeen,
		Remarks:   "已确认过的降级告警对应的历史最高版本；曾经运行过的最高版本再次变高时告警会重新出现，请勿手工修改",
		ItemType:  "string",
	})
}

// knownNoticeIds 当前二进制内置清单里的全部条目 id
func knownNoticeIds() []string {
	notes := wafupgradenotice.All()
	ids := make([]string, 0, len(notes))
	for _, n := range notes {
		ids = append(ids, n.Id)
	}
	return ids
}

// toItem 把库记录 + 内置清单文案拼成一条返回项；清单里已没有的条目返回 false 由调用方丢弃
func toItem(bean model.UpgradeNoticeRecord, lang string) (response.UpgradeNoticeItem, bool) {
	note, ok := wafupgradenotice.ByID(bean.NoticeId)
	if !ok {
		zlog.Debug("升级须知记录在当前版本清单中已不存在，跳过", "notice_id", bean.NoticeId)
		return response.UpgradeNoticeItem{}, false
	}
	text := note.Text(lang)
	item := response.UpgradeNoticeItem{
		NoticeId:     note.Id,
		Version:      wafupgradenotice.DisplayVersion(note.Version),
		Kind:         note.Kind,
		Level:        note.Level,
		Status:       bean.Status,
		FreshInstall: note.FreshInstall,
		Title:        text.Title,
		Detail:       text.Detail,
		EffectOn:     text.EffectOn,
		EffectOff:    text.EffectOff,
		Revert:       text.Revert,
		Page:         note.Page,
		Doc:          note.Doc,
		ApplyType:    note.Apply.Type,
		AppliedUser:  bean.AppliedUser,
	}
	if applied := time.Time(bean.AppliedTime); !applied.IsZero() {
		item.AppliedTime = applied.Format("2006-01-02 15:04:05")
	}
	return item, true
}
