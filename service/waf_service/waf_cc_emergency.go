package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	response2 "SamWaf/model/response"
	"errors"
	"time"

	"gorm.io/gorm"
)

// ccEmergencyMaxMinutes 紧急模式一次最长开多久（24 小时）。
//
// 不提供「永久」以外的更长档位是刻意的：紧急模式让全部访客多走一道人机验证，
// 它是应急闸门不是常态配置。真要长期开着，用户得显式选「手动关闭前一直开」，
// 那是一个需要自己承担后果的选择，不该藏在一个「30 天」的下拉里顺手点上。
const ccEmergencyMaxMinutes = 24 * 60

type WafCCEmergencyService struct{}

var WafCCEmergencyServiceApp = new(WafCCEmergencyService)

// SetEmergency 开关某个站点的紧急模式，返回更新后的站点记录供调用方通知引擎。
func (receiver *WafCCEmergencyService) SetEmergency(hostCode string, enable, durationMin int) (model.Hosts, error) {
	var host model.Hosts
	if hostCode == "" {
		return host, errors.New("网站不能为空")
	}
	err := global.GWAF_LOCAL_DB.Where("code = ?", hostCode).First(&host).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return host, errors.New("网站不存在")
		}
		return host, err
	}

	var until int64
	if enable == 1 {
		if durationMin < 0 {
			durationMin = 0
		}
		if durationMin > ccEmergencyMaxMinutes {
			durationMin = ccEmergencyMaxMinutes
		}
		if durationMin > 0 {
			until = time.Now().Add(time.Duration(durationMin) * time.Minute).Unix()
		}
	} else {
		enable = 0
		// 关闭时把到期时间一并清零，免得下次开启时界面上还挂着上一轮的残留时间
		until = 0
	}

	upd := map[string]interface{}{
		"emergency_mode":  enable,
		"emergency_until": until,
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_DB.Model(model.Hosts{}).Where("code = ?", hostCode).Updates(upd).Error; err != nil {
		return host, err
	}
	host.EmergencyMode = enable
	host.EmergencyUntil = until
	return host, nil
}

// EmergencyStatus 返回站点的紧急模式状态。hostCode 为空时返回全部当前处于开启状态的站点，
// 供界面提示「还有哪些站点开着」——开着忘了关是这个功能最现实的风险。
func (receiver *WafCCEmergencyService) EmergencyStatus(hostCode string) []response2.CCEmergencyStatus {
	var hosts []model.Hosts
	db := global.GWAF_LOCAL_DB.Model(model.Hosts{})
	if hostCode != "" {
		db = db.Where("code = ?", hostCode)
	} else {
		db = db.Where("emergency_mode = ?", 1)
	}
	db.Find(&hosts)

	now := time.Now().Unix()
	out := make([]response2.CCEmergencyStatus, 0, len(hosts))
	for i := range hosts {
		h := hosts[i]
		out = append(out, response2.CCEmergencyStatus{
			HostCode:    h.Code,
			HostName:    h.DisplayName(),
			GlobalHost:  h.GLOBAL_HOST,
			Enable:      h.EmergencyMode,
			Until:       h.EmergencyUntil,
			Active:      h.IsEmergencyActive(now),
			GuardStatus: h.GUARD_STATUS,
		})
	}
	return out
}
