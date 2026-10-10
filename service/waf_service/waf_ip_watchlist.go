package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"net"
	"strings"
	"time"

	"gorm.io/gorm"
)

type WafIPWatchlistService struct{}

var WafIPWatchlistServiceApp = new(WafIPWatchlistService)

const (
	watchDefaultDays  = 7
	watchMaxDays      = 30
	watchReasonMaxLen = 255
)

// AddApi 加入观察名单；已存在则续期（到期时间取更晚者）并更新原因。
func (receiver *WafIPWatchlistService) AddApi(req request.WafIPWatchlistAddReq) error {
	ip := strings.TrimSpace(req.IP)
	if net.ParseIP(ip) == nil {
		return errors.New("IP 格式不正确")
	}
	days := req.Days
	if days <= 0 {
		days = watchDefaultDays
	}
	if days > watchMaxDays {
		days = watchMaxDays
	}
	reason := req.Reason
	if len(reason) > watchReasonMaxLen {
		reason = reason[:watchReasonMaxLen]
	}
	expireAt := time.Now().AddDate(0, 0, days).Unix()

	var existing model.IPWatchlist
	res := global.GWAF_LOCAL_DB.Where("ip = ? and tenant_id = ? and user_code = ?",
		ip, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).First(&existing)
	if res.Error == nil {
		fields := map[string]interface{}{
			"reason":      reason,
			"update_time": customtype.JsonTime(time.Now()),
		}
		if existing.ExpireAt < expireAt {
			fields["expire_at"] = expireAt
		}
		err := global.GWAF_LOCAL_DB.Model(&model.IPWatchlist{}).Where("id = ?", existing.Id).Updates(fields).Error
		global.GWAF_IP_WATCH.Reload()
		return err
	}
	bean := &model.IPWatchlist{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		IP:       ip,
		ExpireAt: expireAt,
		Reason:   reason,
	}
	err := global.GWAF_LOCAL_DB.Create(bean).Error
	global.GWAF_IP_WATCH.Reload()
	return err
}

// DelApi 移出观察名单
func (receiver *WafIPWatchlistService) DelApi(ip string) error {
	err := global.GWAF_LOCAL_DB.Where("ip = ? and tenant_id = ? and user_code = ?",
		strings.TrimSpace(ip), global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Delete(&model.IPWatchlist{}).Error
	global.GWAF_IP_WATCH.Reload()
	return err
}

// ListApi 名单分页（顺带清掉已到期行）。
func (receiver *WafIPWatchlistService) ListApi(req request.WafIPWatchlistSearch) ([]model.IPWatchlist, int64, error) {
	var list []model.IPWatchlist
	var total int64
	now := time.Now().Unix()
	global.GWAF_LOCAL_DB.Where("expire_at <= ?", now).Delete(&model.IPWatchlist{})
	build := func() *gorm.DB {
		q := global.GWAF_LOCAL_DB.Model(&model.IPWatchlist{}).
			Where("tenant_id = ? and user_code = ? and expire_at > ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, now)
		if strings.TrimSpace(req.IP) != "" {
			q = q.Where("ip like ?", "%"+strings.TrimSpace(req.IP)+"%")
		}
		return q
	}
	build().Count(&total)
	err := build().Order("expire_at desc").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list).Error
	return list, total, err
}
