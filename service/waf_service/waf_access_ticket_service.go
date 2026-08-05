package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafenginecore/accessgate"
	"errors"
	"strings"
	"time"
)

type WafAccessTicketService struct{}

var WafAccessTicketServiceApp = new(WafAccessTicketService)

// IssueTicket 签发一张跨域一次性票据，返回要放进回跳 URL 的明文。
//
// 票据只在 targetHost 上可兑换、只能兑换一次、只活 TicketTTL（默认 60 秒）。
// returnTo 必须是调用方已经过 validateReturnTo 校验的地址——本函数不再校验，
// 因为它拿不到路由表（service 层无法 import wafenginecore 根包）。
func (receiver *WafAccessTicketService) IssueTicket(sess model.AccessSession, targetHost, returnTo,
	clientIP, fingerprint string, cfg *accessgate.Config) (string, error) {

	plain, err := genAccessSecret()
	if err != nil {
		return "", err
	}
	now := time.Now()
	bean := model.AccessTicket{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		},
		TicketCode:  HashAccessCode(plain),
		SessionCode: sess.SessionCode,
		AccountCode: sess.AccountCode,
		AccountName: sess.AccountName,
		TargetHost:  strings.ToLower(targetHost),
		ReturnTo:    returnTo,
		ClientIP:    clientIP,
		Fingerprint: fingerprint,
		Used:        0,
		ExpireTime:  customtype.JsonTime(now.Add(cfg.TicketTTL)),
	}
	if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
		return "", err
	}
	return plain, nil
}

// ConsumeTicket 原子地消费一张票据。成功返回票据内容，失败返回错误。
//
// 「恰好用一次」靠的是一条带条件的 UPDATE，判 RowsAffected：
//
//	UPDATE access_ticket SET used=1 WHERE ticket_code=? AND used=0 AND expire_time>?
//
// SQLite/MySQL/PG 都保证这条语句是原子的，所以哪怕两个请求同时拿着同一张票进来，
// 也只有一个能拿到 RowsAffected==1。这一点在优雅升级期间尤其重要——
// 那时新旧两个 Worker 进程同时在跑，任何进程内的锁都不管用。
//
// 为什么不能先 SELECT 再 UPDATE：那是典型的 TOCTOU，两个请求会双双通过 SELECT。
func (receiver *WafAccessTicketService) ConsumeTicket(plain, targetHost, clientIP, fingerprint string,
	cfg *accessgate.Config) (*model.AccessTicket, error) {

	if plain == "" {
		return nil, errors.New("票据为空")
	}
	code := HashAccessCode(plain)
	now := time.Now()

	r := global.GWAF_LOCAL_DB.Model(&model.AccessTicket{}).
		Where("ticket_code = ? and used = 0 and expire_time > ?", code, customtype.JsonTime(now)).
		Updates(map[string]interface{}{
			"used": 1, "used_time": customtype.JsonTime(now), "update_time": customtype.JsonTime(now),
		})
	if r.Error != nil {
		return nil, r.Error
	}
	if r.RowsAffected != 1 {
		// 走到这里只有三种可能：票据不存在（伪造）、已经用过（重放）、已过期。
		// 三种都当作攻击信号上报，调用方会记一条 ticket_replay 审计。
		return nil, errors.New("票据无效、已过期或已被使用")
	}

	var bean model.AccessTicket
	if err := global.GWAF_LOCAL_DB.Where("ticket_code = ?", code).First(&bean).Error; err != nil {
		return nil, errors.New("票据读取失败")
	}
	// 票据只能在签发时指定的那个域名上兑换。
	// 缺了这一条，攻击者可以把受害者在 a.com 换到的票据拿到 b.com 去兑换，
	// 从而在一个他本无权限的站点上拿到有效令牌。
	if !strings.EqualFold(bean.TargetHost, targetHost) {
		return nil, errors.New("票据与当前站点不匹配")
	}
	if cfg.BindIP && bean.ClientIP != "" && bean.ClientIP != clientIP {
		return nil, errors.New("票据与当前来源不匹配")
	}
	if cfg.BindFingerprint && bean.Fingerprint != "" && bean.Fingerprint != fingerprint {
		return nil, errors.New("票据与当前设备不匹配")
	}
	return &bean, nil
}

// LoadSessionByCode 按 session_code 取会话，供 callback 兑票后签发子令牌用。
func (receiver *WafAccessTicketService) LoadSessionByCode(sessionCode string) (*model.AccessSession, error) {
	var sess model.AccessSession
	if err := global.GWAF_LOCAL_DB.Where("session_code = ? and status = ?",
		sessionCode, model.AccessStatusValid).First(&sess).Error; err != nil {
		return nil, errors.New("会话已失效")
	}
	if time.Time(sess.ExpireTime).Before(time.Now()) {
		return nil, errors.New("会话已过期")
	}
	return &sess, nil
}
