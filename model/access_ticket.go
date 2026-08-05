package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

// AccessTicket 是跨域 SSO 的一次性票据。
//
// 为什么必须落库、不能像 rq 那样用无状态 HMAC 签名：
// rq 只需要「防篡改」，票据需要的是「恰好用一次」。后者是全局互斥语义，
// 只能靠数据库的条件更新实现：
//
//	UPDATE access_ticket SET used=1 WHERE ticket_code=? AND used=0 AND expire_time>?
//
// 判 RowsAffected==1 即可，SQLite/MySQL/PG 都保证这条语句是原子的，
// 优雅升级期间新旧 Worker 双进程并存也不会让同一张票被消费两次。
//
// TicketCode 同样存 sha256hex 而非明文，理由与 AccessSession.SessionCode 一致。
type AccessTicket struct {
	baseorm.BaseOrm
	TicketCode  string              `gorm:"size:64" json:"ticket_code"`  //sha256hex(票据明文)，唯一
	SessionCode string              `gorm:"size:64" json:"session_code"` //换票时所依据的中心会话
	AccountCode string              `gorm:"size:64" json:"account_code"`
	AccountName string              `gorm:"size:128" json:"account_name"`
	TargetHost  string              `gorm:"size:255" json:"target_host"` //只能在这个域名上兑换，callback 里比对 r.Host
	ReturnTo    string              `gorm:"type:text" json:"return_to"`  //兑换成功后 302 的目标，已通过 validateReturnTo
	ClientIP    string              `gorm:"size:64" json:"client_ip"`
	Fingerprint string              `gorm:"size:64" json:"fingerprint"`
	Used        int                 `json:"used"` //1已消费 0未消费
	UsedTime    customtype.JsonTime `json:"used_time"`
	ExpireTime  customtype.JsonTime `json:"expire_time"` //默认 60 秒，够一次 302 往返即可
}

func (AccessTicket) TableName() string {
	return "access_ticket"
}
