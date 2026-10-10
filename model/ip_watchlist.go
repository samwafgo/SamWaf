package model

import "SamWaf/model/baseorm"

// IPWatchlist 重点 IP 观察名单：名单内 IP 的请求全量留痕（窄行进 access_log、
// 报文进 event_payload kind=watch），到期自动失效。表在 core 库。
type IPWatchlist struct {
	baseorm.BaseOrm
	IP       string `gorm:"size:64;uniqueIndex:uni_watch_ip" json:"ip"`
	ExpireAt int64  `gorm:"index" json:"expire_at"`     // 到期时间（Unix 秒）
	Reason   string `gorm:"size:255" json:"reason"`     // 加入原因（如触发规则名）
}
