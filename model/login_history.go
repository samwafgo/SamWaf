package model

import (
	"SamWaf/model/baseorm"
)

/*
*
管理端登录历史

放在日志库(GWAF_LOCAL_LOG_DB)而不是核心库：这是只增不改的审计流水，
和 AccountLog / WafSysLog 同性质，核心库只留配置类数据。

注意：日志库受数据保留策略清理，所以「上次登录是哪个IP」的权威值另存在
core 库的 account 表(LastLoginIp/LastLoginArea/LastLoginTime)上，
清历史日志不会导致下次登录被误判成「首次登录」。
*/
type LoginHistory struct {
	baseorm.BaseOrm
	LoginAccount string `gorm:"size:100;index" json:"login_account"` // 登录账号
	LoginIp      string `gorm:"size:64" json:"login_ip"`             // 本次登录IP
	LoginArea    string `gorm:"size:255" json:"login_area"`          // 本次IP归属地
	LoginType    string `gorm:"size:50" json:"login_type"`           // 登录端 web/mobile
	UserAgent    string `gorm:"size:500" json:"user_agent"`          // 客户端UA
	IsChanged    int    `json:"is_changed"`                          // 与上次登录相比IP或归属地是否变化 1变化 0未变化
	IsFirst      int    `json:"is_first"`                            // 是否该账号的首次登录记录 1是 0否
	PrevIp       string `gorm:"size:64" json:"prev_ip"`              // 变化时记录上次的IP，便于审计直接对比
	PrevArea     string `gorm:"size:255" json:"prev_area"`           // 变化时记录上次的归属地
}
