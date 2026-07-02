package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
	"fmt"
	"time"
)

type SslExpire struct {
	baseorm.BaseOrm
	Domain     string              `gorm:"size:255" json:"domain"`    // 证书适用的域名
	Port       int                 `json:"port"`                      // 端口
	ValidTo    customtype.JsonTime `json:"valid_to"`                  // 证书有效期结束时间(未检测出时为NULL，避免MySQL严格模式拒绝0000-00-00)
	VisitLog   string              `gorm:"size:500" json:"visit_log"` //访问日志
	LastDetect customtype.JsonTime `json:"last_detect"`               // 最后检测时间
	Status     string              `gorm:"size:50" json:"status"`     //状态
}

// ExpirationMessage 获取到期提示信息
func (s *SslExpire) ExpirationMessage() string {
	now := time.Now()
	validTo := time.Time(s.ValidTo)
	if validTo.IsZero() {
		return ""
	}
	daysLeft := validTo.Sub(now).Hours() / 24

	if daysLeft > 0 {
		return fmt.Sprintf("还有 %.0f 天到期", daysLeft)
	} else {
		return fmt.Sprintf("已过期 %.0f 天", -daysLeft)
	}
}

// ExpirationDay 剩余到期天数
func (s *SslExpire) ExpirationDay() int {
	now := time.Now()
	daysLeft := time.Time(s.ValidTo).Sub(now).Hours() / 24

	if daysLeft > 0 {
		//还有多少天过期
		return int(daysLeft)
	} else {
		//已过期
		return int(-daysLeft)
	}
}
