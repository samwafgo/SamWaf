package model

import "time"

/*
*
延迟信息
*/
type DelayMsg struct {
	Id           string    `gorm:"primary_key" json:"id"`
	UserCode     string    `json:"user_code"`     //用户码（主要键）
	TenantId     string    `json:"tenant_id"`     //租户ID（主要键）
	DelayType    string    `json:"delay_type"`    //操作类型
	DelayTile    string    `json:"delay_title"`   //操作标题
	DelayContent string    `json:"delay_content"` //操作内容
	CreateTime   time.Time `json:"create_time"`   //创建时间
}
