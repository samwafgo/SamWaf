package model

import "time"

type WafSysLog struct {
	Id         string    `gorm:"primary_key" json:"id"`
	UserCode   string    `json:"user_code"`   //用户码（主要键）
	TenantId   string    `json:"tenant_id"`   //租户ID（主要键）
	OpType     string    `json:"op_type"`     //操作类型
	OpContent  string    `json:"op_content"`  //操作内容
	CreateTime time.Time `json:"create_time"` //创建时间
}
