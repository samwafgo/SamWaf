package baseorm

import "SamWaf/customtype"

/*
*
base orm
*/
type BaseOrm struct {
	Id          string              `gorm:"primary_key" json:"id"` //
	USER_CODE   string              `json:"user_code"`             // 用户码（主要键）
	Tenant_ID   string              `json:"tenant_id"`             //租户ID
	CREATE_TIME customtype.JsonTime `json:"create_time"`           //创建时间
	UPDATE_TIME customtype.JsonTime `json:"update_time"`           //更新时间
}
