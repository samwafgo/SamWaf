package model

import "time"

/*
*
注册信息
*/
type RegistrationInfo struct {
	Version    string    `json:"version"`
	Username   string    `json:"username"`
	MemberType string    `json:"member_type"`
	MachineID  string    `json:"machine_id"`
	ExpiryDate time.Time `json:"expiry_date"`
}

/*
*
机器信息
*/
type MachineInfo struct {
	Version          string `json:"version"`
	MachineID        string `json:"machine_id"`
	ClientServerName string `json:"client_server_name"` // 客户端-自定义名称
	ClientTenantId   string `json:"client_tenant_id"`   // 客户端-租户ID
	ClientUserCode   string `json:"client_user_code"`   // 客户端-用户码
	OtherFeature     string `json:"other_feature"`      // 预留其他特征
}
