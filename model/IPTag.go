package model

import "SamWaf/model/baseorm"

/*
*
IP Tag 信息
*/
type IPTag struct {
	baseorm.BaseOrm
	IP      string `json:"ip"` //ip
	IPTag   string `json:"ip_tag"`
	Cnt     int64  `json:"cnt"`     //触发次数
	Remarks string `json:"remarks"` //备注
}
type AttackIPTag struct {
	TenantID   string `json:"tenant_id"`
	UserCode   string `json:"user_code"`
	IP         string `json:"ip"`
	PassNum    int64  `json:"pass_num"`
	DenyNum    int64  `json:"deny_num"`
	FirstTime  string `json:"first_time"`
	LatestTime string `json:"latest_time"`
	IpTotalTag string `json:"ip_total_tag"`
}

type AllIPTag struct {
	Label string `json:"label"`
	Value string `json:"value"`
}
