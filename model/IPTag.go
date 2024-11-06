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
