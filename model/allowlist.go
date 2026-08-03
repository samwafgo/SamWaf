package model

import (
	"SamWaf/model/baseorm"
)

type IPAllowList struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64" json:"host_code"` //网站唯一码（主要键）
	Ip       string `gorm:"size:128" json:"ip"`       //白名单ip：单IP / CIDR / 通配符(10.10.*.*) / 区间(起-止)；IpType=group 时为空
	Remarks  string `gorm:"size:500" json:"remarks"`  //备注
	// IpType 条目类型：空/ip 表示 Ip 字段生效，group 表示引用 GroupCode 指向的 IP 组。
	// 存量行为空串，等同于 ip，判定处一律只判 == IPEntryTypeGroup。
	IpType    string `gorm:"size:20" json:"ip_type"`
	GroupCode string `gorm:"size:64" json:"group_code"` //IpType=group 时指向 ip_group.group_code
}
type URLAllowList struct {
	baseorm.BaseOrm
	HostCode    string `gorm:"size:64" json:"host_code"`    //网站唯一码（主要键）
	CompareType string `gorm:"size:50" json:"compare_type"` //判断类型，包含、开始、结束、完全匹配
	Url         string `gorm:"type:text" json:"url"`        //请求地址
	Remarks     string `gorm:"size:500" json:"remarks"`     //备注
}
