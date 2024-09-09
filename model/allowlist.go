package model

import (
	"SamWaf/model/baseorm"
)

type IPAllowList struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //白名单ip
	Remarks  string `json:"remarks"`   //备注
}
type URLAllowList struct {
	baseorm.BaseOrm
	HostCode    string `json:"host_code"`    //网站唯一码（主要键）
	CompareType string `json:"compare_type"` //判断类型，包含、开始、结束、完全匹配
	Url         string `json:"url"`          //请求地址
	Remarks     string `json:"remarks"`      //备注
}
