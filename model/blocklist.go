package model

import (
	"SamWaf/model/baseorm"
)

type IPBlockList struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //限制ip
	Remarks  string `json:"remarks"`   //备注
}

type URLBlockList struct {
	baseorm.BaseOrm
	HostCode    string `json:"host_code"`                        //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type"` //对比方式
	Url         string `json:"url"`                              //限制请求地址
	Remarks     string `json:"remarks"`                          //备注
}
