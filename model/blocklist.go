package model

import (
	"SamWaf/model/baseorm"
)

type IPBlockList struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64" json:"host_code"` //网站唯一码（主要键）
	Ip       string `gorm:"size:64" json:"ip"`        //限制ip
	Remarks  string `gorm:"size:500" json:"remarks"`  //备注
}

type URLBlockList struct {
	baseorm.BaseOrm
	HostCode    string `gorm:"size:64" json:"host_code"`                        //网站唯一码（主要键）
	CompareType string `gorm:"size:50" json:"compare_type" form:"compare_type"` //对比方式
	Url         string `gorm:"type:text" json:"url"`                            //限制请求地址
	Remarks     string `gorm:"size:500" json:"remarks"`                         //备注
}
