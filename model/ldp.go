package model

import (
	"SamWaf/model/baseorm"
)

/*
隐私处理
*/
type LDPUrl struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64" json:"host_code"` //网站唯一码（主要键）
	//CompareCol     string    `json:"CompareCol"`        //判断字段
	CompareType string `gorm:"size:50" json:"compare_type"` //判断类型，包含、开始、结束、完全匹配
	Url         string `gorm:"type:text" json:"url"`        //请求地址
	Remarks     string `gorm:"size:500" json:"remarks"`     //备注
}
