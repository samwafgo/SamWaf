package model

import (
	"SamWaf/model/baseorm"
)

/*
隐私处理
*/
type LDPUrl struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	//CompareCol     string    `json:"CompareCol"`        //判断字段
	CompareType string `json:"compare_type"` //判断类型，包含、开始、结束、完全匹配
	Url         string `json:"url"`          //请求地址
	Remarks     string `json:"remarks"`      //备注
}
