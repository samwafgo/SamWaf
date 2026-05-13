package model

import (
	"SamWaf/model/baseorm"
)

/*
*
开放平台调用日志
*/
type OPlatformLog struct {
	baseorm.BaseOrm
	ApiKeyId      string `gorm:"size:64" json:"api_key_id"`      //关联的Key ID
	KeyName       string `gorm:"size:255" json:"key_name"`       //Key名称（冗余，方便查询）
	RequestPath   string `gorm:"size:500" json:"request_path"`   //请求路径
	RequestMethod string `gorm:"size:20" json:"request_method"`  //请求方法
	RequestBody   string `gorm:"type:text" json:"request_body"`  //请求体（非文件类型记录）
	ResponseBody  string `gorm:"type:text" json:"response_body"` //响应体
	ClientIP      string `gorm:"size:64" json:"client_ip"`       //调用者IP
	StatusCode    int    `json:"status_code"`                    //响应状态码
	Duration      int64  `json:"duration"`                       //耗时(ms)
	TimeStr       string `gorm:"size:100" json:"time_str"`       //调用时间字符串
}
