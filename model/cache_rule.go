package model

import "SamWaf/model/baseorm"

// 缓存规则
type CacheRule struct {
	baseorm.BaseOrm
	HostCode      string `json:"host_code" gorm:"column:host_code"`           // 主机代码
	RuleName      string `json:"rule_name" gorm:"column:rule_name"`           // 规则名称
	RuleType      int    `json:"rule_type" gorm:"column:rule_type"`           // 规则类型：1-后缀匹配 ，2-指定目录，3-指定文件
	RuleContent   string `json:"rule_content" gorm:"column:rule_content"`     // 规则内容
	ParamType     int    `json:"param_type" gorm:"column:param_type"`         // 参数处理：1-忽略参数，2-完整参数
	CacheTime     int    `json:"cache_time" gorm:"column:cache_time"`         // 缓存时间(秒)：0-不缓存
	Priority      int    `json:"priority" gorm:"column:priority"`             // 优先级：数字越大优先级越高
	RequestMethod string `json:"request_method" gorm:"column:request_method"` // 请求方式：GET;HEAD;POST等，多个用分号分隔
	Remarks       string `json:"remarks" gorm:"column:remarks"`               // 备注
}
