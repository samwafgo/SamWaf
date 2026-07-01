package model

import "SamWaf/model/baseorm"

// TamperRule 网页防篡改规则（按站点、按精确 URL 存基线，反代响应基线比对）
type TamperRule struct {
	baseorm.BaseOrm
	HostCode        string `json:"host_code" gorm:"column:host_code;size:64"`               // 主机代码
	Url             string `json:"url" gorm:"column:url;size:1024"`                         // 精确URL路径(不含query)，如 /index.html、/app.js
	RuleName        string `json:"rule_name" gorm:"column:rule_name;size:255"`              // 规则名称
	IsEnable        int    `json:"is_enable" gorm:"column:is_enable"`                       // 1启用 0停用
	IgnoreQuery     int    `json:"ignore_query" gorm:"column:ignore_query"`                 // 1忽略query照常比对(静态资源带?v=时间戳默认) / 0带query则跳过放行
	BaselineHash    string `json:"baseline_hash" gorm:"column:baseline_hash;size:64"`       // sha256(hex) of 解压后正文
	BaselineContent []byte `json:"baseline_content" gorm:"column:baseline_content"`         // 解压后正文字节(≤上限)；DB存储→多节点可同步
	ContentType     string `json:"content_type" gorm:"column:content_type;size:255"`        // 学习时记录的 Content-Type
	StatusCode      int    `json:"status_code" gorm:"column:status_code"`                   // 学习时记录的状态码
	ContentSize     int    `json:"content_size" gorm:"column:content_size"`                 // 基线正文字节数
	BaselineStatus  int    `json:"baseline_status" gorm:"column:baseline_status"`           // 0未学习 1已学习 2学习失败(超限)
	BaselineMsg     string `json:"baseline_msg" gorm:"column:baseline_msg;size:500"`        // 学习失败原因
	LastLearnTime   string `json:"last_learn_time" gorm:"column:last_learn_time;size:32"`   // 上次学习时间
	TamperCount     int    `json:"tamper_count" gorm:"column:tamper_count"`                 // 累计命中篡改次数
	LastTamperTime  string `json:"last_tamper_time" gorm:"column:last_tamper_time;size:32"` // 上次命中篡改时间
	Remarks         string `json:"remarks" gorm:"column:remarks;size:500"`                  // 备注
}
