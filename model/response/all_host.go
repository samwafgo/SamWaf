package response

import "SamWaf/customtype"

type AllHostRep struct {
	Code     string `json:"value"`    //唯一码
	Host     string `json:"label"`    //域名
	PreHost  string `json:"pre_host"` //纯域名和端口
	Nickname string `json:"nickname"` //网站昵称（纯昵称，可能为空）
	// GlobalHost 是否"全局网站"（1是）。它不是真实站点，只承载全局规则，
	// 前端做"按站点选一个来配置/诊断"这类下拉时要把它过滤掉。
	GlobalHost int `json:"global_host"`
	// GroupCode 所属分组短码，空=未分组。供前端「先选分组再选站点」的下拉做本地筛选。
	GroupCode string `json:"group_code"`
}

type AllShareDbRep struct {
	StartTime customtype.JsonTime `json:"start_time"` //开始时间
	EndTime   customtype.JsonTime `json:"end_time"`   //结束时间
	FileName  string              `json:"file_name"`  //文件名
	Cnt       int64               `json:"cnt"`        //当前数量
	IsCurrent bool                `json:"is_current"` //是否为当前(实时)分片：前端据此设默认选中项
	PeriodKey string              `json:"period_key"` //周期键（月，如 202609）；按体积切出来的旧分片为空，前端回落显示起止日期
	Tiers     []string            `json:"tiers"`      //该分区现存哪些层（仅服务型数据库给；按层过期后可能只剩安全事件与报文）
	Missing   bool                `json:"missing"`    //登记还在但存储已不在（SQLite 文件被删 / 分区表都不存在）
}

// AllDomainRep 域名信息
type AllDomainRep struct {
	Code string `json:"value"` //唯一码
	Host string `json:"label"` //域名
}
