package request

import "SamWaf/model/common/request"

// WafThreatIPChannelAddReq 新增威胁情报订阅渠道请求
type WafThreatIPChannelAddReq struct {
	Code         string `json:"code" binding:"required"` // 渠道短码(小写字母/数字/下划线，≤13)
	Name         string `json:"name" binding:"required"` // 显示名
	URL          string `json:"url" binding:"required"`  // 拉取地址
	ParserType   string `json:"parser_type"`             // plain_mixed | ipsum | cidr_only
	Threshold    int    `json:"threshold"`               // ipsum 命中数阈值
	LandTarget   string `json:"land_target"`             // waf | system | both
	Enable       int    `json:"enable"`                  // 0/1
	IntervalHour int    `json:"interval_hour"`           // 拉取周期(小时)
	Remarks      string `json:"remarks"`                 // 备注
}

// WafThreatIPChannelEditReq 修改威胁情报订阅渠道请求(不允许改 Code)
type WafThreatIPChannelEditReq struct {
	Id           string `json:"id" binding:"required"`
	Name         string `json:"name" binding:"required"`
	URL          string `json:"url" binding:"required"`
	ParserType   string `json:"parser_type"`
	Threshold    int    `json:"threshold"`
	LandTarget   string `json:"land_target"`
	Enable       int    `json:"enable"`
	IntervalHour int    `json:"interval_hour"`
	Remarks      string `json:"remarks"`
}

// WafThreatIPChannelDelReq 删除请求
type WafThreatIPChannelDelReq struct {
	Id string `json:"id" form:"id" binding:"required"`
}

// WafThreatIPChannelDetailReq 详情请求
type WafThreatIPChannelDetailReq struct {
	Id string `json:"id" form:"id" binding:"required"`
}

// WafThreatIPChannelSyncReq 手动同步请求
type WafThreatIPChannelSyncReq struct {
	Id string `json:"id" binding:"required"`
}

// WafThreatIPChannelSearchReq 分页搜索请求
type WafThreatIPChannelSearchReq struct {
	Name string `json:"name"`
	request.PageInfo
}

// WafThreatIPLandedSummaryReq 订阅落地汇总请求(方案三"订阅来源"Tab)
// Land: system | waf | ""(全部)
type WafThreatIPLandedSummaryReq struct {
	Land string `json:"land" form:"land"`
}

// WafThreatIPLandedIPReq 某渠道落地 IP 分页浏览请求(只读)
type WafThreatIPLandedIPReq struct {
	Code    string `json:"code" binding:"required"` // 渠道短码
	Keyword string `json:"keyword"`                 // IP 子串过滤(可空)
	// OnlyExcluded=1 时只列被误报排除名单剔掉的条目，供用户核对排除的实际效果
	OnlyExcluded int `json:"only_excluded"`
	request.PageInfo
}
