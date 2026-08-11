package request

import "SamWaf/model/common/request"

// WafThreatIPExcludeAddReq 新增威胁情报误报排除条目
type WafThreatIPExcludeAddReq struct {
	Entry   string `json:"entry" binding:"required"` // 单 IP 或 CIDR，如 1.2.3.4 / 1.2.3.0/24
	Remarks string `json:"remarks"`                  // 备注：为什么认为是误报
}

// WafThreatIPExcludeEditReq 修改排除条目(条目原文不可改，要改就删了重加，保证审计可追溯)
type WafThreatIPExcludeEditReq struct {
	Id      string `json:"id" binding:"required"`
	Remarks string `json:"remarks"`
	Enable  int    `json:"enable"` // 1 生效 0 停用
}

// WafThreatIPExcludeDelReq 删除排除条目
type WafThreatIPExcludeDelReq struct {
	Id string `json:"id" form:"id" binding:"required"`
}

// WafThreatIPExcludeSearchReq 排除名单分页查询
type WafThreatIPExcludeSearchReq struct {
	Entry  string `json:"entry"`  // 条目子串过滤
	Source string `json:"source"` // manual | auto | ""(全部)
	request.PageInfo
}

// WafThreatIPExcludePreviewReq 试算一条排除条目的影响(不落库)
type WafThreatIPExcludePreviewReq struct {
	Entry string `json:"entry" binding:"required"`
}

// WafThreatIPExcludeAuditSearchReq 排除操作审计流水查询
type WafThreatIPExcludeAuditSearchReq struct {
	Entry  string `json:"entry"`
	Action string `json:"action"` // add | del | enable | disable | ""(全部)
	request.PageInfo
}
