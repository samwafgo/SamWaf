package request

import "SamWaf/model/common/request"

// WafIPWatchlistAddReq 加入/续期观察名单
type WafIPWatchlistAddReq struct {
	IP     string `json:"ip" form:"ip" binding:"required"`
	Days   int    `json:"days" form:"days"`     // 观察天数，默认 7，上限 30
	Reason string `json:"reason" form:"reason"` // 加入原因（如触发规则名）
}

// WafIPWatchlistDelReq 移出观察名单
type WafIPWatchlistDelReq struct {
	IP string `json:"ip" form:"ip" binding:"required"`
}

// WafIPWatchlistSearch 名单分页查询
type WafIPWatchlistSearch struct {
	IP string `json:"ip" form:"ip"`
	request.PageInfo
}
