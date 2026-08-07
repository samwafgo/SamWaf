package request

// WafHostGuardEventSearchReq 登录失败事件查询
type WafHostGuardEventSearchReq struct {
	Source    string `json:"source" form:"source"`         // ssh / rdp
	IP        string `json:"ip" form:"ip"`                 // 模糊匹配
	UserName  string `json:"user_name" form:"user_name"`   // 模糊匹配
	FailKind  string `json:"fail_kind" form:"fail_kind"`   //
	Action    string `json:"action" form:"action"`         // observe / counted / skipped / banned
	StartTime int64  `json:"start_time" form:"start_time"` // unix秒，0=不限
	EndTime   int64  `json:"end_time" form:"end_time"`
	PageIndex int    `json:"pageIndex" form:"pageIndex"`
	PageSize  int    `json:"pageSize" form:"pageSize"`
}

// WafHostGuardBanSearchReq 封禁记录查询
type WafHostGuardBanSearchReq struct {
	IP        string `json:"ip" form:"ip"`
	Source    string `json:"source" form:"source"`
	Status    string `json:"status" form:"status"` // 留空默认只看生效中的
	PageIndex int    `json:"pageIndex" form:"pageIndex"`
	PageSize  int    `json:"pageSize" form:"pageSize"`
}

// WafHostGuardOffenderSearchReq 攻击者档案查询
type WafHostGuardOffenderSearchReq struct {
	IP        string `json:"ip" form:"ip"`
	Source    string `json:"source" form:"source"`
	PageIndex int    `json:"pageIndex" form:"pageIndex"`
	PageSize  int    `json:"pageSize" form:"pageSize"`
}

// WafHostGuardBanIdReq 按ID操作封禁记录（解封 / 提升为永久）
type WafHostGuardBanIdReq struct {
	Id string `json:"id" form:"id"`
}

// WafHostGuardManualBanReq 手工封禁一个IP
type WafHostGuardManualBanReq struct {
	IP         string `json:"ip" form:"ip"`
	Source     string `json:"source" form:"source"`
	BanMinutes int64  `json:"ban_minutes" form:"ban_minutes"` // 0=永久
	Reason     string `json:"reason" form:"reason"`
}

// WafHostGuardOffenderIdReq 按ID操作攻击者档案（重置阶梯 / 删除）
type WafHostGuardOffenderIdReq struct {
	Id string `json:"id" form:"id"`
}

// WafHostGuardWhitelistTestReq 白名单自测：输入IP看会不会被豁免
type WafHostGuardWhitelistTestReq struct {
	IP string `json:"ip" form:"ip"`
}

// WafHostGuardLadderEditReq 阶梯编辑（整表替换，前端一次提交全部行）
type WafHostGuardLadderEditReq struct {
	Ladders []WafHostGuardLadderItem `json:"ladders" form:"ladders"`
}

// WafHostGuardLadderItem 单级阶梯
type WafHostGuardLadderItem struct {
	Level      int    `json:"level" form:"level"`
	BanMinutes int64  `json:"ban_minutes" form:"ban_minutes"` // 0=永久
	Enable     int    `json:"enable" form:"enable"`
	Remarks    string `json:"remarks" form:"remarks"`
}

// WafHostGuardWhitelistAddReq 把某IP加入白名单（从事件/封禁列表一键操作）
type WafHostGuardWhitelistAddReq struct {
	IP string `json:"ip" form:"ip"`
}
