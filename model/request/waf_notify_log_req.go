package request

// 搜索通知日志请求
type WafNotifyLogSearchReq struct {
	PageIndex   int    `json:"pageIndex"`
	PageSize    int    `json:"pageSize"`
	ChannelId   string `json:"channel_id"`
	MessageType string `json:"message_type"`
	Status      int    `json:"status"`
	StartTime   string `json:"start_time"`
	EndTime     string `json:"end_time"`
}

// 删除通知日志请求
type WafNotifyLogDelReq struct {
	Id string `form:"id" binding:"required"`
}

// 查询通知日志详情请求
type WafNotifyLogDetailReq struct {
	Id string `form:"id" binding:"required"`
}
