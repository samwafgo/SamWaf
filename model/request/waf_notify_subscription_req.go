package request

// 添加通知订阅请求
type WafNotifySubscriptionAddReq struct {
	ChannelId   string `json:"channel_id" binding:"required"`
	MessageType string `json:"message_type" binding:"required"`
	Status      int    `json:"status"`
	FilterJSON  string `json:"filter_json"`
	Remarks     string `json:"remarks"`
}

// 编辑通知订阅请求
type WafNotifySubscriptionEditReq struct {
	Id          string `json:"id" binding:"required"`
	ChannelId   string `json:"channel_id" binding:"required"`
	MessageType string `json:"message_type" binding:"required"`
	Status      int    `json:"status"`
	FilterJSON  string `json:"filter_json"`
	Remarks     string `json:"remarks"`
}

// 查询通知订阅详情请求
type WafNotifySubscriptionDetailReq struct {
	Id string `form:"id" binding:"required"`
}

// 搜索通知订阅请求
type WafNotifySubscriptionSearchReq struct {
	PageIndex   int    `json:"pageIndex"`
	PageSize    int    `json:"pageSize"`
	ChannelId   string `json:"channel_id"`
	MessageType string `json:"message_type"`
	Status      int    `json:"status"`
}

// 删除通知订阅请求
type WafNotifySubscriptionDelReq struct {
	Id string `form:"id" binding:"required"`
}
