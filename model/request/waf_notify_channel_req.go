package request

// 添加通知渠道请求
type WafNotifyChannelAddReq struct {
	Name        string `json:"name" binding:"required"`
	Type        string `json:"type" binding:"required"`
	WebhookURL  string `json:"webhook_url"`
	Secret      string `json:"secret"`
	AccessToken string `json:"access_token"`
	ConfigJSON  string `json:"config_json"`
	Status      int    `json:"status"`
	Remarks     string `json:"remarks"`
}

// 编辑通知渠道请求
type WafNotifyChannelEditReq struct {
	Id          string `json:"id" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Type        string `json:"type" binding:"required"`
	WebhookURL  string `json:"webhook_url"`
	Secret      string `json:"secret"`
	AccessToken string `json:"access_token"`
	ConfigJSON  string `json:"config_json"`
	Status      int    `json:"status"`
	Remarks     string `json:"remarks"`
}

// 查询通知渠道详情请求
type WafNotifyChannelDetailReq struct {
	Id string `form:"id" binding:"required"`
}

// 搜索通知渠道请求
type WafNotifyChannelSearchReq struct {
	PageIndex int    `json:"pageIndex"`
	PageSize  int    `json:"pageSize"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Status    int    `json:"status"`
}

// 删除通知渠道请求
type WafNotifyChannelDelReq struct {
	Id string `form:"id" binding:"required"`
}

// 测试通知渠道请求
type WafNotifyChannelTestReq struct {
	Id string `json:"id" binding:"required"`
}
