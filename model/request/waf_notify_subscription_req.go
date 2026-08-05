package request

// 添加通知订阅请求
type WafNotifySubscriptionAddReq struct {
	ChannelId   string `json:"channel_id" binding:"required"`
	MessageType string `json:"message_type" binding:"required"`
	Recipients  string `json:"recipients"`
	Status      int    `json:"status"`
	FilterJSON  string `json:"filter_json"`
	Remarks     string `json:"remarks"`
}

// 编辑通知订阅请求
type WafNotifySubscriptionEditReq struct {
	Id          string `json:"id" binding:"required"`
	ChannelId   string `json:"channel_id" binding:"required"`
	MessageType string `json:"message_type" binding:"required"`
	Recipients  string `json:"recipients"`
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

// ========== 精细化配置（issue #822） ==========
//
// 频控/模板/过滤这些"每个格子单独配"的字段刻意不放进 Edit 请求：
// 前端的开关切换、收件人编辑都会整包提交 Edit，一旦漏传就会把用户配好的模板清空。
// 所以它们只能通过下面这个专用接口写入。

// WafNotifyThrottleReq 频控细项
type WafNotifyThrottleReq struct {
	AggregateWindowSec       int      `json:"aggregate_window_sec"`        // 聚合窗口（秒），0=继承全局
	AggregateMaxDetail       int      `json:"aggregate_max_detail"`        // 合并通知最多展示条数，0=继承
	CooldownStepsSec         []int    `json:"cooldown_steps_sec"`          // 递增冷却梯度（秒），空=继承
	CooldownResetSec         int      `json:"cooldown_reset_sec"`          // 冷却级别重置时间（秒），0=继承
	MaxPerHour               int      `json:"max_per_hour"`                // 每小时上限，0=不限
	DedupKeys                []string `json:"dedup_keys"`                  // 去重维度，空=继承
	QuietHours               string   `json:"quiet_hours"`                 // 免打扰时段 HH:MM-HH:MM，空=不启用
	QuietHoursBypassSeverity string   `json:"quiet_hours_bypass_severity"` // 该级别及以上穿透免打扰
}

// WafNotifyFilterReq 过滤条件
type WafNotifyFilterReq struct {
	Domains     []string `json:"domains"`
	ExcludeIps  []string `json:"exclude_ips"`
	Keywords    []string `json:"keywords"`
	MinSeverity string   `json:"min_severity"`
}

// WafNotifySubscriptionConfigReq 保存单个订阅的精细化配置
type WafNotifySubscriptionConfigReq struct {
	Id              string               `json:"id" binding:"required"`
	ThrottleMode    string               `json:"throttle_mode"`
	Throttle        WafNotifyThrottleReq `json:"throttle"`
	Filter          WafNotifyFilterReq   `json:"filter"`
	TitleTemplate   string               `json:"title_template"`
	ContentTemplate string               `json:"content_template"`
}

// WafNotifySubscriptionBatchConfigReq 批量套用配置
//
// ChannelType 与 MessageType 至少填一个：前者=把配置套到某类渠道的所有消息类型，
// 后者=套到某个消息类型的所有渠道（"套用到本类型所有渠道"按钮）。
type WafNotifySubscriptionBatchConfigReq struct {
	ChannelType     string               `json:"channel_type"`
	MessageType     string               `json:"message_type"`
	ThrottleMode    string               `json:"throttle_mode"`
	Throttle        WafNotifyThrottleReq `json:"throttle"`
	Filter          WafNotifyFilterReq   `json:"filter"`
	TitleTemplate   string               `json:"title_template"`
	ContentTemplate string               `json:"content_template"`
	ApplyThrottle   bool                 `json:"apply_throttle"` // 是否套用频控
	ApplyTemplate   bool                 `json:"apply_template"` // 是否套用模板
	ApplyFilter     bool                 `json:"apply_filter"`   // 是否套用过滤
}

// WafNotifySubscriptionPreviewReq 模板预览（不发送）
type WafNotifySubscriptionPreviewReq struct {
	MessageType     string `json:"message_type" binding:"required"`
	ChannelType     string `json:"channel_type"`   // 影响变量转义方式（邮件走HTML转义）
	TitleTemplate   string `json:"title_template"` // 传当前编辑中的模板，未保存也能预览
	ContentTemplate string `json:"content_template"`
}

// WafNotifySubscriptionTestReq 订阅级测试发送（真实发送，绕过频控与过滤）
type WafNotifySubscriptionTestReq struct {
	Id              string `json:"id" binding:"required"`
	TitleTemplate   string `json:"title_template"`
	ContentTemplate string `json:"content_template"`
}

// WafNotifySubscriptionDryRunReq 干跑：只演算不发送，返回会不会被拦、被什么拦
type WafNotifySubscriptionDryRunReq struct {
	Id string `json:"id" binding:"required"`
}

// WafNotifySubscriptionTemplateVarsReq 取某消息类型的可用变量
type WafNotifySubscriptionTemplateVarsReq struct {
	MessageType string `form:"message_type" binding:"required"`
}

// WafNotifyGlobalThrottleUpdateReq 全局默认频控配置
type WafNotifyGlobalThrottleUpdateReq struct {
	Mode      string               `json:"mode"`
	Throttle  WafNotifyThrottleReq `json:"throttle"`
	DebugMode bool                 `json:"debug_mode"`
}
