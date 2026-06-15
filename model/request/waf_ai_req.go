package request

// WafAIExportReq 训练数据导出入参
type WafAIExportReq struct {
	Days     int `json:"days"`      // 导出最近多少天的日志（<=0 表示不限）
	MaxCount int `json:"max_count"` // 最多导出多少条（<=0 表示用默认上限）
}

// WafAIDashboardReq AI检测看板入参
type WafAIDashboardReq struct {
	StartDay int    `json:"start_day"` // 起始日 YYYYMMDD（<=0 表示不限）
	EndDay   int    `json:"end_day"`   // 结束日 YYYYMMDD（<=0 表示不限）
	HostCode string `json:"host_code"` // 站点编码，空表示全部站点
}

// WafAILabelMarkReq 训练标签人工修正入参
type WafAILabelMarkReq struct {
	ReqUuid    string `json:"req_uuid" binding:"required"` // 关联请求日志
	HostCode   string `json:"host_code"`
	Mark       string `json:"mark" binding:"required"` // normal / attack / ignore
	AttackType string `json:"attack_type"`             // mark=attack 时的人工分类，空=自动判定
	Rule       string `json:"rule"`                    // 原始触发规则（快照）
	SrcIp      string `json:"src_ip"`
	Url        string `json:"url"`
}

// WafAILabelUnmarkReq 取消标记入参
type WafAILabelUnmarkReq struct {
	ReqUuid string `json:"req_uuid" binding:"required"`
}

// WafAILabelByUuidsReq 按 req_uuid 批量查询标记状态（用于日志列表回显）
type WafAILabelByUuidsReq struct {
	ReqUuids []string `json:"req_uuids"`
}

// WafAILabelListReq 标注工作台列表入参：在 AI 命中(ai_score>0)子集上分页 + 过滤
type WafAILabelListReq struct {
	HostCode   string  `json:"host_code"`   // 站点编码，空=全部
	StartDay   int     `json:"start_day"`   // 起始日 YYYYMMDD（<=0 不限）
	EndDay     int     `json:"end_day"`     // 结束日 YYYYMMDD（<=0 不限）
	MarkStatus string  `json:"mark_status"` // ""=全部 / unmarked / marked / normal / attack / ignore
	MinScore   float64 `json:"min_score"`   // 最小分数（<=0 不限）
	PageIndex  int     `json:"page_index"`  // 页码，从 1 开始
	PageSize   int     `json:"page_size"`   // 每页条数
}

// WafAILabelBatchMarkReq 批量标记入参
type WafAILabelBatchMarkReq struct {
	ReqUuids   []string `json:"req_uuids" binding:"required"` // 待标记的请求列表
	Mark       string   `json:"mark" binding:"required"`      // normal / attack / ignore
	AttackType string   `json:"attack_type"`                  // mark=attack 时的人工分类，空=每条按原始日志自动判定
}

// WafAILabelBatchUnmarkReq 批量取消标记入参
type WafAILabelBatchUnmarkReq struct {
	ReqUuids []string `json:"req_uuids" binding:"required"`
}
