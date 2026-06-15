package response

// WafAINameValue 通用名称-数值对（类别汇总/分数分布用）
type WafAINameValue struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// WafAITrendPoint AI命中按天趋势点
type WafAITrendPoint struct {
	Day     int   `json:"day"`     // YYYYMMDD
	Observe int64 `json:"observe"` // 观察命中数（log_only_mode=1）
	Block   int64 `json:"block"`   // 拦截命中数（log_only_mode=0）
}

// WafAIDashboard AI检测看板聚合结果
type WafAIDashboard struct {
	Total      int64             `json:"total"`       // AI命中总数
	ObserveCnt int64             `json:"observe_cnt"` // 观察命中数
	BlockCnt   int64             `json:"block_cnt"`   // 拦截命中数
	Categories []WafAINameValue  `json:"categories"`  // 按类别汇总
	ScoreHist  []WafAINameValue  `json:"score_hist"`  // 分数分布直方图（10桶）
	Trend      []WafAITrendPoint `json:"trend"`       // 按天 observe/block 趋势
}

// WafAILabelItem 标注工作台列表项（AI命中 + 当前标记状态 + 请求详情）
type WafAILabelItem struct {
	ReqUuid     string  `json:"req_uuid"`
	CreateTime  string  `json:"create_time"`
	HostCode    string  `json:"host_code"`
	SrcIp       string  `json:"src_ip"`
	Method      string  `json:"method"`
	Url         string  `json:"url"`
	RawQuery    string  `json:"raw_query"`
	Body        string  `json:"body"`
	UserAgent   string  `json:"user_agent"`
	AiScore     float64 `json:"ai_score"`
	Rule        string  `json:"rule"`          // 命中规则文本（AI检测:<类别>）
	LogOnlyMode int     `json:"log_only_mode"` // 1 观察 0 拦截
	Mark        string  `json:"mark"`          // 当前人工标记 normal/attack/ignore，空=未标记
	AttackType  string  `json:"attack_type"`   // 人工分类
}

// WafAILabelList 标注工作台分页结果
type WafAILabelList struct {
	Total int64            `json:"total"`
	Rows  []WafAILabelItem `json:"rows"`
}
